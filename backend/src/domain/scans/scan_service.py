"""Scan application service: the controlled entry point (ADR-0009).

Responsibilities:

* create scans behind the authorization-attestation gate
  (403 ATTESTATION_NOT_CONFIRMED without one);
* tenant-isolated retrieval / listing / cancellation;
* orchestrate execution: QUEUED → RUNNING (with authorization RE-CHECK) →
  secure pipeline (resolver → policy → binding → sandbox → transport →
  engine) → AI_ANALYSIS → REPORT_READY[_DEGRADED], persisting engine
  executions, deterministic findings, and the AI assessment document.

The API layer never touches resolvers, sandboxes, transports, engines, or
providers — only this service and its injected ``pipeline`` seam. The
production composition root (``domain/scans/pipeline.py``) is the ONLY place
where ``SandboxedScanExecutor(enable_execution=True)`` exists.
"""

from __future__ import annotations

import asyncio
import functools
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy import select

from src.config.constants import (
    ENGINE_HEADERS,
    SCAN_STATUS_AI_ANALYSIS,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_REJECTED,
    SCAN_STATUS_REPORT_READY,
    SCAN_STATUS_REPORT_READY_DEGRADED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_SCAN_COMPLETE,
)
from src.domain.errors import (
    AttestationNotConfirmedError,
    InvalidScanStateError,
    NotAuthenticatedError,
    NotFoundError,
)
from src.domain.scans.fingerprinting import (
    UnsupportedFingerprintCategory,
    generate_fingerprint_from_finding,
)
from src.domain.scans.lifecycle import can_transition
from src.domain.scans.lifecycle_finding import derive_lifecycle_status
from src.infrastructure.database.models import (
    AuthorizationAttestation,
    FindingEvidence,
    FindingLifecycleStatus,
    FindingStatusHistory,
    Scan,
    ScanEngine,
    ScanEngineExecution,
    ScanFinding,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount


SCAN_STATUS_QUEUED_CODE = SCAN_STATUS_QUEUED
SCAN_STATUS_RUNNING_CODE = SCAN_STATUS_RUNNING
SCAN_STATUS_REJECTED_CODE = SCAN_STATUS_REJECTED
SCAN_STATUS_SCAN_COMPLETE_CODE = SCAN_STATUS_SCAN_COMPLETE
SCAN_STATUS_AI_CODE = SCAN_STATUS_AI_ANALYSIS
SCAN_STATUS_REPORT_READY_CODE = SCAN_STATUS_REPORT_READY
SCAN_STATUS_REPORT_DEGRADED_CODE = SCAN_STATUS_REPORT_READY_DEGRADED
SCAN_STATUS_CANCELLED_CODE = SCAN_STATUS_CANCELLED


@dataclass(frozen=True)
class ScanDetails:
    """Framework-agnostic scan entity for API DTOs."""

    id: uuid.UUID
    target_id: uuid.UUID
    status_code: str
    scan_profile_code: str
    initiated_by_user_id: uuid.UUID
    authorization_attestation_id: uuid.UUID
    queued_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


@dataclass(frozen=True)
class _FindingIdentity:
    """Resolved execution → scan → target → hostname triple.

    Used by ``_persist_findings`` to populate the Phase 9 identity
    columns (fingerprint, target_id, scan_id, source_engine_code,
    affected_asset) without re-querying inside the findings loop. All
    fields are best-effort: an empty identity is a valid state when an
    engine execution is somehow orphaned, and the caller decides
    whether to skip lifecycle tracking accordingly.
    """

    scan_id: uuid.UUID | None = None
    target_id: uuid.UUID | None = None
    hostname: str = ""
    affected_asset_default: str = "/"


class ScanPipeline(Protocol):
    """The secure scanning chain, abstracted for orchestration/testing."""

    def run(self, *, hostname: str, scheme: str, port: int, path: str) -> Any: ...


class ScanService:
    """Business rules + execution orchestration for the ``scan`` aggregate."""

    def __init__(
        self,
        session: AsyncSession,
        principal: UserAccount | None = None,
    ) -> None:
        self._session = session
        self._principal = principal

    # ------------------------------------------------------------------ #
    # Creation & queries                                                 #
    # ------------------------------------------------------------------ #

    async def create_scan(
        self,
        *,
        target_id: uuid.UUID,
        scan_profile_code: str = "standard",
    ) -> ScanDetails:
        """Authorize + queue a scan (202 pattern; job scheduled by caller).

        Raises 404 for cross-tenant targets and 403 ATTESTATION_NOT_CONFIRMED
        when no active attestation covers the target.
        """
        from src.domain.scans.attestation_service import AttestationService
        from src.domain.targets.target_service import TargetService
        from src.infrastructure.database.repositories.scan_repository import (
            ScanRepository,
            _profile_id,
        )

        principal = self._assert_principal()
        targets = TargetService(self._session, principal)
        target = await targets.get_target(target_id)
        if target.is_archived:
            raise NotFoundError()

        attestations = AttestationService(self._session, principal)
        attestation = await attestations.latest_active_confirmed(target_id)
        if attestation is None:
            raise AttestationNotConfirmedError()

        repository = ScanRepository(self._session)
        status_ids = await repository.status_ids_by_code()
        profile_id = await _profile_id(self._session, scan_profile_code)

        now = datetime.now(UTC)
        scan = Scan(
            id=uuid.uuid4(),
            target_id=target.id,
            scan_profile_id=profile_id,
            initiated_by_user_id=principal.id,
            authorization_attestation_id=attestation.id,
            status_id=status_ids[SCAN_STATUS_QUEUED_CODE],
            queued_at=now,
            created_at=now,
        )
        repository.add(scan)
        await repository.flush()
        from src.domain.audit.audit_service import ACTION_SCAN_REQUESTED, AuditService

        await AuditService(self._session).record(
            action_code=ACTION_SCAN_REQUESTED,
            entity_type="scan",
            entity_id=scan.id,
            metadata_json={
                "targetId": str(target.id),
                "scanProfile": scan_profile_code,
                "authorizationAttestationId": str(attestation.id),
            },
            actor_user_id=principal.id,
            occurred_at=now,
        )
        return await self._details(scan)

    async def get_scan(self, scan_id: uuid.UUID) -> ScanDetails:
        scan = await self._get_visible_scan(scan_id)
        return await self._details(scan)

    async def list_scans(
        self,
        *,
        target_id: uuid.UUID | None = None,
        status_code: str | None = None,
        limit: int = 50,
    ) -> list[ScanDetails]:
        from src.infrastructure.database.repositories.scan_repository import (
            ScanRepository,
        )

        repository = ScanRepository(self._session)
        rows = await repository.list_for_user(
            (self._assert_principal()).id,
            target_id=target_id,
            status_code=status_code,
            limit=limit,
        )
        # Batched hydration: one status map + one profile map for the whole
        # page instead of two lookups per row (1+2N queries → 3). Missing
        # seed ids raise LookupError, matching the pre-batch per-row path.
        status_by_id = await repository.status_code_by_id()
        profile_by_id = await repository.profile_code_by_id()
        details: list[ScanDetails] = []
        for row in rows:
            try:
                status_code = status_by_id[row.status_id]
                profile_code = profile_by_id[row.scan_profile_id]
            except KeyError as exc:
                raise LookupError(f"unseeded lookup id for scan {row.id}") from exc
            details.append(
                self._details_from_codes(
                    row,
                    status_code=status_code,
                    profile_code=profile_code,
                )
            )
        return details

    async def rescan_scan(self, scan_id: uuid.UUID) -> ScanDetails:
        """Create a new scan linked to ``scan_id`` as parent.

        Preserves target, profile and authorization model; requires the
        same attestation gate as a fresh scan. Does not mutate the original.
        """
        original = await self._get_visible_scan(scan_id)
        from src.domain.scans.attestation_service import AttestationService

        attestations = AttestationService(self._session, self._assert_principal())
        latest = await attestations.latest_active_confirmed(original.target_id)
        if latest is None:
            raise AttestationNotConfirmedError()
        from src.infrastructure.database.repositories.scan_repository import ScanRepository

        repository = ScanRepository(self._session)
        status_ids = await repository.status_ids_by_code()
        now = datetime.now(UTC)
        new_scan = Scan(
            id=uuid.uuid4(),
            target_id=original.target_id,
            scan_profile_id=original.scan_profile_id,
            initiated_by_user_id=self._assert_principal().id,
            authorization_attestation_id=latest.id,
            status_id=status_ids[SCAN_STATUS_QUEUED_CODE],
            parent_scan_id=original.id,
            queued_at=now,
            created_at=now,
        )
        repository.add(new_scan)
        await repository.flush()
        from src.domain.audit.audit_service import ACTION_SCAN_REQUESTED, AuditService

        await AuditService(self._session).record(
            action_code=ACTION_SCAN_REQUESTED,
            entity_type="scan",
            entity_id=new_scan.id,
            metadata_json={
                "targetId": str(original.target_id),
                "parentScanId": str(original.id),
                "scanProfile": await self._profile_code_for_id(original.scan_profile_id),
                "authorizationAttestationId": str(latest.id),
            },
            actor_user_id=self._assert_principal().id,
            occurred_at=now,
        )
        return await self._details(new_scan)

    async def compare_scans(
        self, scan_a_id: uuid.UUID, scan_b_id: uuid.UUID
    ) -> dict[str, list[dict[str, object]]]:
        """Compare two scans of the same target by fingerprint.

        Both scans must be visible to the caller (``_get_visible_scan``
        enforces tenant isolation: cross-tenant scans surface as 404, not
        403, to prevent existence leaks). The two scans must target the
        same ``target.id`` — comparing findings across different targets
        would produce a meaningless diff.
        """
        scan_a = await self._get_visible_scan(scan_a_id)
        scan_b = await self._get_visible_scan(scan_b_id)
        if scan_a.target_id != scan_b.target_id:
            raise InvalidScanStateError()

        a_map = await self._fingerprint_index(scan_a.id)
        b_map = await self._fingerprint_index(scan_b.id)
        a_fps, b_fps = set(a_map), set(b_map)

        regressed_candidates = b_fps - a_fps
        history_resolved: set[str] = set()
        if regressed_candidates:
            status_ids = await _lifecycle_status_ids(self._session)
            resolved_id = status_ids.get("RESOLVED")
            if resolved_id is not None:
                history_resolved = await self._fingerprints_with_status(
                    target_id=scan_a.target_id,
                    fingerprints=regressed_candidates,
                    status_id=resolved_id,
                )

        new_fps = sorted(f for f in (b_fps - a_fps) if f not in history_resolved)
        regressed_fps = sorted(f for f in regressed_candidates if f in history_resolved)
        persistent_fps = sorted(a_fps & b_fps)
        resolved_fps = sorted(a_fps - b_fps)

        return {
            "new": _to_compare_dtos(new_fps, b_map),
            "persistent": _to_compare_dtos(persistent_fps, b_map),
            "resolved": _to_compare_dtos(resolved_fps, a_map),
            "regressed": _to_compare_dtos(regressed_fps, b_map),
        }

    async def _fingerprint_index(self, scan_id: uuid.UUID) -> dict[str, tuple[uuid.UUID, str]]:
        """Map fingerprint → (finding_id, title) for one scan.

        Returns an empty dict when the scan has no fingerprint-bearing
        findings yet (e.g. lifecycle trackable engine has not run).
        """
        rows = await self._session.execute(
            select(
                ScanFinding.fingerprint,
                ScanFinding.id,
                ScanFinding.title,
            ).where(
                ScanFinding.scan_id == scan_id,
                ScanFinding.fingerprint.is_not(None),
            )
        )
        return {fp: (fid, title) for fp, fid, title in rows.all() if fp}

    async def _fingerprints_with_status(
        self,
        *,
        target_id: uuid.UUID,
        fingerprints: set[str],
        status_id: int,
    ) -> set[str]:
        rows = await self._session.execute(
            select(FindingStatusHistory.fingerprint).where(
                FindingStatusHistory.target_id == target_id,
                FindingStatusHistory.finding_lifecycle_status_id == status_id,
                FindingStatusHistory.fingerprint.in_(list(fingerprints)),
            )
        )
        return {r[0] for r in rows.all() if r[0]}

    async def _profile_code_for_id(self, profile_id: int) -> str:
        from src.infrastructure.database.repositories.scan_repository import _profile_code

        return await _profile_code(self._session, profile_id)

    async def cancel_scan(self, scan_id: uuid.UUID) -> ScanDetails:
        """Cancel pre-RUNNING scans only (honest cancellation boundary)."""
        from src.infrastructure.database.repositories.scan_repository import (
            ScanRepository,
        )

        scan = await self._get_visible_scan(scan_id)
        current = getattr(scan, "status_code", None)
        if current is None:
            from src.infrastructure.database.repositories.scan_repository import (
                _status_code_of,
            )

            current = await _status_code_of(self._session, scan.status_id)
        # The state machine is authoritative: CANCELLED is reachable only
        # from QUEUED (scans are born QUEUED; PENDING_ATTESTATION never
        # materializes as a scan row). A read-then-write race with the
        # worker is still possible, so the optimistic transition below is
        # the final arbiter — but an already-invalid edge must never even
        # be attempted (e.g. SCAN_COMPLETE/AI_ANALYSIS → CANCELLED).
        if not can_transition(current, SCAN_STATUS_CANCELLED_CODE):
            raise InvalidScanStateError()

        repository = ScanRepository(self._session)
        status_ids = await repository.status_ids_by_code()
        moved = await repository.try_transition(
            scan.id,
            from_status_id=status_ids[current],
            to_status_id=status_ids[SCAN_STATUS_CANCELLED_CODE],
            set_completed_at=datetime.now(UTC),
        )
        if not moved:
            raise InvalidScanStateError()
        from src.domain.audit.audit_service import (
            ACTION_SCAN_STATE_TRANSITION,
            AuditService,
        )

        await AuditService(self._session).record(
            action_code=ACTION_SCAN_STATE_TRANSITION,
            entity_type="scan",
            entity_id=scan.id,
            metadata_json={
                "from": current,
                "to": SCAN_STATUS_CANCELLED_CODE,
                "ownerUserId": str(scan.initiated_by_user_id),
            },
            actor_user_id=self._assert_principal().id,
            occurred_at=datetime.now(UTC),
        )
        refreshed = await repository.get_by_id(scan.id)
        assert refreshed is not None
        return await self._details(refreshed)

    # ------------------------------------------------------------------ #
    # Execution orchestration (background job entry point)               #
    # ------------------------------------------------------------------ #

    @classmethod
    def build_background_job(
        cls,
        scan_id: uuid.UUID,
        *,
        pipeline: ScanPipeline | None = None,
        ai_analyzer: Any | None = None,
    ) -> Callable[[], Any]:
        """Build an awaitable job that owns its own DB session."""

        async def _job() -> None:
            from src.infrastructure.database.connection import get_async_sessionmaker

            sessionmaker = get_async_sessionmaker()
            async with sessionmaker() as session:
                service = cls(session, principal=None)
                await service.execute_scan_job(scan_id, pipeline=pipeline, ai_analyzer=ai_analyzer)

        return _job

    async def execute_scan_job(
        self,
        scan_id: uuid.UUID,
        *,
        pipeline: ScanPipeline | None = None,
        ai_analyzer: Any | None = None,
    ) -> None:
        """Run the authorized secure chain for a QUEUED scan."""
        from src.domain.scans.pipeline import build_default_pipeline
        from src.infrastructure.database.repositories.attestation_repository import (
            AttestationRepository,
        )
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
            ScanRepository,
        )

        repository = ScanRepository(self._session)
        scan = await repository.get_by_id(scan_id)
        if scan is None:
            return
        status_ids = await repository.status_ids_by_code()

        # ---- optimistic claim: QUEUED → RUNNING -------------------------
        now = datetime.now(UTC)
        claimed = await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_QUEUED_CODE],
            to_status_id=status_ids[SCAN_STATUS_RUNNING_CODE],
            set_started_at=now,
        )
        if not claimed:
            return

        # ---- authorization RE-CHECK at execution time --------------------
        attestation = await AttestationRepository(self._session).get_by_id(
            scan.authorization_attestation_id
        )
        if attestation is None or not _attestation_active(attestation):
            from src.domain.audit.audit_service import (
                ACTION_SCAN_STATE_TRANSITION,
                AuditService,
            )

            await AuditService(self._session).record(
                action_code=ACTION_SCAN_STATE_TRANSITION,
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": SCAN_STATUS_QUEUED_CODE,
                    "to": SCAN_STATUS_REJECTED_CODE,
                    "reason": "authorization attestation no longer valid",
                    "ownerUserId": str(scan.initiated_by_user_id),
                },
                actor_user_id=None,
            )
            executions = ScanEngineExecutionRepository(self._session)
            execution_row = await executions.create(
                scan_id=scan.id,
                scan_engine_id=await _engine_id(self._session),
                tool_version_snapshot="unknown",
                status="FAILED",
            )
            await executions.mark(
                execution_row.id,
                status="FAILED",
                completed_at=datetime.now(UTC),
                error_message="authorization attestation no longer valid",
            )
            if not await repository.try_transition(
                scan.id,
                from_status_id=status_ids[SCAN_STATUS_RUNNING_CODE],
                to_status_id=status_ids[SCAN_STATUS_REJECTED_CODE],
                set_completed_at=datetime.now(UTC),
            ):
                # Lost a race after recording REJECTED (e.g. cancel won):
                # surface it so the worker reaps whatever state actually won.
                raise InvalidScanStateError()
            await self._session.commit()
            return

        # ---- secure chain --------------------------------------------------
        effective_pipeline = pipeline if pipeline is not None else build_default_pipeline()
        origin = await self._origin_for_target(scan.target_id)

        executions = ScanEngineExecutionRepository(self._session)
        engine_code = getattr(effective_pipeline, "engine_code", ENGINE_HEADERS)
        engine_version = getattr(effective_pipeline, "engine_version", "1")
        execution_row = await executions.create(
            scan_id=scan.id,
            scan_engine_id=await _engine_id(self._session, engine_code),
            tool_version_snapshot=engine_version[:50],
            status="RUNNING",
            started_at=datetime.now(UTC),
        )
        await self._session.commit()

        loop = asyncio.get_running_loop()
        from src.domain.audit.audit_service import (
            ACTION_SCAN_STATE_TRANSITION,
            AuditService,
        )

        audit = AuditService(self._session)
        try:
            analysis_result = await loop.run_in_executor(
                None,
                functools.partial(
                    effective_pipeline.run,
                    hostname=origin["hostname"],
                    scheme=origin["scheme"],
                    port=origin["port"],
                    path=origin["path"],
                ),
            )
            await audit.record(
                action_code=ACTION_SCAN_STATE_TRANSITION,
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": SCAN_STATUS_RUNNING_CODE,
                    "to": "EXECUTION_SUCCEEDED",
                    "ownerUserId": str(scan.initiated_by_user_id),
                },
                occurred_at=datetime.now(UTC),
            )
        except Exception as exc:  # noqa: BLE001 - controlled lifecycle failure
            await executions.mark(
                execution_row.id,
                status="FAILED",
                completed_at=datetime.now(UTC),
                error_message=type(exc).__name__,
            )
            await audit.record(
                action_code=ACTION_SCAN_STATE_TRANSITION,
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": SCAN_STATUS_RUNNING_CODE,
                    "to": SCAN_STATUS_REJECTED_CODE,
                    "reason": type(exc).__name__,
                    "ownerUserId": str(scan.initiated_by_user_id),
                },
                occurred_at=datetime.now(UTC),
            )
            if not await repository.try_transition(
                scan.id,
                from_status_id=status_ids[SCAN_STATUS_RUNNING_CODE],
                to_status_id=status_ids[SCAN_STATUS_REJECTED_CODE],
                set_completed_at=datetime.now(UTC),
            ):
                # Lost a race after recording REJECTED (e.g. cancel won):
                # surface it so the worker reaps whatever state actually won.
                raise InvalidScanStateError() from exc
            await self._session.commit()
            return

        await executions.mark(execution_row.id, status="SUCCEEDED", completed_at=datetime.now(UTC))
        await self._persist_findings(executions, execution_row.id, analysis_result)

        # Stage edges are optimistic: a concurrent mutation (cancel winning
        # the race, duplicate worker delivery) must abort the job instead of
        # persisting artifacts under a status that never advances. The
        # worker maps the resulting InvalidScanStateError to REJECTED (a
        # no-op when cancel already won with CANCELLED).
        if not await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_RUNNING_CODE],
            to_status_id=status_ids[SCAN_STATUS_SCAN_COMPLETE_CODE],
        ):
            raise InvalidScanStateError()
        if not await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_SCAN_COMPLETE_CODE],
            to_status_id=status_ids[SCAN_STATUS_AI_CODE],
        ):
            raise InvalidScanStateError()
        await self._session.commit()

        from src.domain.scanning.analysis.evidence import EvidenceSet
        from src.domain.scanning.analysis.models import AssessmentUnavailable

        evidence = EvidenceSet.from_result(analysis_result)
        outcome: Any = None
        analyzer_used = ai_analyzer
        if analyzer_used is None:
            analyzer_used = self._maybe_gemini_analyzer()
        if analyzer_used is not None:
            from src.domain.scanning.analysis.service import AiAnalysisService as _Svc

            _, outcome = await loop.run_in_executor(
                None,
                functools.partial(_Svc(analyzer_used).analyze, evidence),
            )
        if outcome is None:
            payload: dict[str, object] = {
                "evidence_set_id": evidence.evidence_set_id,
                "failure_kind": "provider_unavailable",
                "detail": "AI provider not configured",
            }
            is_available, failure_kind = False, "provider_unavailable"
            provider_name, model_name = "none", "unavailable"
        elif isinstance(outcome, AssessmentUnavailable):
            payload = outcome.to_dict()
            is_available = False
            failure_kind = outcome.failure_kind.value
            provider_name, model_name = "none", "unavailable"
        else:
            payload = outcome.to_dict()
            is_available, failure_kind = True, None
            meta = outcome.provider_metadata
            provider_name = meta.provider if meta else "unknown"
            model_name = meta.model if meta else "unknown"

        # Per-finding fallback explanations: when the AI is unavailable,
        # every finding still gets a deterministic template so the
        # per-finding endpoint (SRS Ch5 §9) has data to serve without
        # the AI ever being called again. This is the "never silently
        # present incomplete data" principle (SRS Ch2 §11).
        per_finding_payload = self._build_per_finding_fallback_payload(analysis_result)
        if isinstance(payload, dict):
            payload.setdefault("findings", per_finding_payload)

        final_status = (
            SCAN_STATUS_REPORT_READY_CODE if is_available else SCAN_STATUS_REPORT_DEGRADED_CODE
        )
        await executions.upsert_ai_assessment(
            execution_id=execution_row.id,
            provider=provider_name,
            model=model_name,
            prompt_schema_version=PROMPT_SCHEMA_VERSION_STR,
            output_schema_version=OUTPUT_SCHEMA_VERSION_STR,
            is_available=is_available,
            failure_kind=failure_kind,
            unsupported_claim_count=_coerce_count(payload),
            payload=payload,
        )
        if not await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_AI_CODE],
            to_status_id=status_ids[final_status],
            set_completed_at=datetime.now(UTC),
        ):
            # Same optimistic-race contract as the earlier stage edges.
            raise InvalidScanStateError()
        await self._session.commit()

    def _maybe_gemini_analyzer(self) -> Any | None:
        from src.infrastructure.ai.factory import maybe_evidence_analyzer

        return maybe_evidence_analyzer()

    @staticmethod
    def _build_per_finding_fallback_payload(analysis_result: Any) -> dict[str, object]:
        """Build a per-finding fallback map for the assessment payload.

        Always uses the deterministic template — no AI text appears here.
        Keyed by finding ID (the same key the per-finding endpoint reads).
        """
        from src.domain.scanning.analysis.fallback_templates import (
            build_fallback_explanation,
        )

        result: dict[str, object] = {}
        for finding in getattr(analysis_result, "findings", ()) or ():
            explanation = build_fallback_explanation(
                finding_id=finding.id,
                category_code=finding.category,
            )
            result[finding.id] = explanation.to_dict()
        return result

    # ------------------------------------------------------------------ #
    # Internals                                                          #
    # ------------------------------------------------------------------ #

    def _assert_principal(self) -> UserAccount:
        if self._principal is None:
            raise NotAuthenticatedError()
        return self._principal

    async def _get_visible_scan(self, scan_id: uuid.UUID) -> Scan:
        from src.infrastructure.database.repositories.scan_repository import (
            ScanRepository,
        )

        scan = await ScanRepository(self._session).get_by_id(scan_id)
        if scan is None:
            raise NotFoundError()
        # Tenant isolation baseline (v1): scans are visible to their
        # initiator. Organization-wide sharing lands with org roles later.
        if self._principal is not None and scan.initiated_by_user_id != self._principal.id:
            raise NotFoundError()
        return scan

    async def _details(self, scan: Scan) -> ScanDetails:
        # Rows produced by tests may carry denormalized codes directly;
        # production ORM rows fall back to lookup-table joins.
        status_code = getattr(scan, "status_code", None)
        profile_code = getattr(scan, "scan_profile_code", None)
        if status_code is None:
            from src.infrastructure.database.repositories.scan_repository import (
                _status_code_of,
            )

            status_code = await _status_code_of(self._session, scan.status_id)
        if profile_code is None:
            from src.infrastructure.database.repositories.scan_repository import (
                _profile_code,
            )

            profile_code = await _profile_code(self._session, scan.scan_profile_id)
        return self._details_from_codes(scan, status_code=status_code, profile_code=profile_code)

    @staticmethod
    def _details_from_codes(scan: Scan, *, status_code: str, profile_code: str) -> ScanDetails:
        return ScanDetails(
            id=scan.id,
            target_id=scan.target_id,
            status_code=status_code,
            scan_profile_code=profile_code,
            initiated_by_user_id=scan.initiated_by_user_id,
            authorization_attestation_id=scan.authorization_attestation_id,
            queued_at=scan.queued_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            created_at=scan.created_at,
        )

    async def _persist_findings(
        self,
        executions: Any,
        execution_id: uuid.UUID,
        analysis_result: Any,
    ) -> None:
        """Persist deterministic findings + evidence + lifecycle history.

        Identity resolution (execution → scan → target) happens once, up front.
        Fingerprints are generated from the canonical persisted finding-category
        code (after ``_map_category`` mapping), not the raw engine alias.
        Evidence is typed, bounded (≤2048 chars) and immutable (DB trigger).
        Lifecycle status is derived from fingerprint+target against the
        previous scan (parent_link first, else most-recent completed).
        """
        identity = await self._resolve_finding_identity(execution_id)

        category_ids = await _category_ids(self._session)
        severity_ids = await _severity_ids(self._session)

        engine_code = await self._engine_code_for_execution(execution_id)

        rows: list[ScanFinding] = []
        fingerprints: list[str | None] = []
        for finding in analysis_result.findings:
            canonical_code = _canonical_category_code(finding.category)
            fingerprint = self._safe_fingerprint(
                hostname=identity.hostname,
                canonical_category=canonical_code,
                title=finding.title,
                location=finding.location,
            )
            fingerprints.append(fingerprint)
            affected_asset = (finding.location or identity.affected_asset_default)[:500]
            rows.append(
                ScanFinding(
                    execution_id=execution_id,
                    category_id=_map_category(category_ids, finding.category),
                    severity_id=severity_ids[finding.severity.value.upper()],
                    title=finding.title[:200],
                    description=finding.description,
                    evidence=finding.evidence,
                    location=finding.location[:500],
                    recommendation=finding.recommendation,
                    fingerprint=fingerprint,
                    target_id=identity.target_id,
                    scan_id=identity.scan_id,
                    source_engine_code=engine_code,
                    affected_asset=affected_asset,
                )
            )
        await executions.add_findings(rows)

        self._persist_evidence(rows, analysis_result.findings)

        if identity.target_id is not None and identity.scan_id is not None:
            await self._record_lifecycle(
                target_id=identity.target_id,
                scan_id=identity.scan_id,
                current_fingerprints={fp for fp in fingerprints if fp},
            )

    # ------------------------------------------------------------------ #
    # _persist_findings helpers (private; no broad exception swallow)     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _safe_fingerprint(
        *,
        hostname: str,
        canonical_category: str,
        title: str,
        location: str,
    ) -> str | None:
        """Return a stable fingerprint or None for unsupported categories.

        ``UnsupportedFingerprintCategory`` and ``ValueError`` are honest,
        narrow outcomes — the finding is persisted without a fingerprint
        and therefore has no cross-scan identity. New finding categories
        must register a fingerprint rule before they can join lifecycle
        tracking.
        """
        try:
            return generate_fingerprint_from_finding(
                hostname=hostname,
                category_code=canonical_category,
                title=title,
                location=location,
            )
        except (UnsupportedFingerprintCategory, ValueError):
            return None

    async def _resolve_finding_identity(self, execution_id: uuid.UUID) -> _FindingIdentity:
        """Resolve execution → scan → target → hostname for finding identity.

        Returns a typed dataclass with None defaults for missing rows so
        the caller can decide whether to skip lifecycle tracking. No
        broad-exception swallow: a missing execution or scan is an
        unrecoverable invariant violation (a finding cannot exist without
        an execution, and an execution cannot exist without a scan).
        """
        from src.infrastructure.database.repositories.target_repository import (
            TargetRepository,
        )

        execution = await self._session.get(ScanEngineExecution, execution_id)
        if execution is None:
            return _FindingIdentity()
        scan = await self._session.get(Scan, execution.scan_id)
        if scan is None:
            return _FindingIdentity()
        target = await TargetRepository(self._session).get_by_id(scan.target_id)
        if target is None:
            return _FindingIdentity(scan_id=scan.id, target_id=scan.target_id)
        return _FindingIdentity(
            scan_id=scan.id,
            target_id=scan.target_id,
            hostname=target.hostname or "",
            affected_asset_default=f"{(target.normalized_url or '').rstrip('/') or '/'}",
        )

    async def _engine_code_for_execution(self, execution_id: uuid.UUID) -> str:
        """Resolve the actual ``scan_engine.code`` for an execution row.

        Falls back to ``"unknown"`` only if the execution or its engine
        row is missing — a configuration error, not a normal outcome.
        """
        execution = await self._session.get(ScanEngineExecution, execution_id)
        if execution is None:
            return "unknown"
        engine = await self._session.get(ScanEngine, execution.scan_engine_id)
        if engine is None:
            return "unknown"
        return engine.code[:50]

    def _persist_evidence(
        self,
        rows: list[ScanFinding],
        findings: Any,
    ) -> None:
        """Write typed, bounded, immutable evidence rows for the findings.

        Evidence types are restricted to the values enforced by the
        ``ck_finding_evidence_type`` DB check constraint
        (RAW_HEADER / TOOL_OUTPUT_SNIPPET / RESPONSE_BODY_SNIPPET /
        REQUEST_METADATA). Content is truncated to 2048 chars. Empty
        content is skipped (an evidence row without content has no
        integrity value). Failures are propagated — the secure chain has
        no reason to silently drop evidence persistence.
        """
        for finding_model, finding in zip(rows, findings, strict=True):
            content = (finding.evidence or finding.description or finding.title)[:2048]
            if not content.strip():
                continue
            evidence_type = self._classify_evidence_type(finding)
            self._session.add(
                FindingEvidence(
                    finding_id=finding_model.id,
                    evidence_type=evidence_type,
                    content=content,
                )
            )

    @staticmethod
    def _classify_evidence_type(finding: Any) -> str:
        """Map a finding to one of the allowed evidence_type values.

        Header-shaped findings carry their evidence as a ``RAW_HEADER``
        snippet; anything else is recorded as ``TOOL_OUTPUT_SNIPPET``
        unless its evidence already resembles a request metadata block.
        """
        title_lc = finding.title.lower()
        category_lc = finding.category.lower()
        evidence_lc = (finding.evidence or "").lower()
        if evidence_lc.startswith("request ") or "request metadata" in title_lc:
            return "REQUEST_METADATA"
        if evidence_lc.startswith("response body") or "response body" in title_lc:
            return "RESPONSE_BODY_SNIPPET"
        if "header" in title_lc or "header" in category_lc:
            return "RAW_HEADER"
        return "TOOL_OUTPUT_SNIPPET"

    async def _record_lifecycle(
        self,
        *,
        target_id: uuid.UUID,
        scan_id: uuid.UUID,
        current_fingerprints: set[str],
    ) -> None:
        """Compute + persist NEW/PERSISTENT/RESOLVED/REGRESSED rows.

        The "previous" scan is the explicit ``parent_scan_id`` when set,
        otherwise the most-recent completed scan of the same target.
        Lifecycle identity is fingerprint + target. RESOLVED events for
        fingerprints that are no longer in the current scan are derived
        from the comparison set, not just from the absence of a prior
        row.
        """
        previous_scan_id = await self._previous_scan_id(target_id, scan_id)
        previous_fingerprints: set[str] = set()
        if previous_scan_id is not None:
            previous_fingerprints = await self._fingerprints_for_scan(previous_scan_id)

        history_map = await self._latest_status_map(
            target_id, current_fingerprints | previous_fingerprints
        )
        status_ids = await _lifecycle_status_ids(self._session)

        all_considered = current_fingerprints | previous_fingerprints
        for fp in all_considered:
            derived = derive_lifecycle_status(
                fingerprint=fp,
                in_current=fp in current_fingerprints,
                in_previous=fp in previous_fingerprints,
                last_known_status=history_map.get(fp),
            )
            if derived is None:
                continue
            status_id = status_ids.get(derived)
            if status_id is None:
                continue
            self._session.add(
                FindingStatusHistory(
                    fingerprint=fp,
                    target_id=target_id,
                    finding_lifecycle_status_id=status_id,
                    observed_in_scan_id=scan_id,
                )
            )
        await self._session.flush()

    async def _fingerprints_for_scan(self, scan_id: uuid.UUID) -> set[str]:
        rows = await self._session.execute(
            select(ScanFinding.fingerprint).where(
                ScanFinding.scan_id == scan_id,
                ScanFinding.fingerprint.is_not(None),
            )
        )
        return {r[0] for r in rows.all() if r[0]}

    async def _latest_status_map(
        self,
        target_id: uuid.UUID,
        fingerprints: set[str],
    ) -> dict[str, str]:
        """Map each fingerprint to the most-recent lifecycle status code.

        Returns an empty dict when no history exists. The query is
        bounded by the ``fingerprints`` set so we never load the full
        table; ``effective_at DESC`` guarantees the freshest entry per
        fingerprint wins.
        """
        if not fingerprints:
            return {}
        status_id_to_code = await _lifecycle_status_code_map(self._session)
        rows = await self._session.execute(
            select(
                FindingStatusHistory.fingerprint, FindingStatusHistory.finding_lifecycle_status_id
            )
            .where(
                FindingStatusHistory.target_id == target_id,
                FindingStatusHistory.fingerprint.in_(list(fingerprints)),
            )
            .order_by(FindingStatusHistory.effective_at.desc())
        )
        out: dict[str, str] = {}
        for fp, status_id in rows.all():
            if fp in out:
                continue
            out[fp] = status_id_to_code.get(int(status_id), "")
        return out

    async def _previous_scan_id(
        self, target_id: uuid.UUID, current_scan_id: uuid.UUID
    ) -> uuid.UUID | None:
        """Resolve the previous scan for lifecycle comparison.

        Per SRS Ch4 §6.2, the ``parent_scan_id`` linkage is the explicit
        "previous" reference for rescans. When absent (e.g. an ad-hoc
        re-scan with no parent), fall back to the most-recent completed
        scan of the same target. The query is bounded to the same
        target so we never compare findings across unrelated targets.
        """
        current = await self._session.get(Scan, current_scan_id)
        if current is not None and getattr(current, "parent_scan_id", None) is not None:
            return current.parent_scan_id
        row = (
            await self._session.execute(
                select(Scan.id)
                .where(
                    Scan.target_id == target_id,
                    Scan.id != current_scan_id,
                    Scan.completed_at.is_not(None),
                )
                .order_by(Scan.completed_at.desc())
                .limit(1)
            )
        ).first()
        return row[0] if row else None

    async def _origin_for_target(self, target_id: uuid.UUID) -> dict[str, Any]:
        import urllib.parse

        from src.infrastructure.database.repositories.target_repository import (
            TargetRepository,
        )

        target = await TargetRepository(self._session).get_by_id(target_id)
        if target is None:
            raise NotFoundError()
        parts = urllib.parse.urlsplit(target.normalized_url)
        scheme = parts.scheme.lower() or "https"
        default_port = 443 if scheme == "https" else 80
        hostname = parts.hostname or target.hostname
        port = parts.port or default_port
        path = parts.path or "/"
        return {"hostname": hostname, "scheme": scheme, "port": port, "path": path}


# ---------------------------------------------------------------------- #
# Module-level helpers (kept out of the class for testability)           #
# ---------------------------------------------------------------------- #

PROMPT_SCHEMA_VERSION_STR = "v1"
OUTPUT_SCHEMA_VERSION_STR = "v1"

_CATEGORY_FALLBACK = "MISSING_SECURITY_HEADER"


def _coerce_count(value: object) -> int:
    """Bounded coercion for JSON-decoded counts."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _attestation_active(attestation: AuthorizationAttestation) -> bool:
    if attestation.status != "CONFIRMED":
        return False
    if attestation.expires_at is None:
        return True
    return attestation.expires_at > datetime.now(UTC)


async def _engine_id(session: AsyncSession, code: str = ENGINE_HEADERS) -> int:
    from sqlalchemy import select

    from src.infrastructure.database.models import ScanEngine

    row = (await session.execute(select(ScanEngine.id).where(ScanEngine.code == code))).first()
    if row is None:
        raise LookupError(f"scan_engine {code!r} is not seeded")
    return int(row[0])


async def _category_ids(session: AsyncSession) -> dict[str, int]:
    from sqlalchemy import select

    from src.infrastructure.database.models import FindingCategory

    rows = await session.execute(select(FindingCategory.code, FindingCategory.id))
    mapping: dict[str, int] = {}
    for code, id_ in rows.all():
        mapping[code] = id_
    return mapping


_ENGINE_CATEGORY_TO_CANONICAL: dict[str, str] = {
    "http.security-headers": "MISSING_SECURITY_HEADER",
    "http.cookies": "MISSING_SECURITY_HEADER",
    "http.transport": "WEAK_CIPHER",
    "http.server-info": "MISSING_SECURITY_HEADER",
}


def _canonical_category_code(engine_category: str) -> str:
    """Map engine category to the canonical persisted finding-category code."""
    return _ENGINE_CATEGORY_TO_CANONICAL.get(engine_category, engine_category.upper())


def _map_category(category_ids: dict[str, int], engine_category: str) -> int:
    canonical = _canonical_category_code(engine_category)
    # Fall back to generic header category if canonical not seeded.
    code = canonical if canonical in category_ids else _CATEGORY_FALLBACK
    return category_ids.get(code, category_ids[_CATEGORY_FALLBACK])


async def _severity_ids(session: AsyncSession) -> dict[str, int]:
    from sqlalchemy import select

    from src.infrastructure.database.models import SeverityLevel

    rows = await session.execute(select(SeverityLevel.code, SeverityLevel.id))
    mapping: dict[str, int] = {}
    for code, id_ in rows.all():
        mapping[code] = id_
    return mapping


async def _lifecycle_status_ids(session: AsyncSession) -> dict[str, int]:
    """Map lifecycle status code → id (cached per scan)."""
    from sqlalchemy import select

    rows = await session.execute(select(FindingLifecycleStatus.code, FindingLifecycleStatus.id))
    return {code: int(id_) for code, id_ in rows.all()}


async def _lifecycle_status_code_map(session: AsyncSession) -> dict[int, str]:
    """Reverse map: id → code (used to read back the latest status)."""
    from sqlalchemy import select

    rows = await session.execute(select(FindingLifecycleStatus.id, FindingLifecycleStatus.code))
    return {int(id_): code for id_, code in rows.all()}


def _to_compare_dtos(
    fps: list[str], source_map: dict[str, tuple[uuid.UUID, str]]
) -> list[dict[str, object]]:
    """Render fingerprint list → DTO list for the compare endpoint."""
    return [
        {"id": str(source_map[fp][0]), "fingerprint": fp, "title": source_map[fp][1]}
        for fp in sorted(fps)
    ]
