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

from src.config.constants import (
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
from src.domain.scans.lifecycle import is_terminal
from src.infrastructure.database.models import (
    AuthorizationAttestation,
    Scan,
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
        from src.domain.audit.audit_service import AuditService

        await AuditService(self._session).record(
            action_code="SCAN_REQUESTED",
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

        rows = await ScanRepository(self._session).list_for_user(
            (self._assert_principal()).id,
            target_id=target_id,
            status_code=status_code,
            limit=limit,
        )
        return [await self._details(row) for row in rows]

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
        if is_terminal(current) or current == SCAN_STATUS_RUNNING_CODE:
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
            from src.domain.audit.audit_service import AuditService

            await AuditService(self._session).record(
                action_code="SCAN_STATE_TRANSITION",
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": SCAN_STATUS_QUEUED_CODE,
                    "to": SCAN_STATUS_REJECTED_CODE,
                    "reason": "authorization attestation no longer valid",
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
            await repository.try_transition(
                scan.id,
                from_status_id=status_ids[SCAN_STATUS_RUNNING_CODE],
                to_status_id=status_ids[SCAN_STATUS_REJECTED_CODE],
                set_completed_at=datetime.now(UTC),
            )
            await self._session.commit()
            return

        # ---- secure chain --------------------------------------------------
        effective_pipeline = pipeline if pipeline is not None else build_default_pipeline()
        origin = await self._origin_for_target(scan.target_id)

        executions = ScanEngineExecutionRepository(self._session)
        engine_code = getattr(effective_pipeline, "engine_code", "headers-analyzer")
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
        from src.domain.audit.audit_service import AuditService as _Audit

        audit = _Audit(self._session)
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
                action_code="SCAN_STATE_TRANSITION",
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": SCAN_STATUS_RUNNING_CODE,
                    "to": "EXECUTION_SUCCEEDED",
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
                action_code="SCAN_STATE_TRANSITION",
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": SCAN_STATUS_RUNNING_CODE,
                    "to": SCAN_STATUS_REJECTED_CODE,
                    "reason": type(exc).__name__,
                },
                occurred_at=datetime.now(UTC),
            )
            await repository.try_transition(
                scan.id,
                from_status_id=status_ids[SCAN_STATUS_RUNNING_CODE],
                to_status_id=status_ids[SCAN_STATUS_REJECTED_CODE],
                set_completed_at=datetime.now(UTC),
            )
            await self._session.commit()
            return

        await executions.mark(execution_row.id, status="SUCCEEDED", completed_at=datetime.now(UTC))
        await self._persist_findings(executions, execution_row.id, analysis_result)

        await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_RUNNING_CODE],
            to_status_id=status_ids[SCAN_STATUS_SCAN_COMPLETE_CODE],
        )
        await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_SCAN_COMPLETE_CODE],
            to_status_id=status_ids[SCAN_STATUS_AI_CODE],
        )
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
        await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_AI_CODE],
            to_status_id=status_ids[final_status],
            set_completed_at=datetime.now(UTC),
        )
        await self._session.commit()

    def _maybe_gemini_analyzer(self) -> Any | None:
        from src.config.settings import get_settings

        settings = get_settings()
        if not settings.gemini_api_key:
            return None
        try:
            from src.infrastructure.ai.gemini_provider import GeminiEvidenceAnalyzer

            return GeminiEvidenceAnalyzer.from_settings()
        except Exception:  # noqa: BLE001 - AI must degrade, never block scans
            return None

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
        from src.infrastructure.database.models import ScanFinding as ScanFindingModel

        category_ids = await _category_ids(self._session)
        severity_ids = await _severity_ids(self._session)
        rows: list[ScanFindingModel] = []
        for finding in analysis_result.findings:
            rows.append(
                ScanFindingModel(
                    execution_id=execution_id,
                    category_id=_map_category(category_ids, finding.category),
                    severity_id=severity_ids[finding.severity.value.upper()],
                    title=finding.title[:200],
                    description=finding.description,
                    evidence=finding.evidence,
                    location=finding.location[:500],
                    recommendation=finding.recommendation,
                )
            )
        await executions.add_findings(rows)

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


async def _engine_id(session: AsyncSession, code: str = "headers-analyzer") -> int:
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


def _map_category(category_ids: dict[str, int], engine_category: str) -> int:
    mapping = {
        "http.security-headers": "MISSING_SECURITY_HEADER",
        "http.cookies": "MISSING_SECURITY_HEADER",
        "http.transport": "WEAK_CIPHER",
        "http.server-info": "MISSING_SECURITY_HEADER",
    }
    code = mapping.get(engine_category, _CATEGORY_FALLBACK)
    return category_ids.get(code, category_ids[_CATEGORY_FALLBACK])


async def _severity_ids(session: AsyncSession) -> dict[str, int]:
    from sqlalchemy import select

    from src.infrastructure.database.models import SeverityLevel

    rows = await session.execute(select(SeverityLevel.code, SeverityLevel.id))
    mapping: dict[str, int] = {}
    for code, id_ in rows.all():
        mapping[code] = id_
    return mapping
