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
from datetime import UTC, datetime, timedelta
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

    from src.domain.events.events import DomainEvent
    from src.domain.scans.rate_limit import RedisAtomicRateLimiter
    from src.domain.users.user_service import UserAccount
    from src.reporting.assembler import ReportDocument


SCAN_STATUS_QUEUED_CODE = SCAN_STATUS_QUEUED
SCAN_STATUS_RUNNING_CODE = SCAN_STATUS_RUNNING
SCAN_STATUS_REJECTED_CODE = SCAN_STATUS_REJECTED
SCAN_STATUS_SCAN_COMPLETE_CODE = SCAN_STATUS_SCAN_COMPLETE
SCAN_STATUS_AI_CODE = SCAN_STATUS_AI_ANALYSIS
SCAN_STATUS_REPORT_READY_CODE = SCAN_STATUS_REPORT_READY
SCAN_STATUS_REPORT_DEGRADED_CODE = SCAN_STATUS_REPORT_READY_DEGRADED
SCAN_STATUS_CANCELLED_CODE = SCAN_STATUS_CANCELLED

REPORT_V2_SCHEMA_VERSION = "sgpt.report.v2"

# Scan statuses that carry persisted findings and can anchor a report
# delta (v1 render states excluded: nothing deterministic to diff).
REPORT_V2_COMPLETED_STATUSES = frozenset(
    {
        "SCAN_COMPLETE",
        "AI_ANALYSIS",
        "REPORT_READY",
        "REPORT_READY_DEGRADED",
        "PARTIALLY_COMPLETE",
    }
)

# Canonical finding categories produced by the TLS posture engine.
REPORT_V2_TLS_CATEGORIES = frozenset({"OUTDATED_TLS", "WEAK_CIPHER"})


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


@dataclass(frozen=True)
class _FingerprintBuckets:
    """Deterministic fingerprint-set classification for one scan pair.

    ``a_map``/``b_map`` map fingerprint → (finding_id, title, severity,
    category) for scans A and B; the four lists hold sorted fingerprints.
    Shared by the legacy bucket view and the intelligence view so the two
    can never disagree on classification.
    """

    a_map: dict[str, tuple[uuid.UUID, str, str, str]]
    b_map: dict[str, tuple[uuid.UUID, str, str, str]]
    new: list[str]
    regressed: list[str]
    persistent: list[str]
    resolved: list[str]


class ScanPipeline(Protocol):
    """The secure scanning chain, abstracted for orchestration/testing."""

    def run(self, *, hostname: str, scheme: str, port: int, path: str) -> Any: ...


class ScanService:
    """Business rules + execution orchestration for the ``scan`` aggregate."""

    def __init__(
        self,
        session: AsyncSession,
        principal: UserAccount | None = None,
        *,
        scan_limiter: RedisAtomicRateLimiter | None = None,
        max_queued_per_user: int = 5,
        max_running_per_user: int = 2,
    ) -> None:
        self._session = session
        self._principal = principal
        self._scan_limiter = scan_limiter
        self._max_queued_per_user = max_queued_per_user
        self._max_running_per_user = max_running_per_user

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

        # Abuse protection runs AFTER validation (rejected scans must not
        # consume rate budget) and BEFORE persistence (nothing is stored on
        # the 429 paths, so retrying never duplicates work).
        await self._admission_guard(principal.id)

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
                "ownerUserId": str(principal.id),
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
        # Rescans create real queue load: same guard as fresh creation.
        await self._admission_guard(self._assert_principal().id)
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
                "ownerUserId": str(self._assert_principal().id),
            },
            actor_user_id=self._assert_principal().id,
            occurred_at=now,
        )
        return await self._details(new_scan)

    async def get_finding_history(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> dict[str, object] | None:
        """Assemble one finding's cross-scan history (fingerprint identity).

        Returns None when the scan is invisible to the caller (handled as
        404 upstream), when the finding does not exist, or when it does not
        belong to the requested scan. Occurrences are scoped to scans the
        caller initiated, so history never leaks another user's scans.
        No historical events are invented: every entry comes from persisted
        finding rows and lifecycle history.
        """
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        finding = await executions.get_finding_by_id(finding_id)
        if finding is None:
            return None
        if finding.scan_id is not None and finding.scan_id != scan.id:
            return None
        if finding.scan_id is None and not await self._finding_in_scan(scan_id, finding_id):
            return None

        fingerprint = finding.fingerprint
        severity = await self._finding_severity(finding)
        occurrences: list[dict[str, object]] = []
        lifecycle_events: list[dict[str, object]] = []
        if fingerprint:
            occurrences = await executions.list_findings_by_fingerprint(
                fingerprint=fingerprint,
                target_id=scan.target_id,
                user_id=self._assert_principal().id,
            )
            lifecycle_events = await executions.lifecycle_events_for_fingerprint(
                fingerprint=fingerprint, target_id=scan.target_id
            )

        severity_changes: list[dict[str, object]] = []
        severities = [str(o["severity"]) for o in occurrences]
        for previous, current, occurrence in zip(
            severities[:-1], severities[1:], occurrences[1:], strict=True
        ):
            if current != previous:
                severity_changes.append(
                    {
                        "from": previous,
                        "to": current,
                        "scan_id": str(occurrence["scan_id"]),
                        "at": _iso(occurrence["created_at"]),
                    }
                )
        previous_severity: str | None = None
        for sev in reversed(
            severities[:-1] if severities and severities[-1] == severity else severities
        ):
            if sev != severity:
                previous_severity = sev
                break

        created_list = [
            o["created_at"] for o in occurrences if isinstance(o["created_at"], datetime)
        ]
        first_seen = min(created_list).isoformat() if created_list else None
        last_seen_at = max(created_list).isoformat() if created_list else None
        lifecycle_status = str(lifecycle_events[-1]["status"]) if lifecycle_events else None
        return {
            "finding_id": str(finding.id),
            "scan_id": str(scan.id),
            "fingerprint": fingerprint,
            "title": finding.title,
            "current_severity": severity,
            "previous_severity": previous_severity,
            "lifecycle_status": lifecycle_status,
            "first_seen_at": first_seen,
            "last_seen_at": last_seen_at,
            "occurrences": [
                {
                    "finding_id": str(o["id"]),
                    "scan_id": str(o["scan_id"]),
                    "severity": str(o["severity"]),
                    "created_at": _iso(o["created_at"]),
                }
                for o in occurrences
            ],
            "lifecycle_events": [
                {
                    "status": str(e["status"]),
                    "effective_at": _iso(e["effective_at"]),
                    "observed_in_scan_id": str(e["observed_in_scan_id"]),
                }
                for e in lifecycle_events
            ],
            "severity_changes": severity_changes,
        }

    async def _finding_in_scan(self, scan_id: uuid.UUID, finding_id: uuid.UUID) -> bool:
        """Fallback association check for legacy rows without denormalized scan_id."""
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        rows = await ScanEngineExecutionRepository(self._session).list_finding_dtos(scan_id)
        return any(str(row["id"]) == str(finding_id) for row in rows)

    async def _finding_severity(self, finding: ScanFinding) -> str:
        """Canonical severity code for one finding row."""
        from src.infrastructure.database.models import SeverityLevel

        row = await self._session.execute(
            select(SeverityLevel.code).where(SeverityLevel.id == finding.severity_id)
        )
        code = row.scalar()
        return str(code) if code is not None else "UNKNOWN"

    async def get_finding_enrichment(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> list[dict[str, object]] | None:
        """Advisory enrichment rows for one finding's fingerprint.

        Same gates as history (visible scan + association); None maps to
        404 upstream. Returns [] when the fingerprint has no enrichment —
        absence is normal, not an error.
        """
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        finding = await executions.get_finding_by_id(finding_id)
        if finding is None:
            return None
        if finding.scan_id is not None and finding.scan_id != scan.id:
            return None
        if finding.scan_id is None and not await self._finding_in_scan(scan_id, finding_id):
            return None
        if not finding.fingerprint:
            return []
        return await executions.list_enrichment(
            fingerprint=finding.fingerprint, target_id=scan.target_id
        )

    async def attach_finding_enrichment(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID, payload: dict[str, object]
    ) -> dict[str, object] | None:
        """Validate and attach one enrichment row (deduplicated).

        Validation failures raise InvalidEnrichmentError (400); re-attaching
        the same advisory returns the existing row. Canonical finding
        fields are never touched by this path.
        """
        from src.domain.scans.enrichment import EnrichmentInput, EnrichmentValidationError
        from src.domain.scans.errors import InvalidEnrichmentError
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        try:
            validated = EnrichmentInput.parse(payload)
        except EnrichmentValidationError as exc:
            raise InvalidEnrichmentError(str(exc)) from exc
        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        finding = await executions.get_finding_by_id(finding_id)
        if finding is None:
            return None
        if finding.scan_id is not None and finding.scan_id != scan.id:
            return None
        if finding.scan_id is None and not await self._finding_in_scan(scan_id, finding_id):
            return None
        if not finding.fingerprint:
            raise InvalidEnrichmentError("Finding has no fingerprint to enrich.")
        return await executions.add_enrichment(
            fingerprint=finding.fingerprint,
            target_id=scan.target_id,
            source=validated.source,
            external_ref=validated.external_ref,
            cve_id=validated.cve_id,
            cwe_id=validated.cwe_id,
            cvss_score=validated.cvss_score,
            cvss_vector=validated.cvss_vector,
            references=validated.references,
            affected_technology=validated.affected_technology,
            remediation=validated.remediation,
        )

    async def get_finding_remediation(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> dict[str, object] | None:
        """Operator remediation workflow state for one finding's fingerprint.

        Same gates as enrichment (visible scan + association); None maps
        to 404 upstream. None is also returned when no workflow state was
        ever recorded — absence is normal, not an error.
        """
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        fingerprint = await self._finding_fingerprint_for(scan_id, finding_id)
        if fingerprint is None:
            return None
        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        row = await executions.get_remediation(fingerprint=fingerprint, target_id=scan.target_id)
        if row is None:
            return None
        return await self._with_assignee_display(row)

    async def set_finding_remediation(
        self,
        scan_id: uuid.UUID,
        finding_id: uuid.UUID,
        payload: dict[str, object],
        events: list[DomainEvent] | None = None,
    ) -> dict[str, object] | None:
        """Record operator remediation workflow state (upsert, 200).

        Validation failures raise InvalidRemediationError (400). Setting
        DONE records operator intent only — the canonical lifecycle still
        moves to RESOLVED exclusively from deterministic scan evidence.
        When ``events`` is provided, the transition appends a
        REMEDIATION_CHANGED domain event (old status resolved first, so
        the event carries the honest before/after pair).

        M8 collaboration (same endpoint, no new identity): the payload
        may also carry ``assigneeUserId`` (UUID string or null to clear)
        and ``dueAt`` (timezone-aware ISO-8601 or null to clear). Absent
        keys leave stored values untouched. Assignment is owner-gated by
        the same finding-visibility checks below and grants no
        visibility to the assignee — strict ownership is unchanged. The
        assignee must exist and be active (unknown ids are 404,
        inactive accounts are 400). Every assignment change and due-date
        change appends its own audit event; status/notes keep the
        existing REMEDIATION_UPDATED code.
        """
        import uuid as _uuid

        from src.domain.events.events import remediation_event
        from src.domain.scans.errors import InvalidRemediationError
        from src.domain.scans.remediation import RemediationInput, RemediationValidationError
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )
        from src.infrastructure.database.repositories.user_repository import UserRepository

        try:
            validated = RemediationInput.parse(payload)
        except RemediationValidationError as exc:
            raise InvalidRemediationError(str(exc)) from exc
        fingerprint = await self._finding_fingerprint_for(scan_id, finding_id)
        if fingerprint is None:
            return None
        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        previous = await executions.get_remediation(
            fingerprint=fingerprint, target_id=scan.target_id
        )
        previous_status: str | None = str(previous.get("status")) if previous is not None else None
        previous_assignee: str | None = (
            str(previous.get("assignee_user_id"))
            if previous is not None and previous.get("assignee_user_id") is not None
            else None
        )
        previous_due: str | None = (
            str(previous.get("due_at"))
            if previous is not None and previous.get("due_at") is not None
            else None
        )
        assignee_id: _uuid.UUID | None = None
        if validated.assignee_changed and validated.assignee_user_id is not None:
            try:
                assignee_id = _uuid.UUID(validated.assignee_user_id)
            except ValueError as exc:
                raise InvalidRemediationError("assigneeUserId must be a UUID.") from exc
            assignee = await UserRepository(self._session).get_by_id(assignee_id)
            if assignee is None:
                raise NotFoundError()
            if not assignee.is_active:
                raise InvalidRemediationError("assignee account is not active.")
        row = await executions.set_remediation(
            fingerprint=fingerprint,
            target_id=scan.target_id,
            status=validated.status,
            notes=validated.notes,
            updated_by_user_id=self._assert_principal().id,
            assignee_user_id=assignee_id,
            assignee_set=validated.assignee_changed,
            due_at=validated.due_at,
            due_at_set=validated.due_at_changed,
            assigned_by_user_id=self._assert_principal().id,
        )
        from src.domain.audit.audit_service import (
            ACTION_REMEDIATION_ASSIGNED,
            ACTION_REMEDIATION_DUE_DATE_CHANGED,
            ACTION_REMEDIATION_REASSIGNED,
            ACTION_REMEDIATION_UPDATED,
            AuditService,
        )

        audit = AuditService(self._session)
        await audit.record(
            action_code=ACTION_REMEDIATION_UPDATED,
            entity_type="finding_remediation",
            entity_id=finding_id,
            metadata_json={
                "fingerprint": fingerprint,
                "targetId": str(scan.target_id),
                "from": previous_status,
                "to": validated.status,
            },
            actor_user_id=self._assert_principal().id,
        )
        new_assignee = str(row.get("assignee_user_id")) if row.get("assignee_user_id") else None
        if validated.assignee_changed and new_assignee != previous_assignee:
            await audit.record(
                action_code=(
                    ACTION_REMEDIATION_ASSIGNED
                    if previous_assignee is None
                    else ACTION_REMEDIATION_REASSIGNED
                ),
                entity_type="finding_remediation",
                entity_id=finding_id,
                metadata_json={
                    "fingerprint": fingerprint,
                    "targetId": str(scan.target_id),
                    "from": previous_assignee,
                    "to": new_assignee,
                },
                actor_user_id=self._assert_principal().id,
            )
        new_due = str(row.get("due_at")) if row.get("due_at") else None
        if validated.due_at_changed and new_due != previous_due:
            await audit.record(
                action_code=ACTION_REMEDIATION_DUE_DATE_CHANGED,
                entity_type="finding_remediation",
                entity_id=finding_id,
                metadata_json={
                    "fingerprint": fingerprint,
                    "targetId": str(scan.target_id),
                    "from": previous_due,
                    "to": new_due,
                },
                actor_user_id=self._assert_principal().id,
            )
        if events is not None:
            events.append(
                remediation_event(
                    target_id=scan.target_id,
                    fingerprint=fingerprint,
                    scan_id=scan.id,
                    old_status=previous_status,
                    new_status=validated.status,
                    occurred_at=datetime.now(UTC),
                    updated_by_user_id=self._assert_principal().id,
                )
            )
        return await self._with_assignee_display(row)

    async def _with_assignee_display(self, row: dict[str, object]) -> dict[str, object]:
        """Attach assignee email + derived overdue to one remediation DTO.

        Single extra query for the single assignee (list paths batch
        through ``with_assignee_displays`` instead).
        """
        return (await self.with_assignee_displays([row]))[0]

    async def with_assignee_displays(
        self, rows: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        """Batch display enrichment for remediation DTOs (one user query).

        Adds ``assignee_email`` (None when unassigned or the account
        vanished) and the derived ``overdue`` flag. Never touches
        canonical finding data.
        """
        from src.domain.scans.remediation import is_overdue
        from src.infrastructure.database.repositories.user_repository import UserRepository

        needed: list[uuid.UUID] = []
        for row in rows:
            raw = row.get("assignee_user_id")
            if isinstance(raw, str) and raw:
                try:
                    candidate = uuid.UUID(raw)
                except ValueError:
                    continue
                if candidate not in needed:
                    needed.append(candidate)
        basics = await UserRepository(self._session).basic_by_ids(needed)
        enriched: list[dict[str, object]] = []
        for row in rows:
            out = dict(row)
            raw = row.get("assignee_user_id")
            email: str | None = None
            if isinstance(raw, str) and raw and raw in basics:
                candidate_email = basics[raw].get("email")
                email = str(candidate_email) if candidate_email is not None else None
            out["assignee_email"] = email
            due_raw = row.get("due_at")
            due_at: datetime | None = None
            if isinstance(due_raw, str) and due_raw:
                try:
                    due_at = datetime.fromisoformat(due_raw)
                except ValueError:
                    due_at = None
            out["overdue"] = is_overdue(due_at=due_at, status=str(row.get("status", "TODO")))
            enriched.append(out)
        return enriched

    async def add_remediation_comment(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID, payload: dict[str, object]
    ) -> dict[str, object] | None:
        """Append one collaboration comment (201 semantics, 200 transport).

        Same gates as remediation (visible scan + association → else
        None/404). The author is always the principal; authorship cannot
        be spoofed. Comments never mutate canonical finding data and are
        excluded from reports. The audit event references the comment id
        only — bodies may carry pasted operator text, so they stay out
        of the audit trail.
        """
        from src.domain.scans.errors import InvalidRemediationError
        from src.domain.scans.remediation import CommentInput, RemediationValidationError
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        try:
            validated = CommentInput.parse(payload)
        except RemediationValidationError as exc:
            raise InvalidRemediationError(str(exc)) from exc
        fingerprint = await self._finding_fingerprint_for(scan_id, finding_id)
        if fingerprint is None:
            return None
        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        row = await executions.add_comment(
            fingerprint=fingerprint,
            target_id=scan.target_id,
            author_user_id=self._assert_principal().id,
            body=validated.body,
        )
        from src.domain.audit.audit_service import (
            ACTION_REMEDIATION_COMMENT_ADDED,
            AuditService,
        )

        await AuditService(self._session).record(
            action_code=ACTION_REMEDIATION_COMMENT_ADDED,
            entity_type="remediation_comment",
            entity_id=uuid.UUID(str(row["id"])),
            metadata_json={
                "fingerprint": fingerprint,
                "targetId": str(scan.target_id),
            },
            actor_user_id=self._assert_principal().id,
        )
        return await self._with_comment_author(row)

    async def list_remediation_comments(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID, *, limit: int = 100
    ) -> list[dict[str, object]] | None:
        """Comments for one finding's remediation identity, oldest first.

        Same gates as remediation (None → 404). Bounded (default 100).
        Author emails resolve in one batched query.
        """
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )
        from src.infrastructure.database.repositories.user_repository import UserRepository

        fingerprint = await self._finding_fingerprint_for(scan_id, finding_id)
        if fingerprint is None:
            return None
        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        rows = await executions.list_comments(
            fingerprint=fingerprint, target_id=scan.target_id, limit=limit
        )
        needed: list[uuid.UUID] = []
        for row in rows:
            raw = row.get("author_user_id")
            if isinstance(raw, str) and raw:
                try:
                    candidate = uuid.UUID(raw)
                except ValueError:
                    continue
                if candidate not in needed:
                    needed.append(candidate)
        basics = await UserRepository(self._session).basic_by_ids(needed)
        out: list[dict[str, object]] = []
        for row in rows:
            item = dict(row)
            raw = row.get("author_user_id")
            item["author_email"] = (
                str(basics[str(raw)].get("email"))
                if isinstance(raw, str) and raw in basics
                else None
            )
            out.append(item)
        return out

    async def _with_comment_author(self, row: dict[str, object]) -> dict[str, object]:
        """Attach the author's email to one freshly written comment."""
        from src.infrastructure.database.repositories.user_repository import UserRepository

        item = dict(row)
        raw = row.get("author_user_id")
        email: str | None = None
        if isinstance(raw, str) and raw:
            try:
                basics = await UserRepository(self._session).basic_by_ids([uuid.UUID(raw)])
            except ValueError:
                basics = {}
            if raw in basics:
                candidate = basics[raw].get("email")
                email = str(candidate) if candidate is not None else None
        item["author_email"] = email
        return item

    async def get_remediation_summary(self) -> dict[str, object]:
        """Deterministic remediation aggregates for the owner's targets.

        Four queries total (targets, remediation rows, bounded lifecycle
        history, assignee basics) — no N+1. Lifecycle-aware buckets
        (done-open, resolved/regressed after remediation) only count
        identities with known lifecycle state; unknown stays unbucketed
        rather than guessed. Ordering is deterministic
        (target, fingerprint).
        """
        from src.domain.scans.remediation import DONE, is_overdue
        from src.infrastructure.database.repositories.posture_repository import (
            PostureRepository,
        )
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        principal = self._assert_principal()
        posture_repo = PostureRepository(self._session)
        targets = await posture_repo.list_owned_targets(principal.id)
        target_ids: list[uuid.UUID] = []
        for target_entry in targets:
            raw_id = target_entry.get("id")
            if isinstance(raw_id, str) and raw_id:
                try:
                    target_ids.append(uuid.UUID(raw_id))
                except ValueError:
                    continue
        executions = ScanEngineExecutionRepository(self._session)
        rows = await executions.list_remediations_for_owner_targets(target_ids=target_ids)
        rows = await self.with_assignee_displays(rows)

        history = await posture_repo.history_events(target_ids, limit=10_000)
        latest_lifecycle: dict[tuple[str, str], str] = {}
        for event in history:
            history_target = event.get("target_id")
            history_fingerprint = event.get("fingerprint")
            history_status = event.get("status")
            if (
                isinstance(history_target, str)
                and isinstance(history_fingerprint, str)
                and history_status is not None
            ):
                latest_lifecycle[(history_target, history_fingerprint)] = str(history_status)

        by_status: dict[str, int] = {}
        by_assignee: dict[str, int] = {}
        assigned = 0
        unassigned = 0
        due_open = 0
        overdue = 0
        no_due = 0
        done_open = 0
        resolved_after = 0
        regressed_after = 0
        lifecycle_unknown = 0
        overdue_items: list[dict[str, object]] = []
        due_soon_items: list[dict[str, object]] = []
        unassigned_items: list[dict[str, object]] = []
        now = datetime.now(UTC)
        due_soon_horizon = now + timedelta(days=3)

        for row in rows:
            row_status = str(row.get("status", "TODO"))
            by_status[row_status] = by_status.get(row_status, 0) + 1
            target_id_str = str(row.get("target_id", ""))
            fingerprint_str = str(row.get("fingerprint", ""))
            stub = {
                "fingerprint": fingerprint_str,
                "target_id": target_id_str,
                "status": row_status,
                "assignee_user_id": row.get("assignee_user_id"),
                "assignee_email": row.get("assignee_email"),
                "due_at": row.get("due_at"),
                "overdue": bool(row.get("overdue")),
            }
            assignee = row.get("assignee_user_id")
            if isinstance(assignee, str) and assignee:
                assigned += 1
                by_assignee[assignee] = by_assignee.get(assignee, 0) + 1
            else:
                unassigned += 1
                if len(unassigned_items) < 200:
                    unassigned_items.append(stub)
            due_raw = row.get("due_at")
            due_at: datetime | None = None
            if isinstance(due_raw, str) and due_raw:
                try:
                    due_at = datetime.fromisoformat(due_raw)
                except ValueError:
                    due_at = None
            if due_at is None:
                no_due += 1
            elif is_overdue(due_at=due_at, status=row_status, now=now):
                overdue += 1
                if len(overdue_items) < 200:
                    overdue_items.append(stub)
            else:
                due_open += 1
                aware_due = due_at if due_at.tzinfo is not None else due_at.replace(tzinfo=UTC)
                if (
                    row_status != DONE
                    and aware_due <= due_soon_horizon
                    and len(due_soon_items) < 200
                ):
                    due_soon_items.append(stub)
            lifecycle = latest_lifecycle.get((target_id_str, fingerprint_str))
            if lifecycle is None:
                lifecycle_unknown += 1
            elif lifecycle == "RESOLVED":
                resolved_after += 1
            elif lifecycle == "REGRESSED":
                regressed_after += 1
            elif row_status == DONE:
                done_open += 1

        return {
            "total": len(rows),
            "by_status": dict(sorted(by_status.items())),
            "assigned": assigned,
            "unassigned": unassigned,
            "due_open": due_open,
            "overdue": overdue,
            "no_due_date": no_due,
            "done_open": done_open,
            "resolved_after_remediation": resolved_after,
            "regressed_after_remediation": regressed_after,
            "lifecycle_unknown": lifecycle_unknown,
            "by_assignee": dict(sorted(by_assignee.items())),
            "overdue_items": overdue_items,
            "due_soon_items": due_soon_items,
            "unassigned_items": unassigned_items,
        }

    async def request_verify_fix(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> dict[str, object] | None:
        """Request fix verification: rescan + link, same gates throughout.

        Creates a rescan of the finding's scan through ``rescan_scan``
        (attestation, quota, and rate gates enforced there — failures
        propagate unchanged and nothing is persisted), then links the
        finding's remediation row to the new scan. Requires existing
        remediation workflow state (mark first, then verify).
        """
        from src.domain.audit.audit_service import (
            ACTION_REMEDIATION_VERIFY_REQUESTED,
            AuditService,
        )
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        fingerprint = await self._finding_fingerprint_for(scan_id, finding_id)
        if fingerprint is None:
            return None
        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        existing = await executions.get_remediation(
            fingerprint=fingerprint, target_id=scan.target_id
        )
        if existing is None:
            raise NotFoundError()
        rescan = await self.rescan_scan(scan_id)
        await executions.set_verification_link(
            fingerprint=fingerprint,
            target_id=scan.target_id,
            scan_id=rescan.id,
        )
        await AuditService(self._session).record(
            action_code=ACTION_REMEDIATION_VERIFY_REQUESTED,
            entity_type="finding_remediation",
            entity_id=finding_id,
            metadata_json={
                "fingerprint": fingerprint,
                "targetId": str(scan.target_id),
                "rescanId": str(rescan.id),
            },
            actor_user_id=self._assert_principal().id,
        )
        return {
            "finding_id": str(finding_id),
            "fingerprint": fingerprint,
            "rescan_id": str(rescan.id),
            "rescan_status": rescan.status_code,
            "state": "pending",
        }

    async def get_verify_fix_status(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> dict[str, object] | None:
        """Derive verification state live (never stored, cannot go stale).

        ``pending`` while the verification rescan has not completed,
        ``stale`` when it failed or was cancelled, ``verified_fixed``
        when the fingerprint is absent from the completed rescan, and
        ``still_present`` otherwise. Resolution itself stays
        scan-derived; this endpoint only reports it.
        """
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        fingerprint = await self._finding_fingerprint_for(scan_id, finding_id)
        if fingerprint is None:
            return None
        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        remediation = await executions.get_remediation(
            fingerprint=fingerprint, target_id=scan.target_id
        )
        if remediation is None or not remediation.get("verified_in_scan_id"):
            return {"state": "none", "rescan_id": None}
        rescan_id = remediation["verified_in_scan_id"]
        assert isinstance(rescan_id, str)
        try:
            rescan = await self._get_visible_scan(uuid.UUID(rescan_id))
        except NotFoundError:
            return {"state": "stale", "rescan_id": rescan_id}
        status = await self._status_for_scan(rescan)
        if status not in ("REPORT_READY", "REPORT_READY_DEGRADED"):
            if status in ("REJECTED", "CANCELLED"):
                return {"state": "stale", "rescan_id": rescan_id, "rescan_status": status}
            return {"state": "pending", "rescan_id": rescan_id, "rescan_status": status}
        comparison = await self.compare_scans(scan_id, rescan.id)
        resolved_fps = {item["fingerprint"] for item in comparison["resolved"]}
        state = "verified_fixed" if fingerprint in resolved_fps else "still_present"
        return {
            "state": state,
            "rescan_id": rescan_id,
            "rescan_status": status,
            "completed_at": rescan.completed_at.isoformat() if rescan.completed_at else None,
        }

    async def get_scan_report_v2(self, scan_id: uuid.UUID) -> dict[str, object] | None:
        """Assemble the deterministic v2 evidence report (M5, read-only).

        The report is derived exclusively from stored deterministic
        evidence: scan metadata, engine executions, findings with
        lifecycle/priority, operator remediation workflow + M4
        verification states, delta vs the previous completed scan of the
        same target, passive technology inventory, and a TLS summary.
        It contains no AI interpretation of any kind (the v1 assessment
        section is excluded by design), and every section recomputes on
        each call, so the document cannot go stale.

        ``contentHash`` is the SHA-256 of the canonical JSON encoding of
        the document minus ``generatedAt``/``contentHash``: two renders
        over unchanged evidence are verifiably identical. Invisible or
        missing scans return None (404, never 403).
        """
        import hashlib
        import json

        from src.reporting.assembler import ReportAssembler

        scan = await self._get_visible_scan(scan_id)
        base = await ReportAssembler(self._session).assemble(scan_id)
        if base is None:
            return None

        remediation_map = await self._remediation_map_for_report(scan.target_id)
        enriched_rows = await self.with_assignee_displays(list(remediation_map.values()))
        remediation_map = {
            str(row.get("fingerprint", fingerprint)): row
            for fingerprint, row in zip(remediation_map, enriched_rows, strict=True)
        }
        verification = await self._batched_verification(scan_id, remediation_map)
        delta = await self._delta_for_report(scan)
        technologies = await self._technologies_for_report(scan.target_id)

        findings: list[dict[str, object]] = []
        for finding in base.findings:
            remediation = (
                remediation_map.get(finding.fingerprint or "") if finding.fingerprint else None
            )
            findings.append(
                {
                    "id": str(finding.id),
                    "fingerprint": finding.fingerprint,
                    "severity": finding.severity,
                    "category": finding.category,
                    "title": finding.title,
                    "description": finding.description,
                    "evidence": finding.evidence,
                    "location": finding.location,
                    "recommendation": finding.recommendation,
                    "lifecycleStatus": finding.lifecycle_status,
                    "priority": finding.priority.to_dict() if finding.priority else None,
                    "remediation": (
                        {
                            "status": remediation.get("status"),
                            "notes": remediation.get("notes"),
                            "updatedAt": remediation.get("updated_at"),
                            "assigneeUserId": remediation.get("assignee_user_id"),
                            "assigneeEmail": remediation.get("assignee_email"),
                            "dueAt": remediation.get("due_at"),
                            "overdue": bool(remediation.get("overdue")),
                        }
                        if remediation is not None
                        else None
                    ),
                    "verification": verification.get(finding.fingerprint or ""),
                }
            )

        document: dict[str, object] = {
            "schemaVersion": REPORT_V2_SCHEMA_VERSION,
            "deterministic": True,
            "generatedAt": datetime.now(UTC).isoformat(),
            "scan": {
                "id": str(base.scan.scan_id),
                "targetHostname": base.scan.target_hostname,
                "targetNormalizedUrl": base.scan.target_normalized_url,
                "scanProfile": base.scan.scan_profile,
                "status": base.scan.scan_status,
                "queuedAt": base.scan.queued_at.isoformat() if base.scan.queued_at else None,
                "startedAt": base.scan.started_at.isoformat() if base.scan.started_at else None,
                "completedAt": base.scan.completed_at.isoformat()
                if base.scan.completed_at
                else None,
            },
            "engines": [
                {
                    "engineCode": engine.engine_code,
                    "toolVersionSnapshot": engine.tool_version_snapshot,
                    "status": engine.status,
                    "startedAt": engine.started_at.isoformat() if engine.started_at else None,
                    "completedAt": engine.completed_at.isoformat() if engine.completed_at else None,
                    "errorMessage": engine.error_message,
                }
                for engine in base.engines
            ],
            "severityCounts": dict(sorted(base.severity_counts.items())),
            "lifecycleCounts": dict(sorted(base.lifecycle_counts.items())),
            "findings": findings,
            "delta": delta,
            "technologies": technologies,
            "tlsSummary": self._tls_summary(base),
            "complianceEvidence": self._compliance_section_for_report(scan, base, remediation_map),
        }
        canonical_doc = {
            key: value
            for key, value in document.items()
            if key not in ("generatedAt", "contentHash")
        }
        canonical = json.dumps(canonical_doc, sort_keys=True, separators=(",", ":"), default=str)
        document["contentHash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return document

    async def _remediation_map_for_report(
        self, target_id: uuid.UUID
    ) -> dict[str, dict[str, object]]:
        """All remediation rows for one target, keyed by fingerprint."""
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        return await ScanEngineExecutionRepository(self._session).list_remediations_for_target(
            target_id=target_id
        )

    @staticmethod
    def _compliance_section_for_report(
        scan: Scan,
        base: ReportDocument,
        remediation_map: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        """Compliance-evidence section (M9, derived, not a certification).

        Reuses the report's already-assembled deterministic evidence
        (zero new queries): per-framework control relevance over this
        scan's findings with lifecycle + remediation states. Finding
        references omit evidence payloads here — the assessment API is
        the evidence-trace surface. The section always carries the
        mapping version and the not-a-certification disclaimer.
        """
        from src.domain.compliance.assessment import DISCLAIMER, assess_control
        from src.domain.compliance.catalog import MAPPING_VERSION, list_frameworks

        views: list[dict[str, object]] = []
        for finding in base.findings:
            remediation = (
                remediation_map.get(finding.fingerprint or "") if finding.fingerprint else None
            )
            views.append(
                {
                    "finding_id": str(finding.id),
                    "fingerprint": finding.fingerprint,
                    "target_id": str(scan.target_id),
                    "scan_id": str(scan.id),
                    "category": finding.category,
                    "title": finding.title,
                    "severity": finding.severity,
                    "lifecycle": finding.lifecycle_status,
                    "remediation_status": (
                        remediation.get("status") if remediation is not None else None
                    ),
                    "priority_level": (finding.priority.level if finding.priority else None),
                    "evidence": [],
                    "observed_at": _scan_moment(scan),
                }
            )
        frameworks: list[dict[str, object]] = []
        for framework in list_frameworks():
            frameworks.append(
                {
                    "framework": framework.framework_id,
                    "framework_name": framework.name,
                    "framework_version": framework.version,
                    "mapping_version": MAPPING_VERSION,
                    "controls": [
                        assess_control(framework, control.control_id, views)
                        for control in sorted(framework.controls, key=lambda c: c.control_id)
                    ],
                }
            )
        return {
            "mapping_version": MAPPING_VERSION,
            "disclaimer": DISCLAIMER,
            "frameworks": frameworks,
        }

    async def _delta_for_report(self, scan: Scan) -> dict[str, object] | None:
        """Delta vs the previous completed scan of the same target.

        ``compare_scans(previous, current)`` orients the buckets so
        ``new`` means first seen in this scan and ``resolved`` means
        gone since the previous one. None when no earlier completed
        scan exists (first scan of a target has no delta).
        """
        candidates = await self.list_scans(target_id=scan.target_id, limit=50)
        earlier = [
            details
            for details in candidates
            if details.id != scan.id
            and details.status_code in REPORT_V2_COMPLETED_STATUSES
            and details.created_at < scan.created_at
        ]
        if not earlier:
            return None
        previous = max(earlier, key=lambda details: details.created_at)
        buckets = await self.compare_scans(previous.id, scan.id)
        fingerprint_lists = {
            bucket: sorted(str(item.get("fingerprint", "")) for item in rows)
            for bucket, rows in buckets.items()
        }
        return {
            "previousScanId": str(previous.id),
            "counts": {bucket: len(rows) for bucket, rows in buckets.items()},
            "fingerprints": fingerprint_lists,
        }

    async def _technologies_for_report(self, target_id: uuid.UUID) -> list[dict[str, object]]:
        """Passive technology inventory section (observations only)."""
        from src.infrastructure.database.repositories.target_repository import (
            TargetRepository,
        )

        rows = await TargetRepository(self._session).list_technologies(target_id)
        return [
            {
                "slug": row.get("slug"),
                "display": row.get("display"),
                "family": row.get("family"),
                "version": row.get("version"),
                "confidence": row.get("confidence"),
                "observedInScanId": row.get("observed_in_scan_id"),
                "firstObservedAt": row.get("first_observed_at"),
                "lastObservedAt": row.get("last_observed_at"),
            }
            for row in rows
        ]

    async def _batched_verification(
        self, scan_id: uuid.UUID, remediation_map: dict[str, dict[str, object]]
    ) -> dict[str, dict[str, object] | None]:
        """M4 verification states for every linked fingerprint, batched.

        Findings sharing one verification rescan share one comparison
        (one ``compare_scans`` per distinct rescan, not per finding).
        Same derivation as ``get_verify_fix_status``: pending while the
        rescan runs, stale when it failed/was cancelled or the link
        dangles, verified_fixed/still_present from the completed diff.
        Unlinked fingerprints map to None (no verification requested).
        """
        links: dict[str, str] = {}
        for fingerprint, row in remediation_map.items():
            rescan_id = row.get("verified_in_scan_id")
            if isinstance(rescan_id, str) and rescan_id:
                links[fingerprint] = rescan_id

        states: dict[str, dict[str, object] | None] = dict.fromkeys(remediation_map)
        by_rescan: dict[str, list[str]] = {}
        for fingerprint, rescan_id in links.items():
            by_rescan.setdefault(rescan_id, []).append(fingerprint)

        for rescan_id, fingerprints in by_rescan.items():
            try:
                rescan = await self._get_visible_scan(uuid.UUID(rescan_id))
            except NotFoundError:
                for fingerprint in fingerprints:
                    states[fingerprint] = {"state": "stale", "rescanId": rescan_id}
                continue
            status = await self._status_for_scan(rescan)
            if status not in ("REPORT_READY", "REPORT_READY_DEGRADED"):
                state = "stale" if status in ("REJECTED", "CANCELLED") else "pending"
                for fingerprint in fingerprints:
                    states[fingerprint] = {
                        "state": state,
                        "rescanId": rescan_id,
                        "rescanStatus": status,
                    }
                continue
            comparison = await self.compare_scans(scan_id, rescan.id)
            resolved = {str(item.get("fingerprint", "")) for item in comparison["resolved"]}
            for fingerprint in fingerprints:
                states[fingerprint] = {
                    "state": "verified_fixed" if fingerprint in resolved else "still_present",
                    "rescanId": rescan_id,
                    "rescanStatus": status,
                }
        return states

    @staticmethod
    def _tls_summary(base: ReportDocument) -> dict[str, object]:
        """TLS posture rollup from canonical TLS finding categories."""
        tls_findings = [
            finding for finding in base.findings if finding.category in REPORT_V2_TLS_CATEGORIES
        ]
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for finding in tls_findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
        inspector_status: str | None = None
        for engine in base.engines:
            if engine.engine_code == "ssl-inspector":
                inspector_status = engine.status
        return {
            "findingCount": len(tls_findings),
            "bySeverity": dict(sorted(by_severity.items())),
            "byCategory": dict(sorted(by_category.items())),
            "inspectorStatus": inspector_status,
        }

    async def _status_for_scan(self, scan: Scan) -> str:
        """Canonical status code for a scan row (denormalized or joined)."""
        status_code = getattr(scan, "status_code", None)
        if isinstance(status_code, str):
            return status_code
        from src.infrastructure.database.repositories.scan_repository import (
            _status_code_of,
        )

        return await _status_code_of(self._session, scan.status_id)

    async def _finding_fingerprint_for(
        self, scan_id: uuid.UUID, finding_id: uuid.UUID
    ) -> str | None:
        """Resolve a finding's fingerprint after the standard visibility gates.

        Returns None when the scan is invisible, the finding is unknown or
        foreign to the scan, or the finding carries no fingerprint.
        """
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )

        scan = await self._get_visible_scan(scan_id)
        executions = ScanEngineExecutionRepository(self._session)
        finding = await executions.get_finding_by_id(finding_id)
        if finding is None:
            return None
        if finding.scan_id is not None and finding.scan_id != scan.id:
            return None
        if finding.scan_id is None and not await self._finding_in_scan(scan_id, finding_id):
            return None
        return finding.fingerprint or None

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

        buckets = await self._classify_fingerprints(scan_a, scan_b)
        a_map = buckets.a_map
        b_map = buckets.b_map

        return {
            "new": _to_compare_dtos(buckets.new, b_map),
            "persistent": _to_compare_dtos(buckets.persistent, b_map, secondary_map=a_map),
            "resolved": _to_compare_dtos(buckets.resolved, a_map),
            "regressed": _to_compare_dtos(buckets.regressed, b_map),
        }

    async def _classify_fingerprints(self, scan_a: Scan, scan_b: Scan) -> _FingerprintBuckets:
        """Shared fingerprint-set classification for both compare flavors.

        Returns the per-scan finding indexes plus the deterministically
        ordered (sorted) fingerprint lists for the four lifecycle buckets.
        Both scans must already be visibility-checked and same-target.
        """
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

        return _FingerprintBuckets(
            a_map=a_map,
            b_map=b_map,
            new=sorted(f for f in (b_fps - a_fps) if f not in history_resolved),
            regressed=sorted(f for f in regressed_candidates if f in history_resolved),
            persistent=sorted(a_fps & b_fps),
            resolved=sorted(a_fps - b_fps),
        )

    async def compare_scans_detailed(
        self, scan_a_id: uuid.UUID, scan_b_id: uuid.UUID
    ) -> dict[str, object]:
        """Deterministic comparison intelligence for two scans of one target.

        Builds on the :meth:`compare_scans` classification (same gates,
        same buckets) and adds, per finding present in either scan: severity
        / priority / remediation / evidence / enrichment transitions,
        lifecycle states, and first/last seen — plus an aggregate summary.
        The result is the AI-ready representation: a future analyst may
        narrate it but must never recompute it.

        Historical honesty (nothing is fabricated): previous-side values
        are None when the finding did not exist then; previous priority
        uses scan-A-era signals only with both versions exposed;
        previous remediation and scan-A enrichment presence are inferred
        from row timestamps (a row created or modified after scan A cannot
        describe scan-A state).
        """
        from src.domain.scans.priority import (
            PRIORITY_VERSION_V2,
            PriorityInputsV2,
            calculate_priority_v2,
        )
        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
        )
        from src.infrastructure.database.repositories.target_repository import (
            TargetRepository,
        )

        scan_a = await self._get_visible_scan(scan_a_id)
        scan_b = await self._get_visible_scan(scan_b_id)
        if scan_a.target_id != scan_b.target_id:
            raise InvalidScanStateError()

        buckets = await self._classify_fingerprints(scan_a, scan_b)
        target_id = scan_a.target_id
        user_id = self._assert_principal().id
        all_fps = sorted(
            set(buckets.a_map) | set(buckets.b_map),
            key=lambda fp: (
                _BUCKET_ORDER[
                    "new"
                    if fp in buckets.new
                    else "persistent"
                    if fp in buckets.persistent
                    else "resolved"
                    if fp in buckets.resolved
                    else "regressed"
                ],
                fp,
            ),
        )

        executions = ScanEngineExecutionRepository(self._session)
        enrichment = await executions.list_enrichment_for_fingerprints(
            fingerprints=all_fps, target_id=target_id
        )
        finding_ids = [
            str(entry[0]) for m in (buckets.a_map, buckets.b_map) for entry in m.values()
        ]
        evidence = await executions.list_evidence_for_findings(finding_ids)
        prev_lifecycle = await self._previous_lifecycle_in_scan(
            fingerprints=all_fps, target_id=target_id, scan_id=scan_a.id
        )
        bounds = await self._occurrence_bounds(
            fingerprints=all_fps, target_id=target_id, user_id=user_id
        )
        remediation = await self._remediation_states(fingerprints=all_fps, target_id=target_id)
        _tech_rows = await TargetRepository(self._session).list_technologies(target_id)
        current_technologies = _technology_signal_slugs(_tech_rows, None)
        previous_technologies = _technology_signal_slugs(
            _tech_rows, scan_a.completed_at or scan_a.created_at
        )

        scan_a_time = scan_a.completed_at or scan_a.created_at
        records: list[dict[str, object]] = []
        for fp in all_fps:
            if fp in buckets.new:
                records.append(
                    self._compare_record(
                        fingerprint=fp,
                        bucket="new",
                        a_entry=None,
                        b_entry=buckets.b_map[fp],
                        scan_a=scan_a,
                        scan_b=scan_b,
                        scan_a_time=scan_a_time,
                        prev_lifecycle=None,
                        bounds=bounds.get(fp),
                        enrichment_rows=enrichment.get(fp, []),
                        evidence_by_finding=evidence,
                        remediation_row=remediation.get(fp),
                        calculate_priority=calculate_priority_v2,
                        PriorityInputs=PriorityInputsV2,
                        priority_version=PRIORITY_VERSION_V2,
                        current_technologies=current_technologies,
                        previous_technologies=previous_technologies,
                    )
                )
            elif fp in buckets.persistent:
                records.append(
                    self._compare_record(
                        fingerprint=fp,
                        bucket="persistent",
                        a_entry=buckets.a_map[fp],
                        b_entry=buckets.b_map[fp],
                        scan_a=scan_a,
                        scan_b=scan_b,
                        scan_a_time=scan_a_time,
                        prev_lifecycle=prev_lifecycle.get(fp),
                        bounds=bounds.get(fp),
                        enrichment_rows=enrichment.get(fp, []),
                        evidence_by_finding=evidence,
                        remediation_row=remediation.get(fp),
                        calculate_priority=calculate_priority_v2,
                        PriorityInputs=PriorityInputsV2,
                        priority_version=PRIORITY_VERSION_V2,
                        current_technologies=current_technologies,
                        previous_technologies=previous_technologies,
                    )
                )
            elif fp in buckets.resolved:
                records.append(
                    self._compare_record(
                        fingerprint=fp,
                        bucket="resolved",
                        a_entry=buckets.a_map[fp],
                        b_entry=None,
                        scan_a=scan_a,
                        scan_b=scan_b,
                        scan_a_time=scan_a_time,
                        prev_lifecycle=prev_lifecycle.get(fp),
                        bounds=bounds.get(fp),
                        enrichment_rows=enrichment.get(fp, []),
                        evidence_by_finding=evidence,
                        remediation_row=remediation.get(fp),
                        calculate_priority=calculate_priority_v2,
                        PriorityInputs=PriorityInputsV2,
                        priority_version=PRIORITY_VERSION_V2,
                        current_technologies=current_technologies,
                        previous_technologies=previous_technologies,
                    )
                )
            else:
                records.append(
                    self._compare_record(
                        fingerprint=fp,
                        bucket="regressed",
                        a_entry=None,
                        b_entry=buckets.b_map[fp],
                        scan_a=scan_a,
                        scan_b=scan_b,
                        scan_a_time=scan_a_time,
                        prev_lifecycle=None,
                        bounds=bounds.get(fp),
                        enrichment_rows=enrichment.get(fp, []),
                        evidence_by_finding=evidence,
                        remediation_row=remediation.get(fp),
                        calculate_priority=calculate_priority_v2,
                        PriorityInputs=PriorityInputsV2,
                        priority_version=PRIORITY_VERSION_V2,
                        current_technologies=current_technologies,
                        previous_technologies=previous_technologies,
                    )
                )

        # Legacy buckets stay byte-compatible for existing consumers.
        return {
            "new": _to_compare_dtos(buckets.new, buckets.b_map),
            "persistent": _to_compare_dtos(
                buckets.persistent, buckets.b_map, secondary_map=buckets.a_map
            ),
            "resolved": _to_compare_dtos(buckets.resolved, buckets.a_map),
            "regressed": _to_compare_dtos(buckets.regressed, buckets.b_map),
            "records": records,
            "summary": _compare_summary(records),
        }

    @staticmethod
    def _compare_record(
        *,
        fingerprint: str,
        bucket: str,
        a_entry: tuple[uuid.UUID, str, str, str] | None,
        b_entry: tuple[uuid.UUID, str, str, str] | None,
        scan_a: Scan,
        scan_b: Scan,
        scan_a_time: datetime,
        prev_lifecycle: str | None,
        bounds: dict[str, datetime | None] | None,
        enrichment_rows: list[dict[str, object]],
        evidence_by_finding: dict[str, list[dict[str, str]]],
        remediation_row: dict[str, object] | None,
        calculate_priority: Any,
        PriorityInputs: Any,
        priority_version: str,
        current_technologies: tuple[str, ...] = (),
        previous_technologies: tuple[str, ...] = (),
    ) -> dict[str, object]:
        """Assemble one deterministic comparison record (pure assembly).

        ``a_entry``/``b_entry`` are (finding_id, title, severity, category)
        index rows; exactly one may be None (new/resolved/regressed).
        """
        current = b_entry if b_entry is not None else a_entry
        assert current is not None
        cur_id, cur_title, cur_severity, cur_category = current
        prev_severity = a_entry[2] if a_entry is not None else None
        severity_changed = prev_severity is not None and prev_severity != cur_severity

        current_enrich = _enrichment_signal_rows(enrichment_rows, None)
        previous_enrich = (
            _enrichment_signal_rows(enrichment_rows, scan_a_time) if a_entry is not None else []
        )
        enrichment_changed = _signal_keys(current_enrich) != _signal_keys(previous_enrich)

        current_priority = _priority_snapshot(
            calculate_priority,
            PriorityInputs,
            severity=cur_severity,
            lifecycle_status=_BUCKET_LIFECYCLE[bucket],
            enrichment_rows=current_enrich,
            priority_version=priority_version,
            technologies=current_technologies,
        )
        previous_priority: dict[str, object] | None = None
        if a_entry is not None:
            previous_priority = _priority_snapshot(
                calculate_priority,
                PriorityInputs,
                severity=a_entry[2],
                lifecycle_status=prev_lifecycle,
                enrichment_rows=previous_enrich,
                priority_version=priority_version,
                technologies=previous_technologies,
            )
        priority_changed, versions_match = _priority_changed(current_priority, previous_priority)

        remediation_status = str(remediation_row["status"]) if remediation_row else None
        prev_remediation, remediation_changed = _remediation_transition(
            remediation_row, scan_a_time, existed_at_a=a_entry is not None
        )

        cur_evidence = evidence_by_finding.get(str(cur_id), [])
        prev_evidence = evidence_by_finding.get(str(a_entry[0]), []) if a_entry is not None else []
        cur_hashes = sorted(_evidence_hash(e) for e in cur_evidence)
        prev_hashes = sorted(_evidence_hash(e) for e in prev_evidence)
        # Evidence change needs a previous finding to compare against; new
        # and regressed findings have none (their counts still show).
        evidence_changed = a_entry is not None and (
            (len(cur_evidence) != len(prev_evidence)) or (cur_hashes != prev_hashes)
        )

        cves = sorted({str(r["cve_id"]) for r in current_enrich if r.get("cve_id")})
        cvss_values = [
            float(score)
            for r in current_enrich
            if isinstance((score := r.get("cvss_score")), (int, float))
        ]
        bound_first = (bounds or {}).get("first_seen")
        bound_last = (bounds or {}).get("last_seen")
        return {
            "id": str(cur_id),
            "previous_finding_id": str(a_entry[0]) if a_entry is not None else None,
            "title": cur_title,
            "category": a_entry[3] if a_entry is not None else cur_category,
            "fingerprint": fingerprint,
            "lifecycle_status": _BUCKET_LIFECYCLE[bucket],
            "previous_lifecycle_status": prev_lifecycle if a_entry is not None else None,
            "severity": cur_severity,
            "previous_severity": prev_severity,
            "severity_changed": severity_changed,
            "priority": current_priority,
            "previous_priority": previous_priority,
            "priority_changed": priority_changed,
            "priority_versions_match": versions_match,
            "remediation_status": remediation_status,
            "previous_remediation_status": prev_remediation,
            "remediation_changed": remediation_changed,
            "evidence_count": len(cur_evidence),
            "previous_evidence_count": len(prev_evidence),
            "evidence_changed": evidence_changed,
            "evidence_hashes": cur_hashes,
            "enrichment_changed": enrichment_changed,
            "cves": cves,
            "cvss_max": max(cvss_values) if cvss_values else None,
            "enrichment": [
                {
                    "source": str(r.get("source")),
                    "external_ref": str(r.get("external_ref")),
                    "cve_id": r.get("cve_id"),
                    "cwe_id": r.get("cwe_id"),
                    "cvss_score": r.get("cvss_score"),
                }
                for r in current_enrich
            ],
            "first_seen_at": bound_first.isoformat() if bound_first else None,
            "last_seen_at": bound_last.isoformat() if bound_last else None,
            "scan_id": str(scan_b.id) if b_entry is not None else str(scan_a.id),
            "previous_scan_id": str(scan_a.id)
            if b_entry is not None
            else (
                str(scan_a.parent_scan_id)
                if getattr(scan_a, "parent_scan_id", None) is not None
                else None
            ),
        }

    async def _previous_lifecycle_in_scan(
        self,
        *,
        fingerprints: list[str],
        target_id: uuid.UUID,
        scan_id: uuid.UUID,
    ) -> dict[str, str]:
        """Latest lifecycle status observed in one scan, per fingerprint."""
        from src.infrastructure.database.models import (
            FindingLifecycleStatus,
            FindingStatusHistory,
        )

        fps = sorted(set(fingerprints))
        if not fps:
            return {}
        rows = await self._session.execute(
            select(
                FindingStatusHistory.fingerprint,
                FindingLifecycleStatus.code,
                FindingStatusHistory.effective_at,
            )
            .join(
                FindingLifecycleStatus,
                FindingStatusHistory.finding_lifecycle_status_id == FindingLifecycleStatus.id,
            )
            .where(
                FindingStatusHistory.fingerprint.in_(fps),
                FindingStatusHistory.target_id == target_id,
                FindingStatusHistory.observed_in_scan_id == scan_id,
            )
            .order_by(FindingStatusHistory.effective_at.desc())
        )
        out: dict[str, str] = {}
        for fp, code, _at in rows.all():
            out.setdefault(str(fp), str(code))
        return out

    async def _occurrence_bounds(
        self,
        *,
        fingerprints: list[str],
        target_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> dict[str, dict[str, datetime | None]]:
        """First/last seen timestamps per fingerprint (one batched query).

        Scoped to scans the requester initiated, matching the history
        visibility rule.
        """
        from sqlalchemy import func

        fps = sorted(set(fingerprints))
        if not fps:
            return {}
        rows = await self._session.execute(
            select(
                ScanFinding.fingerprint,
                func.min(ScanFinding.created_at),
                func.max(ScanFinding.created_at),
            )
            .join(Scan, ScanFinding.scan_id == Scan.id)
            .where(
                ScanFinding.fingerprint.in_(fps),
                ScanFinding.target_id == target_id,
                Scan.initiated_by_user_id == user_id,
            )
            .group_by(ScanFinding.fingerprint)
        )
        return {
            str(fp): {"first_seen": first, "last_seen": last}
            for fp, first, last in rows.all()
            if fp
        }

    async def _remediation_states(
        self,
        *,
        fingerprints: list[str],
        target_id: uuid.UUID,
    ) -> dict[str, dict[str, object]]:
        """Current remediation workflow rows keyed by fingerprint."""
        from src.infrastructure.database.models import FindingRemediation

        fps = sorted(set(fingerprints))
        if not fps:
            return {}
        rows = await self._session.execute(
            select(FindingRemediation).where(
                FindingRemediation.fingerprint.in_(fps),
                FindingRemediation.target_id == target_id,
            )
        )
        return {
            str(row.fingerprint): {
                "status": str(row.status),
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows.scalars().all()
        }

    async def _fingerprint_index(
        self, scan_id: uuid.UUID
    ) -> dict[str, tuple[uuid.UUID, str, str, str]]:
        """Map fingerprint → (finding_id, title, severity, category).

        Severity and category ride along so the compare view can surface
        changes on persistent findings (fingerprints are
        severity-independent by design).

        Returns an empty dict when the scan has no fingerprint-bearing
        findings yet (e.g. lifecycle trackable engine has not run).
        """
        from src.infrastructure.database.models import FindingCategory, SeverityLevel

        rows = await self._session.execute(
            select(
                ScanFinding.fingerprint,
                ScanFinding.id,
                ScanFinding.title,
                SeverityLevel.code,
                FindingCategory.code,
            )
            .join(SeverityLevel, ScanFinding.severity_id == SeverityLevel.id)
            .join(FindingCategory, ScanFinding.category_id == FindingCategory.id)
            .where(
                ScanFinding.scan_id == scan_id,
                ScanFinding.fingerprint.is_not(None),
            )
        )
        return {
            fp: (fid, title, severity, category)
            for fp, fid, title, severity, category in rows.all()
            if fp
        }

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
    ) -> list[DomainEvent]:
        """Run the authorized secure chain for a QUEUED scan.

        Returns the deterministic domain events emitted along the way
        (finding lifecycle rows plus at most one terminal scan event).
        Callers that need delivery (workers, schedulers) consume the
        returned list; the job itself never performs I/O beyond the
        database.
        """
        from src.domain.events.events import (
            SCAN_COMPLETED,
            SCAN_FAILED,
            scan_event,
        )
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
        events: list[DomainEvent] = []
        if scan is None:
            return events
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
            return events

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
            rejected_at = datetime.now(UTC)
            events.append(
                scan_event(
                    event_type=SCAN_FAILED,
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    status=SCAN_STATUS_REJECTED_CODE,
                    occurred_at=rejected_at,
                )
            )
            return events

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
            events.append(
                scan_event(
                    event_type=SCAN_FAILED,
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    status=SCAN_STATUS_REJECTED_CODE,
                    occurred_at=datetime.now(UTC),
                )
            )
            return events

        await executions.mark(execution_row.id, status="SUCCEEDED", completed_at=datetime.now(UTC))
        breakdown = getattr(analysis_result, "engine_results", None)
        if breakdown:
            # Composite result: the primary engine's findings persist under
            # the pre-created execution; the merged view stays on
            # ``analysis_result`` for evidence/AI stages below.
            import types

            await self._persist_findings(
                executions,
                execution_row.id,
                types.SimpleNamespace(findings=tuple(breakdown[0][2])),
                events=events,
            )
            await self._persist_extra_engine_findings(
                executions, scan, analysis_result, events=events
            )
        else:
            await self._persist_findings(
                executions, execution_row.id, analysis_result, events=events
            )

        await self._persist_technologies(scan, analysis_result)

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
        events.append(
            scan_event(
                event_type=SCAN_COMPLETED,
                scan_id=scan.id,
                target_id=scan.target_id,
                status=final_status,
                occurred_at=datetime.now(UTC),
            )
        )
        return events

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

    async def _admission_guard(self, user_id: uuid.UUID) -> None:
        """Enforce scan-creation abuse protection for one user.

        Order matters: database-backed active-scan caps first (free to
        check, nothing consumed), then the atomic Redis admission (spends
        one rate token). The owner row lock serializes concurrent
        creations so two racing requests cannot both slip past the caps.
        """
        from src.domain.scans.errors import ScanQueueFullError, ScanRateLimitedError
        from src.infrastructure.database.repositories.scan_repository import (
            ScanRepository,
        )

        repository = ScanRepository(self._session)
        await repository.lock_owner(user_id)
        active = await repository.count_active_for_user(user_id)
        if active.get(SCAN_STATUS_QUEUED_CODE, 0) >= self._max_queued_per_user:
            raise ScanQueueFullError()
        if active.get(SCAN_STATUS_RUNNING_CODE, 0) >= self._max_running_per_user:
            raise ScanQueueFullError()
        if self._scan_limiter is not None and not await self._scan_limiter.try_admit(str(user_id)):
            raise ScanRateLimitedError()

    async def _get_visible_scan(self, scan_id: uuid.UUID) -> Scan:
        from src.infrastructure.database.repositories.scan_repository import (
            ScanRepository,
        )

        scan = await ScanRepository(self._session).get_by_id(scan_id)
        if scan is None:
            raise NotFoundError()
        # Tenant isolation baseline (v1): scans are visible to their
        # initiator.
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
        events: list[DomainEvent] | None = None,
    ) -> None:
        """Persist deterministic findings + evidence + lifecycle history.

        Identity resolution (execution → scan → target) happens once, up front.
        Fingerprints are generated from the canonical persisted finding-category
        code (after ``_map_category`` mapping), not the raw engine alias.
        Evidence is typed, bounded (≤2048 chars) and immutable (DB trigger).
        Lifecycle status is derived from fingerprint+target against the
        previous scan (parent_link first, else most-recent completed).
        When ``events`` is provided, lifecycle transitions append
        deterministic domain events to it (no-op otherwise).
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
                events=events,
            )

    # ------------------------------------------------------------------ #
    # _persist_findings helpers (private; no broad exception swallow)     #
    # ------------------------------------------------------------------ #

    async def _persist_extra_engine_findings(
        self,
        executions: Any,
        scan: Scan,
        analysis_result: Any,
        events: list[DomainEvent] | None = None,
    ) -> None:
        """Persist findings of non-primary engines under their own execution.

        Composite pipelines (HTTP + TLS) attribute each engine's findings
        to a dedicated execution row so ``source_engine_code`` stays exact.
        Single-engine results expose no breakdown and take the legacy path
        untouched. Extra executions are created SUCCEEDED with the same
        completion instant as the primary one.
        """
        import types

        breakdown = getattr(analysis_result, "engine_results", None)
        if not breakdown:
            return
        # The primary engine's findings already persist under the
        # pre-created execution; only subsequent engines need new rows.
        for engine_code, engine_version, findings in list(breakdown)[1:]:
            extra = await executions.create(
                scan_id=scan.id,
                scan_engine_id=await _engine_id(self._session, str(engine_code)),
                tool_version_snapshot=str(engine_version)[:50],
                status="RUNNING",
                started_at=datetime.now(UTC),
            )
            await executions.mark(extra.id, status="SUCCEEDED", completed_at=datetime.now(UTC))
            await self._persist_findings(
                executions,
                extra.id,
                types.SimpleNamespace(findings=tuple(findings)),
                events=events,
            )

    async def _persist_technologies(self, scan: Scan, analysis_result: Any) -> None:
        """Upsert detected target technologies (observation inventory).

        Consumes the structured ``technologies`` carried by engine results
        (populated by the HTTP engine's passive detector); results without
        the field persist nothing. One row per (target, slug): latest
        observation wins, first observation preserved. Technology rows
        never create findings and never touch lifecycle or severity.
        """
        from src.infrastructure.database.repositories.target_repository import (
            TargetRepository,
        )

        technologies = getattr(analysis_result, "technologies", None) or ()
        if not technologies:
            return
        repository = TargetRepository(self._session)
        for tech in technologies:
            slug = str(getattr(tech, "slug", "") or "").strip().lower()
            family = str(getattr(tech, "family", "") or "").strip().lower()
            confidence = str(getattr(tech, "confidence", "") or "").strip().upper()
            # Defense in depth: only curated values reach the table's check
            # constraints (the detector allowlists, but persistence must not
            # trust it — a row violating the constraint would fail the scan).
            if not slug or family not in {
                "server",
                "framework",
                "language",
                "cms",
                "proxy",
            }:
                continue
            if confidence not in {"HIGH", "MEDIUM", "LOW"}:
                continue
            tech_version = getattr(tech, "version", None)
            await repository.upsert_technology(
                target_id=scan.target_id,
                slug=slug[:64],
                display=str(getattr(tech, "display", "") or slug)[:100],
                family=family[:20],
                version=str(tech_version)[:50] if tech_version is not None else None,
                confidence=confidence[:10],
                source=",".join(getattr(tech, "sources", ()) or ()),
                observed_in_scan_id=scan.id,
            )
        await repository.flush()

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
        events: list[DomainEvent] | None = None,
    ) -> None:
        """Compute + persist NEW/PERSISTENT/RESOLVED/REGRESSED rows.

        The "previous" scan is the explicit ``parent_scan_id`` when set,
        otherwise the most-recent completed scan of the same target.
        Lifecycle identity is fingerprint + target. RESOLVED events for
        fingerprints that are no longer in the current scan are derived
        from the comparison set, not just from the absence of a prior
        row. When ``events`` is provided, each written NEW / RESOLVED /
        REGRESSED row also appends its deterministic domain event.
        """
        from src.domain.events.events import lifecycle_event

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
            if events is not None:
                event = lifecycle_event(
                    lifecycle_status=derived,
                    target_id=target_id,
                    fingerprint=fp,
                    scan_id=scan_id,
                    occurred_at=datetime.now(UTC),
                )
                if event is not None:
                    events.append(event)
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
    # TLS posture engine (tls_posture.py): certificate and protocol posture
    # are TLS-configuration problems; cipher posture has its own code.
    "tls.certificate": "OUTDATED_TLS",
    "tls.protocol": "OUTDATED_TLS",
    "tls.cipher": "WEAK_CIPHER",
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


def _iso(value: object) -> str | None:
    """ISO-8601 for datetimes, None otherwise (history timestamps)."""
    from datetime import datetime

    if isinstance(value, datetime):
        return value.isoformat()
    return None


def _scan_moment(scan: Scan) -> str | None:
    """Best observation timestamp for a scan row (completion, else creation)."""
    completed = getattr(scan, "completed_at", None)
    if completed is not None:
        moment = _iso(completed)
        if moment is not None:
            return moment
    return _iso(getattr(scan, "created_at", None))


def _to_compare_dtos(
    fps: list[str],
    source_map: dict[str, tuple[uuid.UUID, str, str, str]],
    secondary_map: dict[str, tuple[uuid.UUID, str, str, str]] | None = None,
) -> list[dict[str, object]]:
    """Render fingerprint list → DTO list for the compare endpoint.

    ``severity`` always reflects the primary (current) side. When a
    secondary map is given (persistent findings: current vs previous),
    ``previous_severity`` is populated only when it differs, so the UI can
    badge severity changes without extra requests.
    """
    dtos: list[dict[str, object]] = []
    for fp in sorted(fps):
        fid, title, severity, _category = source_map[fp]
        previous_severity: str | None = None
        if secondary_map is not None:
            previous = secondary_map.get(fp)
            if previous is not None and previous[2] != severity:
                previous_severity = previous[2]
        dtos.append(
            {
                "id": str(fid),
                "fingerprint": fp,
                "title": title,
                "severity": severity,
                "previous_severity": previous_severity,
            }
        )
    return dtos


# ---------------------------------------------------------------------- #
# Comparison-intelligence helpers (deterministic, side-effect free)        #
# ---------------------------------------------------------------------- #

_BUCKET_ORDER = {"new": 0, "persistent": 1, "resolved": 2, "regressed": 3}

_BUCKET_LIFECYCLE = {
    "new": "NEW",
    "persistent": "PERSISTENT",
    "resolved": "RESOLVED",
    "regressed": "REGRESSED",
}


def _enrichment_signal_rows(
    rows: list[dict[str, object]], as_of: datetime | None
) -> list[dict[str, object]]:
    """Enrichment rows considered present at a point in time.

    ``as_of=None`` means "now" (every row counts). Otherwise only rows
    created at or before ``as_of`` count — a row created later cannot
    describe that earlier moment. Rows without a creation timestamp are
    treated as present-now-only (never backdated).
    """
    if as_of is None:
        return list(rows)
    present: list[dict[str, object]] = []
    for row in rows:
        created = row.get("created_at")
        created_at: datetime | None = None
        if isinstance(created, datetime):
            created_at = created
        elif isinstance(created, str):
            try:
                created_at = datetime.fromisoformat(created)
            except ValueError:
                created_at = None
        if created_at is not None and _as_aware(created_at) <= _as_aware(as_of):
            present.append(row)
    return present


def _signal_keys(rows: list[dict[str, object]]) -> set[tuple[object, ...]]:
    """Identity-relevant enrichment content (never finding identity)."""
    return {
        (
            row.get("source"),
            row.get("external_ref"),
            row.get("cve_id"),
            row.get("cwe_id"),
            row.get("cvss_score"),
        )
        for row in rows
    }


def _as_aware(moment: datetime) -> datetime:
    """Compare tz-naive timestamps as UTC (production rows are aware)."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment


def _technology_signal_slugs(
    rows: list[dict[str, object]], as_of: datetime | None
) -> tuple[str, ...]:
    """Technology slugs considered present at a point in time.

    ``as_of=None`` means "now" (every row counts). Otherwise only rows
    first observed at or before ``as_of`` count — a technology first seen
    later cannot describe that earlier moment. Same honesty rule as
    enrichment presence; rows without a timestamp are present-now-only.
    """
    if as_of is None:
        return tuple(sorted({str(r["slug"]) for r in rows if r.get("slug")}))
    present: set[str] = set()
    for row in rows:
        if not row.get("slug"):
            continue
        first = row.get("first_observed_at")
        first_at: datetime | None = None
        if isinstance(first, datetime):
            first_at = first
        elif isinstance(first, str):
            try:
                first_at = datetime.fromisoformat(first)
            except ValueError:
                first_at = None
        if first_at is not None and _as_aware(first_at) <= _as_aware(as_of):
            present.add(str(row["slug"]))
    return tuple(sorted(present))


def _priority_snapshot(
    calculate_priority: Any,
    PriorityInputs: Any,
    *,
    severity: str,
    lifecycle_status: str | None,
    enrichment_rows: list[dict[str, object]],
    priority_version: str,
    technologies: tuple[str, ...] = (),
) -> dict[str, object]:
    """Priority inputs snapshot (callables injected for testability)."""
    from src.domain.scans.priority import match_technologies

    has_cve = any(row.get("cve_id") for row in enrichment_rows)
    scores = [
        float(score)
        for row in enrichment_rows
        if isinstance((score := row.get("cvss_score")), (int, float))
    ]
    matched = match_technologies(technologies, enrichment_rows)
    result = calculate_priority(
        PriorityInputs(
            severity=severity,
            lifecycle_status=lifecycle_status,
            has_cve=has_cve,
            cvss_score=max(scores) if scores else None,
            technologies=technologies,
            matched_technologies=matched,
        )
    )
    return {
        "score": result.score,
        "level": result.level,
        "version": priority_version,
        "factors": list(result.factors),
    }


def _priority_changed(
    current: dict[str, object], previous: dict[str, object] | None
) -> tuple[bool, bool]:
    """(changed, versions_match) for two priority snapshots.

    Versions are compared, never silently mixed: a future engine bump
    surfaces as ``versions_match=False`` while both versions stay
    visible on the record.
    """
    if previous is None:
        return False, True
    versions_match = current.get("version") == previous.get("version")
    changed = (current.get("score"), current.get("level")) != (
        previous.get("score"),
        previous.get("level"),
    )
    return changed, versions_match


def _remediation_transition(
    row: dict[str, object] | None,
    scan_a_time: datetime,
    *,
    existed_at_a: bool,
) -> tuple[str | None, bool]:
    """(previous_status, changed) inferred from remediation row timestamps.

    The workflow table keeps current state only, so the scan-A state is
    derived honestly: a row created after scan A did not exist then; a row
    modified after scan A changed at an unknown point (previous value
    stays None rather than invented); otherwise state is unchanged.
    """
    if row is None or not existed_at_a:
        return None, False
    created = row.get("created_at")
    updated = row.get("updated_at")
    created_at = created if isinstance(created, datetime) else None
    updated_at = updated if isinstance(updated, datetime) else None
    if created_at is not None and _as_aware(created_at) > _as_aware(scan_a_time):
        return None, True
    if updated_at is not None and _as_aware(updated_at) > _as_aware(scan_a_time):
        return None, True
    return str(row.get("status")), False


def _evidence_hash(evidence: dict[str, str]) -> str:
    """Stable content identity for one evidence row (type + content)."""
    import hashlib

    return hashlib.sha256(
        f"{evidence.get('type', '')}\0{evidence.get('content', '')}".encode()
    ).hexdigest()


def _compare_summary(records: list[dict[str, object]]) -> dict[str, int]:
    """Aggregate counts computed from actual comparison records."""
    summary = {
        "new_count": 0,
        "persistent_count": 0,
        "resolved_count": 0,
        "regressed_count": 0,
        "severity_changed_count": 0,
        "priority_changed_count": 0,
        "remediation_changed_count": 0,
        "evidence_changed_count": 0,
        "enrichment_changed_count": 0,
    }
    bucket_key = {
        "NEW": "new_count",
        "PERSISTENT": "persistent_count",
        "RESOLVED": "resolved_count",
        "REGRESSED": "regressed_count",
    }
    for record in records:
        key = bucket_key.get(str(record.get("lifecycle_status")))
        if key is not None:
            summary[key] += 1
        for flag, count_key in (
            ("severity_changed", "severity_changed_count"),
            ("priority_changed", "priority_changed_count"),
            ("remediation_changed", "remediation_changed_count"),
            ("evidence_changed", "evidence_changed_count"),
            ("enrichment_changed", "enrichment_changed_count"),
        ):
            if record.get(flag) is True:
                summary[count_key] += 1
    return summary
