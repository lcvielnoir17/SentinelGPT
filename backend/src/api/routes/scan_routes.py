"""Scan lifecycle endpoints (SRS Chapter 5, Section 6; ADR-0009).

All routes require authentication and are tenant-isolated server-side.
Scan creation enforces the authorization-attestation gate (403
ATTESTATION_NOT_CONFIRMED); execution runs as a background job through the
secure chain (resolver → policy → binding → sandbox → transport → engine →
AI), never from API-layer networking.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any, cast

from fastapi import APIRouter, BackgroundTasks, Query, Response, status
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from src.api.dependencies import (  # noqa: TC001 - FastAPI runtime
    CurrentUser,
    SessionDep,
)
from src.config.settings import get_settings
from src.domain.errors import NotFoundError
from src.domain.scans.errors import InvalidRemediationError
from src.domain.scans.scan_service import ScanDetails, ScanService

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.events.events import DomainEvent
    from src.domain.scanning.analysis.comparison_models import ComparisonAssessment

router = APIRouter(prefix="/scans", tags=["Scans"])


# --------------------------------------------------------------------- #
# DTOs                                                                  #
# --------------------------------------------------------------------- #


class CreateScanRequest(BaseModel):
    target_id: uuid.UUID = Field(validation_alias="targetId")
    scan_profile: str = Field(
        default="standard",
        validation_alias="scanProfile",
        pattern="^(quick-check|standard|full-assessment)$",
    )


class ScanResponse(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID = Field(serialization_alias="targetId")
    scan_profile: str = Field(serialization_alias="scanProfile")
    status: str
    initiated_by: uuid.UUID = Field(serialization_alias="initiatedBy")
    authorization_attestation_id: uuid.UUID = Field(
        serialization_alias="authorizationAttestationId"
    )
    queued_at: datetime | None = Field(serialization_alias="queuedAt")
    started_at: datetime | None = Field(serialization_alias="startedAt")
    completed_at: datetime | None = Field(serialization_alias="completedAt")
    created_at: datetime = Field(serialization_alias="createdAt")


class FindingEvidenceItem(BaseModel):
    """One typed evidence row bound to a finding (id/type/content only —
    no secrets, tokens, or credentials live on evidence rows)."""

    id: str
    type: str
    content: str


class FindingResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    evidence: str
    location: str
    recommendation: str
    created_at: str = Field(
        validation_alias=AliasChoices("createdAt", "created_at"),
        serialization_alias="createdAt",
    )
    evidence_items: list[FindingEvidenceItem] = Field(
        default_factory=list, serialization_alias="evidenceItems"
    )


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    available: bool
    provider: str
    model: str
    prompt_schema_version: str = Field(
        validation_alias=AliasChoices("promptSchemaVersion", "prompt_schema_version"),
        serialization_alias="promptSchemaVersion",
    )
    output_schema_version: str = Field(
        validation_alias=AliasChoices("outputSchemaVersion", "output_schema_version"),
        serialization_alias="outputSchemaVersion",
    )
    failure_kind: str | None = Field(
        validation_alias=AliasChoices("failureKind", "failure_kind"),
        serialization_alias="failureKind",
    )
    unsupported_claim_count: int = Field(
        validation_alias=AliasChoices("unsupportedClaimCount", "unsupported_claim_count"),
        serialization_alias="unsupportedClaimCount",
    )
    payload: dict[str, Any]
    created_at: str = Field(
        validation_alias=AliasChoices("createdAt", "created_at"),
        serialization_alias="createdAt",
    )


def _to_response(details: ScanDetails) -> ScanResponse:
    return ScanResponse(
        id=details.id,
        target_id=details.target_id,
        scan_profile=details.scan_profile_code,
        status=details.status_code,
        initiated_by=details.initiated_by_user_id,
        authorization_attestation_id=details.authorization_attestation_id,
        queued_at=details.queued_at,
        started_at=details.started_at,
        completed_at=details.completed_at,
        created_at=details.created_at,
    )


def _service(session: AsyncSession, current_user: Any) -> ScanService:
    return ScanService(
        session,
        current_user,
        scan_limiter=_scan_rate_limiter(),
        max_queued_per_user=get_settings().scan_max_queued_per_user,
        max_running_per_user=get_settings().scan_max_running_per_user,
    )


def _scan_rate_limiter() -> Any:
    """Per-user atomic scan-creation admission (Redis; fail-open when down)."""
    from src.domain.scans.rate_limit import RedisAtomicRateLimiter
    from src.infrastructure.cache.redis_client import get_redis_client

    settings = get_settings()
    return RedisAtomicRateLimiter(
        get_redis_client(),
        key_prefix="sgpt:scan:create",
        limit=settings.scan_rate_limit_per_minute,
        window_seconds=60,
    )


def _maybe_gemini() -> Any:
    from src.infrastructure.ai.factory import maybe_evidence_analyzer

    return maybe_evidence_analyzer()


# --------------------------------------------------------------------- #
# Endpoints                                                             #
# --------------------------------------------------------------------- #


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Authorize + queue a scan against an attested target",
)
async def create_scan(
    payload: CreateScanRequest,
    response_bg: BackgroundTasks,
    session: SessionDep,
    current_user: CurrentUser,
) -> ScanResponse:
    service = _service(session, current_user)
    details = await service.create_scan(
        target_id=payload.target_id,
        scan_profile_code=payload.scan_profile,
    )
    # Execution decision (ADR-0009): background jobs are scheduled ONLY when
    # the operator-enabled switch is on. Otherwise the scan remains QUEUED —
    # visible, cancellable, and never executed.
    if get_settings().scanner_execution_enabled:
        from src.workers.scan_tasks import enqueue_scan

        task_id = enqueue_scan(details.id)
        if not task_id:
            # Worker tier unavailable; fall back to in-process scheduling so
            # a single-host dev deployment still runs scans end-to-end.
            response_bg.add_task(
                service.build_background_job(details.id, ai_analyzer=_maybe_gemini())
            )
    return _to_response(details)


@router.get("", response_model=list[ScanResponse], summary="List scans (initiator scope)")
async def list_scans(
    session: SessionDep,
    current_user: CurrentUser,
    target_id: Annotated[uuid.UUID | None, Query(alias="targetId")] = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ScanResponse]:
    rows = await _service(session, current_user).list_scans(
        target_id=target_id, status_code=status_filter, limit=limit
    )
    return [_to_response(row) for row in rows]


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get scan detail")
async def get_scan(
    scan_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> ScanResponse:
    details = await _service(session, current_user).get_scan(scan_id)
    return _to_response(details)


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanResponse,
    summary="Cancel a scan that has not started running",
)
async def cancel_scan(
    scan_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> ScanResponse:
    details = await _service(session, current_user).cancel_scan(scan_id)
    return _to_response(details)


@router.get(
    "/{scan_id}/findings",
    response_model=list[FindingResponse],
    summary="Deterministic findings for a completed scan",
)
async def list_findings(
    scan_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    remediation_status: Annotated[str | None, Query(alias="remediationStatus")] = None,
    assignee: Annotated[str | None, Query()] = None,
    overdue: Annotated[bool | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
) -> list[FindingResponse]:
    """Deterministic findings for a completed scan, optionally filtered.

    Filters apply after the tenant-isolation gate, so they can never
    widen visibility: ``remediationStatus`` (TODO/IN_PROGRESS/DONE/
    DEFERRED), ``assignee`` (assignee user id, or ``unassigned``),
    ``overdue`` (derived due-date state), and ``severity`` (canonical
    code). Unknown statuses and malformed assignee ids are 400.
    """
    from src.domain.scans.remediation import STATUSES, is_overdue

    service = _service(session, current_user)
    scan = await service.get_scan(scan_id)  # tenant-isolation gate
    wanted_status: str | None = None
    if remediation_status is not None:
        wanted_status = remediation_status.strip().upper()
        if wanted_status not in STATUSES:
            raise InvalidRemediationError(f"remediationStatus must be one of {sorted(STATUSES)}")
    wanted_assignee: str | None = None
    assignee_unassigned_only = False
    if assignee is not None:
        lowered = assignee.strip().lower()
        if lowered == "unassigned":
            assignee_unassigned_only = True
        else:
            try:
                wanted_assignee = str(uuid.UUID(assignee.strip()))
            except ValueError as exc:
                raise InvalidRemediationError("assignee must be a UUID or 'unassigned'.") from exc
    wanted_severity: str | None = None
    if severity is not None:
        wanted_severity = severity.strip().upper() or None
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    executions = ScanEngineExecutionRepository(session)
    rows = await executions.list_finding_dtos(scan_id)
    # One batched evidence query + one batched remediation query for the
    # whole list (no per-finding N+1).
    evidence_by_finding = await executions.list_evidence_for_findings([str(r["id"]) for r in rows])
    remediation_by_fingerprint = await executions.list_remediations_for_target(
        target_id=scan.target_id
    )
    responses: list[FindingResponse] = []
    for row in rows:
        payload = dict(row)
        payload["evidence_items"] = evidence_by_finding.get(str(row["id"]), [])
        remediation = None
        fingerprint = row.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            remediation = remediation_by_fingerprint.get(fingerprint)
        if wanted_status is not None and (
            remediation is None or str(remediation.get("status")) != wanted_status
        ):
            continue
        if wanted_assignee is not None and (
            remediation is None or str(remediation.get("assignee_user_id") or "") != wanted_assignee
        ):
            continue
        if assignee_unassigned_only and (
            remediation is not None and remediation.get("assignee_user_id")
        ):
            continue
        if overdue is not None:
            is_due_overdue = False
            if remediation is not None:
                due_raw = remediation.get("due_at")
                try:
                    due_at = (
                        datetime.fromisoformat(str(due_raw))
                        if isinstance(due_raw, str) and due_raw
                        else None
                    )
                except ValueError:
                    due_at = None
                is_due_overdue = is_overdue(
                    due_at=due_at, status=str(remediation.get("status", "TODO"))
                )
            if is_due_overdue != overdue:
                continue
        if wanted_severity is not None and str(row.get("severity", "")).upper() != wanted_severity:
            continue
        payload.pop("fingerprint", None)
        responses.append(FindingResponse(**payload))  # type: ignore[arg-type]
    return responses


class FindingOccurrence(BaseModel):
    finding_id: str = Field(serialization_alias="findingId")
    scan_id: str = Field(serialization_alias="scanId")
    severity: str
    created_at: str | None = Field(default=None, serialization_alias="createdAt")


class FindingLifecycleEvent(BaseModel):
    status: str
    effective_at: str | None = Field(default=None, serialization_alias="effectiveAt")
    observed_in_scan_id: str = Field(serialization_alias="observedInScanId")


class FindingSeverityChange(BaseModel):
    from_severity: str = Field(serialization_alias="from")
    to_severity: str = Field(serialization_alias="to")
    scan_id: str = Field(serialization_alias="scanId")
    at: str | None = None


class FindingHistoryResponse(BaseModel):
    """Cross-scan history for one finding (fingerprint identity).

    Every entry derives from persisted finding rows and lifecycle
    history — nothing is invented. Occurrences cover only scans the
    caller initiated, so another user's scans never leak through here.
    """

    finding_id: str = Field(serialization_alias="findingId")
    scan_id: str = Field(serialization_alias="scanId")
    fingerprint: str | None = None
    title: str
    current_severity: str = Field(serialization_alias="currentSeverity")
    previous_severity: str | None = Field(default=None, serialization_alias="previousSeverity")
    lifecycle_status: str | None = Field(default=None, serialization_alias="lifecycleStatus")
    first_seen_at: str | None = Field(default=None, serialization_alias="firstSeenAt")
    last_seen_at: str | None = Field(default=None, serialization_alias="lastSeenAt")
    occurrences: list[FindingOccurrence] = Field(default_factory=list)
    lifecycle_events: list[FindingLifecycleEvent] = Field(
        default_factory=list, serialization_alias="lifecycleEvents"
    )
    severity_changes: list[FindingSeverityChange] = Field(
        default_factory=list, serialization_alias="severityChanges"
    )


@router.get(
    "/{scan_id}/findings/{finding_id}/history",
    response_model=FindingHistoryResponse,
    summary="Cross-scan history for one finding",
)
async def get_finding_history(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingHistoryResponse:
    """History for one finding in a visible scan.

    The scan gate runs first (cross-tenant scans are 404); a finding
    that does not belong to the scan is also 404. The finding list
    already exposes which findings a visible scan holds, so the
    association check leaks nothing further.
    """
    history = await _service(session, current_user).get_finding_history(scan_id, finding_id)
    if history is None:
        raise NotFoundError()
    occurrences = history["occurrences"]
    lifecycle_events = history["lifecycle_events"]
    severity_changes = history["severity_changes"]
    assert isinstance(occurrences, list)
    assert isinstance(lifecycle_events, list)
    assert isinstance(severity_changes, list)
    return FindingHistoryResponse(
        finding_id=str(history["finding_id"]),
        scan_id=str(history["scan_id"]),
        fingerprint=(str(history["fingerprint"]) if history["fingerprint"] is not None else None),
        title=str(history["title"]),
        current_severity=str(history["current_severity"]),
        previous_severity=(
            str(history["previous_severity"]) if history["previous_severity"] is not None else None
        ),
        lifecycle_status=(
            str(history["lifecycle_status"]) if history["lifecycle_status"] is not None else None
        ),
        first_seen_at=(
            str(history["first_seen_at"]) if history["first_seen_at"] is not None else None
        ),
        last_seen_at=(
            str(history["last_seen_at"]) if history["last_seen_at"] is not None else None
        ),
        occurrences=[
            FindingOccurrence(
                finding_id=str(o["finding_id"]),
                scan_id=str(o["scan_id"]),
                severity=str(o["severity"]),
                created_at=(str(o["created_at"]) if o["created_at"] is not None else None),
            )
            for o in occurrences
        ],
        lifecycle_events=[
            FindingLifecycleEvent(
                status=str(e["status"]),
                effective_at=(str(e["effective_at"]) if e["effective_at"] is not None else None),
                observed_in_scan_id=str(e["observed_in_scan_id"]),
            )
            for e in lifecycle_events
        ],
        severity_changes=[
            FindingSeverityChange(
                from_severity=str(c["from"]),
                to_severity=str(c["to"]),
                scan_id=str(c["scan_id"]),
                at=(str(c["at"]) if c["at"] is not None else None),
            )
            for c in severity_changes
        ],
    )


class FindingEnrichmentResponse(BaseModel):
    """One advisory enrichment row (never canonical finding data)."""

    id: str
    fingerprint: str
    source: str
    external_ref: str = Field(serialization_alias="externalRef")
    cve_id: str | None = Field(default=None, serialization_alias="cveId")
    cwe_id: str | None = Field(default=None, serialization_alias="cweId")
    cvss_score: float | None = Field(default=None, serialization_alias="cvssScore")
    cvss_vector: str | None = Field(default=None, serialization_alias="cvssVector")
    references: list[str] = Field(default_factory=list)
    affected_technology: str | None = Field(default=None, serialization_alias="affectedTechnology")
    remediation: str | None = None
    created_at: str | None = Field(default=None, serialization_alias="createdAt")
    updated_at: str | None = Field(default=None, serialization_alias="updatedAt")


def _to_enrichment_response(item: dict[str, object]) -> FindingEnrichmentResponse:
    raw_score = item.get("cvss_score")
    raw_refs = item.get("references")
    return FindingEnrichmentResponse(
        id=str(item["id"]),
        fingerprint=str(item["fingerprint"]),
        source=str(item["source"]),
        external_ref=str(item["external_ref"]),
        cve_id=(str(item["cve_id"]) if item.get("cve_id") is not None else None),
        cwe_id=(str(item["cwe_id"]) if item.get("cwe_id") is not None else None),
        cvss_score=(float(raw_score) if isinstance(raw_score, (int, float)) else None),
        cvss_vector=(str(item["cvss_vector"]) if item.get("cvss_vector") is not None else None),
        references=[str(r) for r in raw_refs] if isinstance(raw_refs, list) else [],
        affected_technology=(
            str(item["affected_technology"])
            if item.get("affected_technology") is not None
            else None
        ),
        remediation=(str(item["remediation"]) if item.get("remediation") is not None else None),
        created_at=(str(item["created_at"]) if item.get("created_at") is not None else None),
        updated_at=(str(item["updated_at"]) if item.get("updated_at") is not None else None),
    )


@router.get(
    "/{scan_id}/findings/{finding_id}/enrichment",
    response_model=list[FindingEnrichmentResponse],
    summary="Advisory enrichment for one finding",
)
async def get_finding_enrichment(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> list[FindingEnrichmentResponse]:
    """Enrichment rows for a finding's fingerprint ([] when none exist).

    Same gates as history: invisible scans and foreign findings are 404.
    """
    rows = await _service(session, current_user).get_finding_enrichment(scan_id, finding_id)
    if rows is None:
        raise NotFoundError()
    return [_to_enrichment_response(r) for r in rows]


@router.post(
    "/{scan_id}/findings/{finding_id}/enrichment",
    response_model=FindingEnrichmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Attach advisory enrichment to one finding",
)
async def attach_finding_enrichment(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: dict[str, Any],
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingEnrichmentResponse:
    """Validate and attach one enrichment row (deduplicated, 201).

    Malformed identifiers are 400; invisible scans and foreign findings
    are 404. Canonical finding fields are never modified by this path.
    """
    row = await _service(session, current_user).attach_finding_enrichment(
        scan_id, finding_id, payload
    )
    if row is None:
        raise NotFoundError()
    return _to_enrichment_response(row)


class FindingRemediationResponse(BaseModel):
    """Operator remediation workflow state (never canonical finding data)."""

    id: str
    fingerprint: str
    status: str
    notes: str | None = None
    updated_by_user_id: str | None = Field(default=None, serialization_alias="updatedByUserId")
    assignee_user_id: str | None = Field(default=None, serialization_alias="assigneeUserId")
    assignee_email: str | None = Field(default=None, serialization_alias="assigneeEmail")
    assigned_at: str | None = Field(default=None, serialization_alias="assignedAt")
    assigned_by_user_id: str | None = Field(default=None, serialization_alias="assignedByUserId")
    due_at: str | None = Field(default=None, serialization_alias="dueAt")
    overdue: bool = False
    created_at: str | None = Field(default=None, serialization_alias="createdAt")
    updated_at: str | None = Field(default=None, serialization_alias="updatedAt")


def _to_remediation_response(item: dict[str, object]) -> FindingRemediationResponse:
    def _opt(key: str) -> str | None:
        value = item.get(key)
        return str(value) if value is not None else None

    return FindingRemediationResponse(
        id=str(item["id"]),
        fingerprint=str(item["fingerprint"]),
        status=str(item["status"]),
        notes=(str(item["notes"]) if item.get("notes") is not None else None),
        updated_by_user_id=_opt("updated_by_user_id"),
        assignee_user_id=_opt("assignee_user_id"),
        assignee_email=_opt("assignee_email"),
        assigned_at=_opt("assigned_at"),
        assigned_by_user_id=_opt("assigned_by_user_id"),
        due_at=_opt("due_at"),
        overdue=bool(item.get("overdue")),
        created_at=_opt("created_at"),
        updated_at=_opt("updated_at"),
    )


class RemediationCommentResponse(BaseModel):
    """One append-only collaboration comment (never canonical finding data)."""

    id: str
    fingerprint: str
    author_user_id: str = Field(serialization_alias="authorUserId")
    author_email: str | None = Field(default=None, serialization_alias="authorEmail")
    body: str
    created_at: str | None = Field(default=None, serialization_alias="createdAt")


def _to_comment_response(item: dict[str, object]) -> RemediationCommentResponse:
    author = item.get("author_user_id")
    email = item.get("author_email")
    created = item.get("created_at")
    return RemediationCommentResponse(
        id=str(item["id"]),
        fingerprint=str(item["fingerprint"]),
        author_user_id=str(author) if author is not None else "",
        author_email=str(email) if email is not None else None,
        body=str(item["body"]),
        created_at=str(created) if created is not None else None,
    )


@router.get(
    "/{scan_id}/findings/{finding_id}/remediation",
    response_model=FindingRemediationResponse,
    summary="Remediation workflow state for one finding",
)
async def get_finding_remediation(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingRemediationResponse:
    """Workflow state for a finding's fingerprint (404 when never recorded).

    Same gates as enrichment: invisible scans and foreign findings are 404.
    """
    row = await _service(session, current_user).get_finding_remediation(scan_id, finding_id)
    if row is None:
        raise NotFoundError()
    return _to_remediation_response(row)


@router.put(
    "/{scan_id}/findings/{finding_id}/remediation",
    response_model=FindingRemediationResponse,
    summary="Record remediation workflow state for one finding",
)
async def set_finding_remediation(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: dict[str, Any],
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingRemediationResponse:
    """Upsert workflow state (TODO/IN_PROGRESS/DONE/DEFERRED + notes).

    M8 collaboration: the payload may also carry ``assigneeUserId``
    (UUID string, or null to unassign) and ``dueAt`` (timezone-aware
    ISO-8601, or null to clear); absent keys leave stored values alone.
    Malformed payloads are 400; unknown assignees are 404, inactive
    accounts are 400; invisible scans and foreign findings are 404.
    DONE records operator intent only — canonical lifecycle resolution
    still comes exclusively from scan evidence.
    """
    row = await _service(session, current_user).set_finding_remediation(
        scan_id, finding_id, payload
    )
    if row is None:
        raise NotFoundError()
    return _to_remediation_response(row)


@router.put(
    "/{scan_id}/findings/{finding_id}/remediation/notify",
    response_model=FindingRemediationResponse,
    summary="Record remediation state and notify subscribers",
)
async def set_finding_remediation_and_notify(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: dict[str, Any],
    session: SessionDep,
    current_user: CurrentUser,
) -> FindingRemediationResponse:
    """Upsert workflow state, then fan out a REMEDIATION_CHANGED event.

    Unlike the plain upsert above, this variant collects the transition
    event and ledgers webhook deliveries in the same request transaction,
    so subscribers observe exactly the state change just persisted.
    """
    from src.domain.webhooks.dispatch import fanout_events

    events: list[DomainEvent] = []
    row = await _service(session, current_user).set_finding_remediation(
        scan_id, finding_id, payload, events=events
    )
    if row is None:
        raise NotFoundError()
    if events:
        from src.workers.webhook_tasks import deliver_webhook_task

        delivery_ids = await fanout_events(session, current_user.id, events)
        await session.commit()
        for delivery_id in delivery_ids:
            deliver_webhook_task.apply_async(args=[str(delivery_id)])
    return _to_remediation_response(row)


@router.post(
    "/{scan_id}/findings/{finding_id}/remediation/comments",
    response_model=RemediationCommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Append a collaboration comment",
)
async def add_remediation_comment(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: dict[str, Any],
    session: SessionDep,
    current_user: CurrentUser,
) -> RemediationCommentResponse:
    """Append one bounded plain-text comment (201).

    Same gates as remediation: invisible scans and foreign findings are
    404. The author is always the caller — authorship cannot be spoofed.
    Comments never mutate canonical finding data and are excluded from
    reports by design.
    """
    row = await _service(session, current_user).add_remediation_comment(
        scan_id, finding_id, payload
    )
    if row is None:
        raise NotFoundError()
    return _to_comment_response(row)


@router.get(
    "/{scan_id}/findings/{finding_id}/remediation/comments",
    response_model=list[RemediationCommentResponse],
    summary="List collaboration comments",
)
async def list_remediation_comments(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[RemediationCommentResponse]:
    """Comments for one finding's remediation identity, oldest first.

    Same gates as remediation (foreign ids are 404). Bounded (default
    100 per call).
    """
    rows = await _service(session, current_user).list_remediation_comments(
        scan_id, finding_id, limit=limit
    )
    if rows is None:
        raise NotFoundError()
    return [_to_comment_response(item) for item in rows]


class VerifyFixResponse(BaseModel):
    """Verify-fix request outcome (rescan link, state starts pending)."""

    finding_id: str = Field(serialization_alias="findingId")
    fingerprint: str
    rescan_id: str = Field(serialization_alias="rescanId")
    rescan_status: str = Field(serialization_alias="rescanStatus")
    state: str


class VerifyFixStatusResponse(BaseModel):
    """Live verification state (derived, never stored)."""

    state: str
    rescan_id: str | None = Field(default=None, serialization_alias="rescanId")
    rescan_status: str | None = Field(default=None, serialization_alias="rescanStatus")
    completed_at: str | None = Field(default=None, serialization_alias="completedAt")


@router.post(
    "/{scan_id}/findings/{finding_id}/verify-fix",
    response_model=VerifyFixResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request fix verification via rescan",
)
async def request_verify_fix(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    response_bg: BackgroundTasks,
    session: SessionDep,
    current_user: CurrentUser,
) -> VerifyFixResponse:
    """Create a verification rescan and link it to the remediation row.

    Requires existing remediation workflow state (mark first, then
    verify). Attestation, quota, and rate gates enforced by rescan
    creation propagate unchanged; on success the rescan is enqueued
    exactly like a manual rescan.
    """
    service = _service(session, current_user)
    outcome = await service.request_verify_fix(scan_id, finding_id)
    if outcome is None:
        raise NotFoundError()
    if get_settings().scanner_execution_enabled:
        from src.workers.scan_tasks import enqueue_scan

        task_id = enqueue_scan(uuid.UUID(str(outcome["rescan_id"])))
        if not task_id:
            response_bg.add_task(
                service.build_background_job(
                    uuid.UUID(str(outcome["rescan_id"])), ai_analyzer=_maybe_gemini()
                )
            )
    return VerifyFixResponse(
        finding_id=str(outcome["finding_id"]),
        fingerprint=str(outcome["fingerprint"]),
        rescan_id=str(outcome["rescan_id"]),
        rescan_status=str(outcome["rescan_status"]),
        state=str(outcome["state"]),
    )


@router.get(
    "/{scan_id}/findings/{finding_id}/verify-fix",
    response_model=VerifyFixStatusResponse,
    summary="Read live fix-verification state",
)
async def get_verify_fix_status(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> VerifyFixStatusResponse:
    """Derive verification state (pending/stale/verified_fixed/still_present).

    Pure read: the state recomputes from the verification rescan every
    call, so it cannot go stale. Resolution itself stays scan-derived.
    """
    outcome = await _service(session, current_user).get_verify_fix_status(scan_id, finding_id)
    if outcome is None:
        raise NotFoundError()
    return VerifyFixStatusResponse(
        state=str(outcome["state"]),
        rescan_id=str(outcome["rescan_id"]) if outcome.get("rescan_id") else None,
        rescan_status=str(outcome["rescan_status"]) if outcome.get("rescan_status") else None,
        completed_at=str(outcome["completed_at"]) if outcome.get("completed_at") else None,
    )


class ReportV2Priority(BaseModel):
    """Deterministic priority snapshot (never AI-derived)."""

    model_config = ConfigDict(populate_by_name=True)

    score: int
    level: str
    version: str
    factors: list[str] = Field(default_factory=list)


class ReportV2Remediation(BaseModel):
    """Operator workflow state for one fingerprint (None when never marked)."""

    model_config = ConfigDict(populate_by_name=True)

    status: str
    notes: str | None = None
    updated_at: str | None = Field(default=None, alias="updatedAt")


class ReportV2Verification(BaseModel):
    """Live M4 verification state (derived, never stored)."""

    model_config = ConfigDict(populate_by_name=True)

    state: str
    rescan_id: str | None = Field(default=None, alias="rescanId")
    rescan_status: str | None = Field(default=None, alias="rescanStatus")


class ReportV2Finding(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    fingerprint: str | None = None
    severity: str
    category: str
    title: str
    description: str | None = None
    evidence: str | None = None
    location: str | None = None
    recommendation: str | None = None
    lifecycle_status: str | None = Field(default=None, alias="lifecycleStatus")
    priority: ReportV2Priority | None = None
    remediation: ReportV2Remediation | None = None
    verification: ReportV2Verification | None = None


class ReportV2Scan(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    target_hostname: str = Field(default="", alias="targetHostname")
    target_normalized_url: str = Field(
        default="",
        alias="targetNormalizedUrl",
    )
    scan_profile: str = Field(default="", alias="scanProfile")
    status: str
    queued_at: str | None = Field(default=None, alias="queuedAt")
    started_at: str | None = Field(default=None, alias="startedAt")
    completed_at: str | None = Field(default=None, alias="completedAt")


class ReportV2Engine(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    engine_code: str = Field(alias="engineCode")
    tool_version_snapshot: str = Field(alias="toolVersionSnapshot")
    status: str
    started_at: str | None = Field(default=None, alias="startedAt")
    completed_at: str | None = Field(default=None, alias="completedAt")
    error_message: str | None = Field(default=None, alias="errorMessage")


class ReportV2Delta(BaseModel):
    """Delta vs the previous completed scan (None on a target's first scan)."""

    model_config = ConfigDict(populate_by_name=True)

    previous_scan_id: str = Field(alias="previousScanId")
    counts: dict[str, int]
    fingerprints: dict[str, list[str]]


class ReportV2Technology(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    slug: str | None = None
    display: str | None = None
    family: str | None = None
    version: str | None = None
    confidence: str | None = None
    observed_in_scan_id: str | None = Field(
        default=None,
        alias="observedInScanId",
    )
    first_observed_at: str | None = Field(
        default=None,
        alias="firstObservedAt",
    )
    last_observed_at: str | None = Field(
        default=None,
        alias="lastObservedAt",
    )


class ReportV2TlsSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    finding_count: int = Field(alias="findingCount")
    by_severity: dict[str, int] = Field(
        default_factory=dict,
        alias="bySeverity",
    )
    by_category: dict[str, int] = Field(
        default_factory=dict,
        alias="byCategory",
    )
    inspector_status: str | None = Field(default=None, alias="inspectorStatus")


class ReportV2Response(BaseModel):
    """Deterministic v2 evidence report (strictly AI-free by design)."""

    model_config = ConfigDict(populate_by_name=True)

    schema_version: str = Field(alias="schemaVersion")
    deterministic: bool
    generated_at: str = Field(alias="generatedAt")
    content_hash: str = Field(alias="contentHash")
    scan: ReportV2Scan
    engines: list[ReportV2Engine] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(
        default_factory=dict,
        alias="severityCounts",
    )
    lifecycle_counts: dict[str, int] = Field(
        default_factory=dict,
        alias="lifecycleCounts",
    )
    findings: list[ReportV2Finding] = Field(default_factory=list)
    delta: ReportV2Delta | None = None
    technologies: list[ReportV2Technology] = Field(default_factory=list)
    tls_summary: ReportV2TlsSummary = Field(alias="tlsSummary")


@router.get(
    "/{scan_id}/report/v2",
    response_model=ReportV2Response,
    summary="Deterministic v2 evidence report (AI-free)",
)
async def get_scan_report_v2(
    scan_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> ReportV2Response:
    """Assemble the v2 evidence report for one visible scan.

    Read-only and deterministic: findings with lifecycle/priority,
    operator remediation + live verification states, delta vs the
    previous completed scan, technology inventory, TLS summary, and a
    content hash proving byte-identical renders over unchanged
    evidence. No AI interpretation is included. Invisible scans are
    404 (never 403).
    """
    document = await _service(session, current_user).get_scan_report_v2(scan_id)
    if document is None:
        raise NotFoundError()
    return ReportV2Response.model_validate(document)


@router.get(
    "/{scan_id}/findings/{finding_id}/explanation",
    response_model=dict[str, object],
    summary="Per-finding AI explanation (validated or fallback template)",
)
async def get_finding_explanation(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> dict[str, object]:
    """Return the AI explanation for one finding.

    The endpoint is honest about provenance: a finding without an
    explanation is served a deterministic fallback template (NEVER a 404
    or an empty body) so the user always gets a readable explanation.
    The ``validationStatus`` field of the response is the single
    boolean the UI needs to label the answer correctly.
    """
    service = _service(session, current_user)
    await service.get_scan(scan_id)  # tenant-isolation gate
    from src.domain.scanning.analysis.fallback_templates import (
        build_fallback_explanation,
    )
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    repository = ScanEngineExecutionRepository(session)
    finding_dto = await repository.get_finding_with_evidence(finding_id)
    if finding_dto is None:
        return {
            "available": False,
            "validationStatus": "FALLBACK_USED",
            "fallbackReason": "finding_not_found",
        }

    # Confirm the finding belongs to this scan (cross-scan isolation).
    # The response is deliberately IDENTICAL to the unknown-id case above:
    # distinguishing "exists elsewhere" from "exists nowhere" would be a
    # cross-tenant existence oracle, so both answer the same way.
    findings_in_scan = await repository.list_finding_dtos(scan_id)
    if not any(str(row["id"]) == str(finding_id) for row in findings_in_scan):
        return {
            "available": False,
            "validationStatus": "FALLBACK_USED",
            "fallbackReason": "finding_not_found",
        }

    assessment = await repository.get_assessment(scan_id)
    if assessment is None or not assessment.is_available:
        # AI is unavailable, didn't run, or produced a failed response:
        # always return a fallback so the user sees deterministic content.
        explanation = build_fallback_explanation(
            finding_id=str(finding_id),
            category_code=str(finding_dto.get("category", "")),
        )
        return {
            "available": True,
            "validationStatus": explanation.validation_status.value,
            "explanation": explanation.to_dict(),
        }

    # AI output is available: emit the assessment's per-finding narrative
    # when it carries one, otherwise the same deterministic fallback.
    payload = dict(assessment.payload or {})
    per_finding = payload.get("findings")
    if isinstance(per_finding, dict) and str(finding_id) in per_finding:
        return {
            "available": True,
            "validationStatus": "validated",
            "explanation": per_finding[str(finding_id)],
        }

    explanation = build_fallback_explanation(
        finding_id=str(finding_id),
        category_code=str(finding_dto.get("category", "")),
    )
    return {
        "available": True,
        "validationStatus": explanation.validation_status.value,
        "explanation": explanation.to_dict(),
    }


@router.get(
    "/{scan_id}/report",
    summary="Render the canonical report for one scan in the requested format",
    responses={
        200: {
            "description": "Report rendered in the requested format.",
            "content": {
                "application/json": {},
                "text/csv": {},
                "application/pdf": {},
            },
        },
        404: {"description": "Scan not found."},
        422: {"description": "Unsupported format."},
    },
)
async def render_scan_report(
    scan_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    format: Annotated[  # noqa: A002 - public API name
        str,
        Query(pattern="^(json|csv|pdf)$", description="Report format: json, csv, or pdf"),
    ] = "json",
) -> Response:
    """Render the report for one scan as JSON, CSV, or PDF (SRS Ch10 §4).

    The renderer is read-only: it never mutates any database state and
    never alters the canonical finding/severity/lifecycle values
    established by the scan pipeline (Ch10 §3 integrity constraint).
    """
    from fastapi.responses import JSONResponse, PlainTextResponse
    from fastapi.responses import Response as RawResponse

    service = _service(session, current_user)
    await service.get_scan(scan_id)  # tenant-isolation gate

    from src.reporting.assembler import ReportAssembler
    from src.reporting.export_formatters.csv_formatter import render_csv_report
    from src.reporting.export_formatters.json_formatter import render_json_report
    from src.reporting.pdf_generator import render_pdf_report

    document = await ReportAssembler(session).assemble(scan_id)
    if document is None:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "Scan not found."}},
        )

    if format == "json":
        body = render_json_report(document)
        return JSONResponse(
            status_code=200,
            content=json.loads(body),
        )
    if format == "pdf":
        pdf_bytes = render_pdf_report(document)
        return RawResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="sentinel-scan-{scan_id}.pdf"'},
        )
    body = render_csv_report(document)
    # Attachment delivery (not inline): combined with formula neutralization
    # in the formatter, this keeps spreadsheet handlers from executing
    # hostile cell content on open.
    return PlainTextResponse(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="sentinel-scan-{scan_id}.csv"'},
    )


@router.get(
    "/{scan_id}/assessment",
    response_model=AssessmentResponse | dict[str, str],
    summary="AI assessment for a scan (or controlled unavailability)",
)
async def get_assessment(scan_id: uuid.UUID, session: SessionDep, current_user: CurrentUser) -> Any:
    service = _service(session, current_user)
    await service.get_scan(scan_id)  # tenant-isolation gate
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    dto = await ScanEngineExecutionRepository(session).get_assessment_dto(scan_id)
    if dto is None:
        return {
            "available": False,
            "provider": "none",
            "model": "none",
            "promptSchemaVersion": "v1",
            "outputSchemaVersion": "v1",
            "failureKind": "not_ready",
            "unsupportedClaimCount": 0,
            "payload": {},
            "createdAt": datetime.now(UTC).isoformat(),
        }
    return AssessmentResponse(
        available=bool(dto["available"]),
        provider=str(dto["provider"]),
        model=str(dto["model"]),
        prompt_schema_version=str(dto["promptSchemaVersion"]),
        output_schema_version=str(dto["outputSchemaVersion"]),
        failure_kind=cast("str | None", dto["failureKind"]),
        unsupported_claim_count=int(str(dto["unsupportedClaimCount"])),
        payload=cast("dict[str, Any]", dto["payload"]),
        created_at=str(dto["createdAt"]),
    )


@router.post(
    "/{scan_id}/rescan",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan linked to a previous scan (rescan)",
)
async def rescan_scan(
    scan_id: uuid.UUID,
    response_bg: BackgroundTasks,
    session: SessionDep,
    current_user: CurrentUser,
) -> ScanResponse:
    service = _service(session, current_user)
    new_details = await service.rescan_scan(scan_id)
    if get_settings().scanner_execution_enabled:
        from src.workers.scan_tasks import enqueue_scan

        task_id = enqueue_scan(new_details.id)
        if not task_id:
            response_bg.add_task(
                service.build_background_job(new_details.id, ai_analyzer=_maybe_gemini())
            )
    return _to_response(new_details)


class FindingCompareItem(BaseModel):
    id: str
    fingerprint: str
    title: str
    severity: str
    # Populated only for persistent findings whose severity changed between
    # the two scans (fingerprints are severity-independent by design).
    previous_severity: str | None = Field(default=None, serialization_alias="previousSeverity")


class PrioritySnapshot(BaseModel):
    """Deterministic priority at one side of the comparison."""

    score: int
    level: str
    version: str
    factors: list[str] = Field(default_factory=list)


class EnrichmentSignal(BaseModel):
    """Compact advisory metadata attached to a compared finding."""

    source: str
    external_ref: str = Field(serialization_alias="externalRef")
    cve_id: str | None = Field(default=None, serialization_alias="cveId")
    cwe_id: str | None = Field(default=None, serialization_alias="cweId")
    cvss_score: float | None = Field(default=None, serialization_alias="cvssScore")


class CompareRecord(BaseModel):
    """One deterministic per-finding comparison record (AI-ready).

    ``previous_*`` values are None when the finding did not exist (or the
    signal cannot be honestly reconstructed) on that side. A DONE
    remediation status never implies lifecycle resolution.
    """

    id: str
    previous_finding_id: str | None = Field(default=None, serialization_alias="previousFindingId")
    title: str
    category: str
    fingerprint: str
    lifecycle_status: str = Field(serialization_alias="lifecycleStatus")
    previous_lifecycle_status: str | None = Field(
        default=None, serialization_alias="previousLifecycleStatus"
    )
    severity: str
    previous_severity: str | None = Field(default=None, serialization_alias="previousSeverity")
    severity_changed: bool = Field(serialization_alias="severityChanged")
    priority: PrioritySnapshot
    previous_priority: PrioritySnapshot | None = Field(
        default=None, serialization_alias="previousPriority"
    )
    priority_changed: bool = Field(serialization_alias="priorityChanged")
    priority_versions_match: bool = Field(serialization_alias="priorityVersionsMatch")
    remediation_status: str | None = Field(default=None, serialization_alias="remediationStatus")
    previous_remediation_status: str | None = Field(
        default=None, serialization_alias="previousRemediationStatus"
    )
    remediation_changed: bool = Field(serialization_alias="remediationChanged")
    evidence_count: int = Field(serialization_alias="evidenceCount")
    previous_evidence_count: int = Field(serialization_alias="previousEvidenceCount")
    evidence_changed: bool = Field(serialization_alias="evidenceChanged")
    evidence_hashes: list[str] = Field(serialization_alias="evidenceHashes")
    enrichment_changed: bool = Field(serialization_alias="enrichmentChanged")
    cves: list[str] = Field(default_factory=list)
    cvss_max: float | None = Field(default=None, serialization_alias="cvssMax")
    enrichment: list[EnrichmentSignal] = Field(default_factory=list)
    first_seen_at: str | None = Field(default=None, serialization_alias="firstSeenAt")
    last_seen_at: str | None = Field(default=None, serialization_alias="lastSeenAt")
    scan_id: str = Field(serialization_alias="scanId")
    previous_scan_id: str | None = Field(default=None, serialization_alias="previousScanId")


class CompareSummary(BaseModel):
    """Aggregate counts computed from the comparison records."""

    new_count: int = Field(serialization_alias="newCount")
    persistent_count: int = Field(serialization_alias="persistentCount")
    resolved_count: int = Field(serialization_alias="resolvedCount")
    regressed_count: int = Field(serialization_alias="regressedCount")
    severity_changed_count: int = Field(serialization_alias="severityChangedCount")
    priority_changed_count: int = Field(serialization_alias="priorityChangedCount")
    remediation_changed_count: int = Field(serialization_alias="remediationChangedCount")
    evidence_changed_count: int = Field(serialization_alias="evidenceChangedCount")
    enrichment_changed_count: int = Field(serialization_alias="enrichmentChangedCount")


class CompareResponse(BaseModel):
    new_: list[FindingCompareItem] = Field(alias="new")
    persistent: list[FindingCompareItem]
    resolved: list[FindingCompareItem]
    regressed: list[FindingCompareItem]
    records: list[CompareRecord] = Field(default_factory=list)
    summary: CompareSummary | None = None

    model_config = {"populate_by_name": True}


@router.get(
    "/{scan_a_id}/compare/{scan_b_id}",
    response_model=CompareResponse,
    summary="Compare findings between two scans of the same target",
)
async def compare_scans(
    scan_a_id: uuid.UUID,
    scan_b_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> CompareResponse:
    result = await _service(session, current_user).compare_scans_detailed(scan_a_id, scan_b_id)
    return _to_compare_response(result)


def _to_compare_response(result: dict[str, object]) -> CompareResponse:
    """Map a detailed comparison result onto the wire contract.

    Shared by the GET compare endpoint and the POST analysis endpoint so
    both surfaces describe identical deterministic data.
    """
    buckets = cast("dict[str, list[dict[str, object]]]", result)
    records_raw = cast("list[dict[str, object]]", result.get("records") or [])

    def _item(i: dict[str, object]) -> FindingCompareItem:
        return FindingCompareItem(
            id=str(i["id"]),
            fingerprint=str(i["fingerprint"]),
            title=str(i["title"]),
            severity=str(i["severity"]),
            previous_severity=(
                str(i["previous_severity"]) if i.get("previous_severity") is not None else None
            ),
        )

    def _priority(raw: object) -> PrioritySnapshot:
        assert isinstance(raw, dict)
        factors = raw.get("factors")
        return PrioritySnapshot(
            score=int(raw["score"]),
            level=str(raw["level"]),
            version=str(raw["version"]),
            factors=[str(f) for f in factors] if isinstance(factors, list) else [],
        )

    def _record(r: dict[str, object]) -> CompareRecord:
        prev_priority = r.get("previous_priority")
        return CompareRecord(
            id=str(r["id"]),
            previous_finding_id=(
                str(r["previous_finding_id"]) if r.get("previous_finding_id") is not None else None
            ),
            title=str(r["title"]),
            category=str(r["category"]),
            fingerprint=str(r["fingerprint"]),
            lifecycle_status=str(r["lifecycle_status"]),
            previous_lifecycle_status=(
                str(r["previous_lifecycle_status"])
                if r.get("previous_lifecycle_status") is not None
                else None
            ),
            severity=str(r["severity"]),
            previous_severity=(
                str(r["previous_severity"]) if r.get("previous_severity") is not None else None
            ),
            severity_changed=bool(r["severity_changed"]),
            priority=_priority(r["priority"]),
            previous_priority=_priority(prev_priority) if prev_priority is not None else None,
            priority_changed=bool(r["priority_changed"]),
            priority_versions_match=bool(r["priority_versions_match"]),
            remediation_status=(
                str(r["remediation_status"]) if r.get("remediation_status") is not None else None
            ),
            previous_remediation_status=(
                str(r["previous_remediation_status"])
                if r.get("previous_remediation_status") is not None
                else None
            ),
            remediation_changed=bool(r["remediation_changed"]),
            evidence_count=cast("int", r["evidence_count"]),
            previous_evidence_count=cast("int", r["previous_evidence_count"]),
            evidence_changed=bool(r["evidence_changed"]),
            evidence_hashes=[str(h) for h in cast("list[object]", r["evidence_hashes"] or [])],
            enrichment_changed=bool(r["enrichment_changed"]),
            cves=[str(c) for c in cast("list[object]", r["cves"] or [])],
            cvss_max=(cast("float", r["cvss_max"]) if r.get("cvss_max") is not None else None),
            enrichment=[
                EnrichmentSignal(
                    source=str(e.get("source")),
                    external_ref=str(e.get("external_ref")),
                    cve_id=str(e["cve_id"]) if e.get("cve_id") is not None else None,
                    cwe_id=str(e["cwe_id"]) if e.get("cwe_id") is not None else None,
                    cvss_score=(
                        float(score)
                        if isinstance((score := e.get("cvss_score")), (int, float))
                        else None
                    ),
                )
                for e in cast("list[dict[str, object]]", r["enrichment"] or [])
            ],
            first_seen_at=(str(r["first_seen_at"]) if r.get("first_seen_at") is not None else None),
            last_seen_at=(str(r["last_seen_at"]) if r.get("last_seen_at") is not None else None),
            scan_id=str(r["scan_id"]),
            previous_scan_id=(
                str(r["previous_scan_id"]) if r.get("previous_scan_id") is not None else None
            ),
        )

    def _summary(raw: object) -> CompareSummary:
        assert isinstance(raw, dict)
        return CompareSummary(
            new_count=int(raw["new_count"]),
            persistent_count=int(raw["persistent_count"]),
            resolved_count=int(raw["resolved_count"]),
            regressed_count=int(raw["regressed_count"]),
            severity_changed_count=int(raw["severity_changed_count"]),
            priority_changed_count=int(raw["priority_changed_count"]),
            remediation_changed_count=int(raw["remediation_changed_count"]),
            evidence_changed_count=int(raw["evidence_changed_count"]),
            enrichment_changed_count=int(raw["enrichment_changed_count"]),
        )

    return CompareResponse(
        new=[_item(i) for i in buckets["new"]],
        persistent=[_item(i) for i in buckets["persistent"]],
        resolved=[_item(i) for i in buckets["resolved"]],
        regressed=[_item(i) for i in buckets["regressed"]],
        records=[_record(r) for r in records_raw],
        summary=_summary(result["summary"]),
    )


class ComparisonClaimResponse(BaseModel):
    """One AI statement bound to comparison records."""

    text: str
    finding_ids: list[str] = Field(serialization_alias="findingIds")
    fingerprints: list[str] = Field(default_factory=list)
    status: str
    detail: str = ""


class PriorityChangeResponse(BaseModel):
    """A narrated priority transition (levels verified against records)."""

    finding_id: str = Field(serialization_alias="findingId")
    fingerprint: str
    from_level: str = Field(serialization_alias="fromLevel")
    to_level: str = Field(serialization_alias="toLevel")
    reason: str = ""


class RegressionInsightResponse(BaseModel):
    """A narrated regression anchored to one fingerprint."""

    finding_id: str = Field(serialization_alias="findingId")
    fingerprint: str
    previous_state: str = Field(serialization_alias="previousState")
    current_state: str = Field(serialization_alias="currentState")
    why_matters: str = Field(serialization_alias="whyMatters")


class ResolvedItemResponse(BaseModel):
    """A narrated resolution anchored to one fingerprint."""

    finding_id: str = Field(serialization_alias="findingId")
    fingerprint: str
    note: str = ""


class ComparisonActionResponse(BaseModel):
    """One AI-suggested remediation step (verification, never a fix claim)."""

    title: str
    detail: str = ""
    finding_ids: list[str] = Field(serialization_alias="findingIds")
    verification: str = ""


class ComparisonProviderResponse(BaseModel):
    """Honest provenance for one AI comparison run."""

    provider: str
    model: str
    model_version: str = Field(serialization_alias="modelVersion")
    prompt_schema_version: str = Field(serialization_alias="promptSchemaVersion")
    output_schema_version: str = Field(serialization_alias="outputSchemaVersion")
    created_at: str = Field(serialization_alias="createdAt")


class ComparisonAssessmentResponse(BaseModel):
    """Validated AI comparison narration (never canonical truth)."""

    assessment_id: str = Field(serialization_alias="assessmentId")
    comparison_evidence_id: str = Field(serialization_alias="comparisonEvidenceId")
    executive_summary: str = Field(serialization_alias="executiveSummary")
    technical_summary: str = Field(serialization_alias="technicalSummary")
    key_changes: list[ComparisonClaimResponse] = Field(serialization_alias="keyChanges")
    priority_changes: list[PriorityChangeResponse] = Field(serialization_alias="priorityChanges")
    regressions: list[RegressionInsightResponse] = Field(default_factory=list)
    resolved_items: list[ResolvedItemResponse] = Field(serialization_alias="resolvedItems")
    recommended_actions: list[ComparisonActionResponse] = Field(
        serialization_alias="recommendedActions"
    )
    limitations: list[str] = Field(default_factory=list)
    citations: list[ComparisonClaimResponse] = Field(default_factory=list)
    unsupported_claim_count: int = Field(serialization_alias="unsupportedClaimCount")
    provider: ComparisonProviderResponse | None = None


class ComparisonFailureResponse(BaseModel):
    """Controlled degradation: deterministic comparison still returned."""

    kind: str
    detail: str = ""


class CompareAnalysisResponse(BaseModel):
    """Deterministic summary plus optional AI narration of a scan pair."""

    summary: CompareSummary
    analysis: ComparisonAssessmentResponse | None = None
    failure: ComparisonFailureResponse | None = None


# Outer guard around the provider call: the adapter times out internally
# at 20s; this bounds total handler latency (queue + model + validation).
COMPARISON_ANALYSIS_TIMEOUT_S = 45.0


@router.post(
    "/{scan_a_id}/compare/{scan_b_id}/analysis",
    response_model=CompareAnalysisResponse,
    summary="AI narration of a deterministic scan comparison",
)
async def analyze_comparison(
    scan_a_id: uuid.UUID,
    scan_b_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
) -> CompareAnalysisResponse:
    """Explain what changed between two scans of the same target.

    The deterministic comparison gates everything (invisible scans are
    404, cross-target pairs are rejected) and always returns. The AI
    narration is best-effort: unconfigured or failing providers yield a
    controlled ``failure`` with ``analysis`` null — canonical data is
    never mutated by this path.
    """
    import asyncio
    import functools

    from src.domain.scanning.analysis.comparison_evidence import build_comparison_evidence
    from src.domain.scanning.analysis.comparison_models import ComparisonAssessment
    from src.domain.scanning.analysis.comparison_service import ComparisonAnalysisService

    service = _service(session, current_user)
    detailed = await service.compare_scans_detailed(scan_a_id, scan_b_id)
    summary = _to_compare_response(detailed).summary
    assert summary is not None

    scan_a = await service.get_scan(scan_a_id)
    evidence = build_comparison_evidence(
        detailed,
        scan_a_id=str(scan_a_id),
        scan_b_id=str(scan_b_id),
        target_id=str(scan_a.target_id),
    )

    analyzer = _maybe_gemini()
    if analyzer is None:
        return CompareAnalysisResponse(
            summary=summary,
            analysis=None,
            failure=ComparisonFailureResponse(
                kind="provider_unavailable", detail="AI analysis is not configured"
            ),
        )

    analysis_service = ComparisonAnalysisService(analyzer)
    loop = asyncio.get_running_loop()
    try:
        _evidence, outcome = await asyncio.wait_for(
            loop.run_in_executor(None, functools.partial(analysis_service.analyze, evidence)),
            timeout=COMPARISON_ANALYSIS_TIMEOUT_S,
        )
    except TimeoutError:
        return CompareAnalysisResponse(
            summary=summary,
            analysis=None,
            failure=ComparisonFailureResponse(kind="timeout", detail="AI analysis timed out"),
        )

    if isinstance(outcome, ComparisonAssessment):
        return CompareAnalysisResponse(summary=summary, analysis=_to_assessment_response(outcome))
    return CompareAnalysisResponse(
        summary=summary,
        analysis=None,
        failure=ComparisonFailureResponse(kind=outcome.failure_kind.value, detail=outcome.detail),
    )


def _to_assessment_response(assessment: ComparisonAssessment) -> ComparisonAssessmentResponse:
    def _claim(claim: Any) -> ComparisonClaimResponse:
        return ComparisonClaimResponse(
            text=str(claim.text),
            finding_ids=[str(i) for i in claim.finding_ids],
            fingerprints=[str(f) for f in claim.fingerprints],
            status=str(claim.status.value if hasattr(claim.status, "value") else claim.status),
            detail=str(claim.detail),
        )

    provider = assessment.provider_metadata
    return ComparisonAssessmentResponse(
        assessment_id=assessment.assessment_id,
        comparison_evidence_id=assessment.comparison_evidence_id,
        executive_summary=assessment.executive_summary,
        technical_summary=assessment.technical_summary,
        key_changes=[_claim(c) for c in assessment.key_changes],
        priority_changes=[
            PriorityChangeResponse(
                finding_id=str(p.finding_id),
                fingerprint=str(p.fingerprint),
                from_level=str(p.from_level),
                to_level=str(p.to_level),
                reason=str(p.reason),
            )
            for p in assessment.priority_changes
        ],
        regressions=[
            RegressionInsightResponse(
                finding_id=str(r.finding_id),
                fingerprint=str(r.fingerprint),
                previous_state=str(r.previous_state),
                current_state=str(r.current_state),
                why_matters=str(r.why_matters),
            )
            for r in assessment.regressions
        ],
        resolved_items=[
            ResolvedItemResponse(
                finding_id=str(r.finding_id),
                fingerprint=str(r.fingerprint),
                note=str(r.note),
            )
            for r in assessment.resolved_items
        ],
        recommended_actions=[
            ComparisonActionResponse(
                title=str(a.title),
                detail=str(a.detail),
                finding_ids=[str(i) for i in a.finding_ids],
                verification=str(a.verification),
            )
            for a in assessment.recommended_actions
        ],
        limitations=[str(x) for x in assessment.limitations],
        citations=[_claim(c) for c in assessment.citations],
        unsupported_claim_count=assessment.unsupported_claim_count,
        provider=(
            ComparisonProviderResponse(
                provider=str(provider.provider),
                model=str(provider.model),
                model_version=str(provider.model_version),
                prompt_schema_version=str(provider.prompt_schema_version),
                output_schema_version=str(provider.output_schema_version),
                created_at=provider.created_at.isoformat(),
            )
            if provider is not None
            else None
        ),
    )
