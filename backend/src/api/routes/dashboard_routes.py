"""Security-posture read endpoints (derived, never stored).

All three routes return deterministic snapshots computed from canonical
data (targets, scans, findings, lifecycle history, remediation,
enrichment, technology inventory) for the authenticated owner only.
Empty accounts receive honest zeros/empties (200), never 404.
"""

from __future__ import annotations

import uuid  # noqa: TC003 - FastAPI resolves route annotations at runtime
from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from src.api.dependencies import CurrentUser, SessionDep  # noqa: TC001 - FastAPI runtime
from src.domain.posture.posture_service import PostureService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class PrioritySnapshotDto(BaseModel):
    score: int
    level: str
    version: str
    factors: list[str] = Field(default_factory=list)


class TopFindingDto(BaseModel):
    finding_id: str = Field(serialization_alias="findingId")
    target_id: str = Field(serialization_alias="targetId")
    hostname: str
    fingerprint: str
    title: str
    severity: str
    lifecycle_status: str = Field(serialization_alias="lifecycleStatus")
    priority: PrioritySnapshotDto
    remediation_status: str | None = Field(default=None, serialization_alias="remediationStatus")


class RegressionItemDto(BaseModel):
    target_id: str = Field(serialization_alias="targetId")
    hostname: str
    fingerprint: str
    severity: str
    priority: PrioritySnapshotDto


class DoneOpenItemDto(BaseModel):
    target_id: str = Field(serialization_alias="targetId")
    hostname: str
    fingerprint: str
    severity: str
    priority: PrioritySnapshotDto


class LatestScanDto(BaseModel):
    scan_id: str = Field(serialization_alias="scanId")
    target_id: str = Field(serialization_alias="targetId")
    status: str
    completed_at: str | None = Field(default=None, serialization_alias="completedAt")


class MttrDto(BaseModel):
    mean_hours: float = Field(serialization_alias="meanHours")
    median_hours: float = Field(serialization_alias="medianHours")
    sample_size: int = Field(serialization_alias="sampleSize")
    resolved_identities: int = Field(serialization_alias="resolvedIdentities")


class PostureResponse(BaseModel):
    targets_total: int = Field(serialization_alias="targetsTotal")
    targets_active: int = Field(serialization_alias="targetsActive")
    scans_total: int = Field(serialization_alias="scansTotal")
    scans_completed: int = Field(serialization_alias="scansCompleted")
    scans_in_flight: int = Field(serialization_alias="scansInFlight")
    open_findings_total: int = Field(serialization_alias="openFindingsTotal")
    unresolved_identities: int = Field(serialization_alias="unresolvedIdentities")
    severity_counts: dict[str, int] = Field(serialization_alias="severityCounts")
    priority_counts: dict[str, int] = Field(serialization_alias="priorityCounts")
    lifecycle_counts: dict[str, int] = Field(serialization_alias="lifecycleCounts")
    remediation_counts: dict[str, int] = Field(serialization_alias="remediationCounts")
    remediation_open_total: int = Field(serialization_alias="remediationOpenTotal")
    done_open_count: int = Field(serialization_alias="doneOpenCount")
    done_open_items: list[DoneOpenItemDto] = Field(serialization_alias="doneOpenItems")
    regressions_total: int = Field(serialization_alias="regressionsTotal")
    regressions_targets: list[str] = Field(serialization_alias="regressionsTargets")
    top_regressions: list[RegressionItemDto] = Field(serialization_alias="topRegressions")
    top_findings: list[TopFindingDto] = Field(serialization_alias="topFindings")
    mttr: MttrDto | None = None
    latest_scan: LatestScanDto | None = Field(default=None, serialization_alias="latestScan")
    priority_version: str = Field(serialization_alias="priorityVersion")


class TrendPointDto(BaseModel):
    scan_id: str = Field(serialization_alias="scanId")
    target_id: str = Field(serialization_alias="targetId")
    completed_at: str = Field(serialization_alias="completedAt")
    status: str
    total_findings: int = Field(serialization_alias="totalFindings")
    severity_counts: dict[str, int] = Field(serialization_alias="severityCounts")
    priority_counts: dict[str, int] = Field(serialization_alias="priorityCounts")
    new_count: int = Field(serialization_alias="newCount")
    resolved_count: int = Field(serialization_alias="resolvedCount")
    regressed_count: int = Field(serialization_alias="regressedCount")


class TrendsResponse(BaseModel):
    points: list[TrendPointDto]
    insufficient_history: bool = Field(serialization_alias="insufficientHistory")
    priority_version: str = Field(serialization_alias="priorityVersion")


class TargetPostureDto(BaseModel):
    target_id: str = Field(serialization_alias="targetId")
    hostname: str
    is_archived: bool = Field(serialization_alias="isArchived")
    latest_scan: LatestScanDto | None = Field(default=None, serialization_alias="latestScan")
    previous_scan_id: str | None = Field(default=None, serialization_alias="previousScanId")
    last_scan_at: str | None = Field(default=None, serialization_alias="lastScanAt")
    open_findings_total: int = Field(serialization_alias="openFindingsTotal")
    severity_counts: dict[str, int] = Field(serialization_alias="severityCounts")
    priority_counts: dict[str, int] = Field(serialization_alias="priorityCounts")
    regressions_count: int = Field(serialization_alias="regressionsCount")
    remediation_counts: dict[str, int] = Field(serialization_alias="remediationCounts")
    done_open_count: int = Field(serialization_alias="doneOpenCount")


class TargetsPostureResponse(BaseModel):
    targets: list[TargetPostureDto]
    total: int
    priority_version: str = Field(serialization_alias="priorityVersion")


class RemediationItemDto(BaseModel):
    fingerprint: str
    target_id: str = Field(serialization_alias="targetId")
    status: str
    assignee_user_id: str | None = Field(default=None, serialization_alias="assigneeUserId")
    assignee_email: str | None = Field(default=None, serialization_alias="assigneeEmail")
    due_at: str | None = Field(default=None, serialization_alias="dueAt")
    overdue: bool = False


class RemediationSummaryResponse(BaseModel):
    """Deterministic remediation aggregates for the owner's targets.

    Counts plus bounded actionable item lists (overdue, due within 72
    hours, unassigned — 200 each, deterministic target/fingerprint
    order). Lifecycle-aware buckets count only identities with known
    lifecycle state; unknown stays unbucketed rather than guessed.
    """

    total: int
    by_status: dict[str, int] = Field(serialization_alias="byStatus")
    assigned: int
    unassigned: int
    due_open: int = Field(serialization_alias="dueOpen")
    overdue: int
    no_due_date: int = Field(serialization_alias="noDueDate")
    done_open: int = Field(serialization_alias="doneOpen")
    resolved_after_remediation: int = Field(serialization_alias="resolvedAfterRemediation")
    regressed_after_remediation: int = Field(serialization_alias="regressedAfterRemediation")
    lifecycle_unknown: int = Field(serialization_alias="lifecycleUnknown")
    by_assignee: dict[str, int] = Field(serialization_alias="byAssignee")
    overdue_items: list[RemediationItemDto] = Field(serialization_alias="overdueItems")
    due_soon_items: list[RemediationItemDto] = Field(serialization_alias="dueSoonItems")
    unassigned_items: list[RemediationItemDto] = Field(serialization_alias="unassignedItems")


def _to_remediation_item(raw: object) -> RemediationItemDto:
    assert isinstance(raw, dict)
    return RemediationItemDto(
        fingerprint=str(raw["fingerprint"]),
        target_id=str(raw["target_id"]),
        status=str(raw["status"]),
        assignee_user_id=(
            str(raw["assignee_user_id"]) if raw.get("assignee_user_id") is not None else None
        ),
        assignee_email=(
            str(raw["assignee_email"]) if raw.get("assignee_email") is not None else None
        ),
        due_at=str(raw["due_at"]) if raw.get("due_at") is not None else None,
        overdue=bool(raw.get("overdue")),
    )


def _priority(raw: object) -> PrioritySnapshotDto:
    assert isinstance(raw, dict)
    factors = raw.get("factors")
    score = raw.get("score")
    assert isinstance(score, int)
    return PrioritySnapshotDto(
        score=score,
        level=str(raw["level"]),
        version=str(raw["version"]),
        factors=[str(f) for f in factors] if isinstance(factors, list) else [],
    )


def _req_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    assert isinstance(value, int)
    return value


def _req_counts(mapping: dict[str, object], key: str) -> dict[str, int]:
    value = mapping.get(key)
    assert isinstance(value, dict)
    return {str(k): int(v) for k, v in value.items() if isinstance(v, int)}


def _req_float(mapping: dict[str, object], key: str) -> float:
    value = mapping.get(key)
    assert isinstance(value, (int, float)) and not isinstance(value, bool)
    return float(value)


@router.get("/posture", response_model=PostureResponse, summary="Current security posture")
async def get_posture(session: SessionDep, current_user: CurrentUser) -> PostureResponse:
    posture = await PostureService(session, current_user).get_posture()
    mttr = posture.get("mttr")
    latest = posture.get("latest_scan")
    return PostureResponse(
        targets_total=_req_int(posture, "targets_total"),
        targets_active=_req_int(posture, "targets_active"),
        scans_total=_req_int(posture, "scans_total"),
        scans_completed=_req_int(posture, "scans_completed"),
        scans_in_flight=_req_int(posture, "scans_in_flight"),
        open_findings_total=_req_int(posture, "open_findings_total"),
        unresolved_identities=_req_int(posture, "unresolved_identities"),
        severity_counts=_req_counts(posture, "severity_counts"),
        priority_counts=_req_counts(posture, "priority_counts"),
        lifecycle_counts=_req_counts(posture, "lifecycle_counts"),
        remediation_counts=_req_counts(posture, "remediation_counts"),
        remediation_open_total=_req_int(posture, "remediation_open_total"),
        done_open_count=_req_int(posture, "done_open_count"),
        done_open_items=[
            DoneOpenItemDto(
                target_id=str(i["target_id"]),
                hostname=str(i["hostname"]),
                fingerprint=str(i["fingerprint"]),
                severity=str(i["severity"]),
                priority=_priority(i["priority"]),
            )
            for i in _as_list(posture.get("done_open_items"))
        ],
        regressions_total=_req_int(posture, "regressions_total"),
        regressions_targets=_as_str_list(posture.get("regressions_targets")),
        top_regressions=[
            RegressionItemDto(
                target_id=str(i["target_id"]),
                hostname=str(i["hostname"]),
                fingerprint=str(i["fingerprint"]),
                severity=str(i["severity"]),
                priority=_priority(i["priority"]),
            )
            for i in _as_list(posture.get("top_regressions"))
        ],
        top_findings=[
            TopFindingDto(
                finding_id=str(f["finding_id"]),
                target_id=str(f["target_id"]),
                hostname=str(f["hostname"]),
                fingerprint=str(f["fingerprint"]),
                title=str(f["title"]),
                severity=str(f["severity"]),
                lifecycle_status=str(f["lifecycle_status"]),
                priority=_priority(f["priority"]),
                remediation_status=(
                    str(f["remediation_status"])
                    if f.get("remediation_status") is not None
                    else None
                ),
            )
            for f in _as_list(posture.get("top_findings"))
        ],
        mttr=(
            MttrDto(
                mean_hours=_req_float(mttr, "mean_hours"),
                median_hours=_req_float(mttr, "median_hours"),
                sample_size=_req_int(mttr, "sample_size"),
                resolved_identities=_req_int(mttr, "resolved_identities"),
            )
            if isinstance(mttr, dict)
            else None
        ),
        latest_scan=(
            LatestScanDto(
                scan_id=str(latest["scan_id"]),
                target_id=str(latest["target_id"]),
                status=str(latest["status"]),
                completed_at=str(latest["completed_at"])
                if latest.get("completed_at") is not None
                else None,
            )
            if isinstance(latest, dict)
            else None
        ),
        priority_version=str(posture["priority_version"]),
    )


@router.get("/trends", response_model=TrendsResponse, summary="Posture trend points")
async def get_trends(
    session: SessionDep,
    current_user: CurrentUser,
    target_id: Annotated[uuid.UUID | None, Query(alias="targetId")] = None,
    limit: Annotated[int, Query(ge=1, le=50)] = 20,
) -> TrendsResponse:
    trends = await PostureService(session, current_user).get_trends(
        target_id=target_id, limit=limit
    )
    return TrendsResponse(
        points=[
            TrendPointDto(
                scan_id=str(p["scan_id"]),
                target_id=str(p["target_id"]),
                completed_at=str(p["completed_at"]),
                status=str(p["status"]),
                total_findings=_req_int(p, "total_findings"),
                severity_counts=_req_counts(p, "severity_counts"),
                priority_counts=_req_counts(p, "priority_counts"),
                new_count=_req_int(p, "new_count"),
                resolved_count=_req_int(p, "resolved_count"),
                regressed_count=_req_int(p, "regressed_count"),
            )
            for p in _as_list(trends.get("points"))
        ],
        insufficient_history=bool(trends.get("insufficient_history")),
        priority_version=str(trends["priority_version"]),
    )


@router.get("/targets", response_model=TargetsPostureResponse, summary="Per-target posture")
async def get_targets_posture(
    session: SessionDep,
    current_user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> TargetsPostureResponse:
    result = await PostureService(session, current_user).get_targets_posture(limit=limit)
    cards: list[TargetPostureDto] = []
    for target in _as_list(result.get("targets")):
        latest = target.get("latest_scan")
        cards.append(
            TargetPostureDto(
                target_id=str(target["target_id"]),
                hostname=str(target["hostname"]),
                is_archived=bool(target.get("is_archived")),
                latest_scan=(
                    LatestScanDto(
                        scan_id=str(latest["scan_id"]),
                        target_id=str(target["target_id"]),
                        status=str(latest["status"]),
                        completed_at=str(latest["completed_at"])
                        if latest.get("completed_at") is not None
                        else None,
                    )
                    if isinstance(latest, dict)
                    else None
                ),
                previous_scan_id=(
                    str(target["previous_scan_id"])
                    if target.get("previous_scan_id") is not None
                    else None
                ),
                last_scan_at=(
                    str(target["last_scan_at"]) if target.get("last_scan_at") is not None else None
                ),
                open_findings_total=_req_int(target, "open_findings_total"),
                severity_counts=_req_counts(target, "severity_counts"),
                priority_counts=_req_counts(target, "priority_counts"),
                regressions_count=_req_int(target, "regressions_count"),
                remediation_counts=_req_counts(target, "remediation_counts"),
                done_open_count=_req_int(target, "done_open_count"),
            )
        )
    return TargetsPostureResponse(
        targets=cards,
        total=_req_int(result, "total"),
        priority_version=str(result["priority_version"]),
    )


@router.get(
    "/remediation",
    response_model=RemediationSummaryResponse,
    summary="Remediation collaboration summary",
)
async def get_remediation_summary(
    session: SessionDep, current_user: CurrentUser
) -> RemediationSummaryResponse:
    """Assignment, due-date, and lifecycle-aware remediation aggregates.

    Same owner scoping as posture (empty accounts get honest zeros,
    never 404). Computed from stored workflow rows plus bounded
    lifecycle history — no N+1, no new calculation system.
    """
    from src.domain.scans.scan_service import ScanService

    summary = await ScanService(session, current_user).get_remediation_summary()
    return RemediationSummaryResponse(
        total=_req_int(summary, "total"),
        by_status=_req_counts(summary, "by_status"),
        assigned=_req_int(summary, "assigned"),
        unassigned=_req_int(summary, "unassigned"),
        due_open=_req_int(summary, "due_open"),
        overdue=_req_int(summary, "overdue"),
        no_due_date=_req_int(summary, "no_due_date"),
        done_open=_req_int(summary, "done_open"),
        resolved_after_remediation=_req_int(summary, "resolved_after_remediation"),
        regressed_after_remediation=_req_int(summary, "regressed_after_remediation"),
        lifecycle_unknown=_req_int(summary, "lifecycle_unknown"),
        by_assignee=_req_counts(summary, "by_assignee"),
        overdue_items=[_to_remediation_item(i) for i in _as_list(summary.get("overdue_items"))],
        due_soon_items=[_to_remediation_item(i) for i in _as_list(summary.get("due_soon_items"))],
        unassigned_items=[
            _to_remediation_item(i) for i in _as_list(summary.get("unassigned_items"))
        ],
    )


def _as_list(raw: object) -> list[dict[str, Any]]:
    return [dict(i) for i in raw] if isinstance(raw, list) else []


def _as_str_list(raw: object) -> list[str]:
    return [str(i) for i in raw] if isinstance(raw, list) else []
