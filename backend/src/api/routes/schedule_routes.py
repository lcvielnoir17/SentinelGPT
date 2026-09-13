"""Scheduled-scan endpoints (automation over scan creation).

Schedules never scan by themselves: each tick executes through the
normal scan-creation path (ownership, attestation, rate/quota gates).
Cross-owner schedule ids answer 404, matching every other resource.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field

from src.api.dependencies import CurrentUser, SessionDep  # noqa: TC001 - FastAPI runtime
from src.domain.schedules.schedule_service import ScheduleDetails, ScheduleService

router = APIRouter(prefix="/schedules", tags=["Schedules"])


class CreateScheduleRequest(BaseModel):
    """POST /schedules request body."""

    target_id: uuid.UUID = Field(validation_alias="targetId")
    scan_profile: str = Field(default="standard", validation_alias="scanProfile", max_length=50)
    interval_seconds: int = Field(validation_alias="intervalSeconds")


class UpdateScheduleRequest(BaseModel):
    """PATCH /schedules/{id} body — any subset of mutable fields."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, validation_alias="intervalSeconds")
    scan_profile: str | None = Field(default=None, validation_alias="scanProfile", max_length=50)


class ScheduleResponse(BaseModel):
    """Schedule representation with run bookkeeping."""

    id: uuid.UUID
    target_id: uuid.UUID = Field(serialization_alias="targetId")
    scan_profile: str = Field(serialization_alias="scanProfile")
    enabled: bool
    interval_seconds: int = Field(serialization_alias="intervalSeconds")
    next_run_at: str = Field(serialization_alias="nextRunAt")
    last_run_at: str | None = Field(default=None, serialization_alias="lastRunAt")
    last_status: str | None = Field(default=None, serialization_alias="lastStatus")
    last_detail: str | None = Field(default=None, serialization_alias="lastDetail")
    last_scan_id: str | None = Field(default=None, serialization_alias="lastScanId")
    created_at: str = Field(serialization_alias="createdAt")


class ScheduleRunResponse(BaseModel):
    """One executed tick: outcome only, safe to log."""

    schedule_id: uuid.UUID = Field(serialization_alias="scheduleId")
    status: str
    detail: str = ""
    scan_id: str | None = Field(default=None, serialization_alias="scanId")


def _to_response(details: ScheduleDetails) -> ScheduleResponse:
    return ScheduleResponse(
        id=details.id,
        target_id=details.target_id,
        scan_profile=details.scan_profile_code,
        enabled=details.enabled,
        interval_seconds=details.interval_seconds,
        next_run_at=details.next_run_at.isoformat(),
        last_run_at=details.last_run_at.isoformat() if details.last_run_at else None,
        last_status=details.last_status,
        last_detail=details.last_detail,
        last_scan_id=str(details.last_scan_id) if details.last_scan_id else None,
        created_at=details.created_at.isoformat(),
    )


def _to_run_response(outcome: Any) -> ScheduleRunResponse:
    return ScheduleRunResponse(
        schedule_id=outcome.schedule_id,
        status=outcome.status,
        detail=outcome.detail or "",
        scan_id=str(outcome.scan_id) if outcome.scan_id else None,
    )


def _service(session: Any, current_user: Any) -> ScheduleService:
    return ScheduleService(session, current_user)


@router.post(
    "",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a recurring scan schedule",
)
async def create_schedule(
    payload: CreateScheduleRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> ScheduleResponse:
    """Schedule authorized rescans of an owned target on an interval."""
    service = _service(session, current_user)
    details = await service.create_schedule(
        target_id=payload.target_id,
        scan_profile_code=payload.scan_profile,
        interval_seconds=payload.interval_seconds,
    )
    return _to_response(details)


@router.get("", response_model=list[ScheduleResponse], summary="List owned schedules")
async def list_schedules(
    session: SessionDep,
    current_user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ScheduleResponse]:
    rows = await _service(session, current_user).list_schedules()
    return [_to_response(row) for row in rows[:limit]]


@router.get("/{schedule_id}", response_model=ScheduleResponse, summary="Get schedule detail")
async def get_schedule(
    schedule_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> ScheduleResponse:
    return _to_response(await _service(session, current_user).get_schedule(schedule_id))


@router.patch("/{schedule_id}", response_model=ScheduleResponse, summary="Update a schedule")
async def update_schedule(
    schedule_id: uuid.UUID,
    payload: UpdateScheduleRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> ScheduleResponse:
    details = await _service(session, current_user).update_schedule(
        schedule_id,
        enabled=payload.enabled,
        interval_seconds=payload.interval_seconds,
        scan_profile_code=payload.scan_profile,
    )
    return _to_response(details)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a schedule",
)
async def delete_schedule(
    schedule_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> None:
    await _service(session, current_user).delete_schedule(schedule_id)


@router.post(
    "/{schedule_id}/trigger",
    response_model=ScheduleRunResponse,
    summary="Run one schedule tick immediately",
)
async def trigger_schedule(
    schedule_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> ScheduleRunResponse:
    """Execute one gated tick now (same gates as automatic runs)."""
    from src.workers.scan_tasks import enqueue_scan

    service = _service(session, current_user)
    outcome = await service.trigger_schedule(schedule_id)
    if outcome.status == "scan_created" and outcome.scan_id is not None:
        enqueue_scan(outcome.scan_id)
    return _to_run_response(outcome)
