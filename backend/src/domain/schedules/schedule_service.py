"""Scheduled scans: automation over the existing scan-creation path."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from src.domain.audit.audit_service import (
    ACTION_SCHEDULE_CREATED,
    ACTION_SCHEDULE_DELETED,
    ACTION_SCHEDULE_RUN,
    ACTION_SCHEDULE_UPDATED,
    AuditService,
)
from src.domain.errors import (
    AttestationNotConfirmedError,
    InvalidScheduleError,
    NotFoundError,
)
from src.domain.scans.errors import ScanQueueFullError, ScanRateLimitedError
from src.infrastructure.database.models import ScanSchedule
from src.infrastructure.database.repositories.schedule_repository import (
    ScheduleRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

MIN_INTERVAL_SECONDS = 600
MAX_INTERVAL_SECONDS = 2592000

STATUS_SCAN_CREATED = "scan_created"
STATUS_SKIPPED_TARGET_UNAVAILABLE = "skipped_target_unavailable"
STATUS_SKIPPED_TARGET_ARCHIVED = "skipped_target_archived"
STATUS_BLOCKED_NO_ATTESTATION = "blocked_no_attestation"
STATUS_SKIPPED_RATE_LIMITED = "skipped_rate_limited"
STATUS_SKIPPED_OWNER_INACTIVE = "skipped_owner_inactive"
STATUS_FAILED = "failed"


@dataclass(frozen=True)
class ScheduleDetails:
    """Framework-agnostic schedule entity returned by domain services."""

    id: uuid.UUID
    owner_user_id: uuid.UUID
    target_id: uuid.UUID
    scan_profile_code: str
    enabled: bool
    interval_seconds: int
    next_run_at: datetime
    last_run_at: datetime | None
    last_status: str | None
    last_detail: str | None
    last_scan_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class ScheduleRunOutcome:
    """One claimed tick: what happened, safe to log and return."""

    schedule_id: uuid.UUID
    status: str
    detail: str = ""
    scan_id: uuid.UUID | None = None


class ScheduleService:
    """Business rules for the ``scan_schedule`` aggregate."""

    def __init__(self, session: AsyncSession, principal: UserAccount) -> None:
        self._principal = principal
        self._session = session
        self._repository = ScheduleRepository(session)

    async def create_schedule(
        self,
        *,
        target_id: uuid.UUID,
        scan_profile_code: str = "standard",
        interval_seconds: int = 86400,
    ) -> ScheduleDetails:
        """Create a schedule for an owned, visible target."""
        from src.domain.targets.target_service import TargetService

        _validate_interval(interval_seconds)
        target = await TargetService(self._session, self._principal).get_target(target_id)
        profile_id = await self._profile_id(scan_profile_code)
        now = datetime.now(UTC)
        schedule = ScanSchedule(
            id=uuid.uuid4(),
            owner_user_id=self._principal.id,
            target_id=target.id,
            scan_profile_id=profile_id,
            enabled=True,
            interval_seconds=interval_seconds,
            next_run_at=now + timedelta(seconds=interval_seconds),
            created_at=now,
            updated_at=now,
        )
        self._repository.add(schedule)
        await self._repository.flush()
        await AuditService(self._session).record(
            action_code=ACTION_SCHEDULE_CREATED,
            entity_type="scan_schedule",
            entity_id=schedule.id,
            metadata_json={
                "targetId": str(target.id),
                "scanProfile": scan_profile_code,
                "intervalSeconds": interval_seconds,
            },
            actor_user_id=self._principal.id,
            occurred_at=now,
        )
        return await self._details(schedule)

    async def get_schedule(self, schedule_id: uuid.UUID) -> ScheduleDetails:
        """Fetch one owned schedule (foreign ids are 404, never 403)."""
        schedule = await self._get_owned_schedule(schedule_id)
        return await self._details(schedule)

    async def list_schedules(self) -> list[ScheduleDetails]:
        """All schedules owned by the principal, oldest first."""
        rows = await self._repository.list_for_owner(self._principal.id)
        return [await self._details(row) for row in rows]

    async def update_schedule(
        self,
        schedule_id: uuid.UUID,
        *,
        enabled: bool | None = None,
        interval_seconds: int | None = None,
        scan_profile_code: str | None = None,
    ) -> ScheduleDetails:
        """Mutate an owned schedule (any subset of fields)."""
        schedule = await self._get_owned_schedule(schedule_id)
        changes: dict[str, object] = {}
        if enabled is not None and enabled != schedule.enabled:
            schedule.enabled = enabled
            changes["enabled"] = enabled
        if interval_seconds is not None and interval_seconds != schedule.interval_seconds:
            _validate_interval(interval_seconds)
            schedule.interval_seconds = interval_seconds
            changes["intervalSeconds"] = interval_seconds
        if scan_profile_code is not None:
            profile_id = await self._profile_id(scan_profile_code)
            if profile_id != schedule.scan_profile_id:
                schedule.scan_profile_id = profile_id
                changes["scanProfile"] = scan_profile_code
        await self._repository.flush()
        if changes:
            await AuditService(self._session).record(
                action_code=ACTION_SCHEDULE_UPDATED,
                entity_type="scan_schedule",
                entity_id=schedule.id,
                metadata_json=changes,
                actor_user_id=self._principal.id,
            )
        return await self._details(schedule)

    async def delete_schedule(self, schedule_id: uuid.UUID) -> None:
        """Delete an owned schedule (hard delete: configuration, not evidence)."""
        schedule = await self._get_owned_schedule(schedule_id)
        await self._session.delete(schedule)
        await self._session.flush()
        await AuditService(self._session).record(
            action_code=ACTION_SCHEDULE_DELETED,
            entity_type="scan_schedule",
            entity_id=schedule_id,
            actor_user_id=self._principal.id,
        )

    async def trigger_schedule(self, schedule_id: uuid.UUID) -> ScheduleRunOutcome:
        """Run one owned schedule immediately (operator action).

        Resets ``next_run_at`` from now (like a claim) and executes one
        tick through the same gated path as automatic runs. Disabled
        schedules refuse without touching state.
        """
        schedule = await self._get_owned_schedule(schedule_id)
        if not schedule.enabled:
            return ScheduleRunOutcome(
                schedule_id=schedule.id, status="skipped_disabled", detail="schedule is disabled"
            )
        now = datetime.now(UTC)
        schedule.next_run_at = now + timedelta(seconds=schedule.interval_seconds)
        schedule.last_run_at = now
        await self._repository.flush()
        return await self._execute(schedule, self._principal, now)

    async def run_due_schedules(self, now: datetime) -> list[ScheduleRunOutcome]:
        """Claim and execute every due tick (worker entry point).

        Each schedule is claimed atomically before execution, so a racing
        worker or a restart after commit cannot double-run a tick, and a
        crash before commit leaves the tick due (idempotent retry).
        Per-tick failures are recorded on the schedule; they never abort
        the remaining ticks. The caller owns the commit.
        """
        return await run_due_schedules(self._session, now)

    # ------------------------------------------------------------------ #
    # Internals                                                           #
    # ------------------------------------------------------------------ #

    async def _execute_for_owner(self, schedule: ScanSchedule, now: datetime) -> ScheduleRunOutcome:
        """Resolve the schedule owner's principal, then execute gated."""
        return await execute_for_owner(self._session, schedule, now)

    async def _execute(
        self, schedule: ScanSchedule, principal: UserAccount, now: datetime
    ) -> ScheduleRunOutcome:
        """One gated execution: visibility, archive, attestation, limits."""
        return await execute_schedule(self._session, schedule, principal, now)

    async def _record_run(
        self, schedule: ScanSchedule, outcome: ScheduleRunOutcome, now: datetime
    ) -> None:
        await record_run(self._session, schedule, outcome, now)

    async def _get_owned_schedule(self, schedule_id: uuid.UUID) -> ScanSchedule:
        schedule = await self._repository.get_for_owner(schedule_id, self._principal.id)
        if schedule is None:
            raise NotFoundError()
        return schedule

    async def _profile_id(self, code: str) -> int:
        from src.infrastructure.database.repositories.scan_repository import _profile_id

        try:
            return await _profile_id(self._session, code)
        except LookupError as exc:
            raise InvalidScheduleError(f"unknown scan profile: {code!r}") from exc

    async def _profile_code_for_id(self, profile_id: int) -> str:
        from src.infrastructure.database.repositories.scan_repository import _profile_code

        return await _profile_code(self._session, profile_id)

    async def _details(self, schedule: ScanSchedule) -> ScheduleDetails:
        return ScheduleDetails(
            id=schedule.id,
            owner_user_id=schedule.owner_user_id,
            target_id=schedule.target_id,
            scan_profile_code=await self._profile_code_for_id(schedule.scan_profile_id),
            enabled=bool(schedule.enabled),
            interval_seconds=schedule.interval_seconds,
            next_run_at=schedule.next_run_at,
            last_run_at=schedule.last_run_at,
            last_status=schedule.last_status,
            last_detail=schedule.last_detail,
            last_scan_id=schedule.last_scan_id,
            created_at=schedule.created_at,
            updated_at=schedule.updated_at,
        )


def _validate_interval(interval_seconds: object) -> None:
    """Schedule cadence bounds (10 minutes to 30 days)."""
    if (
        not isinstance(interval_seconds, int)
        or isinstance(interval_seconds, bool)
        or not MIN_INTERVAL_SECONDS <= interval_seconds <= MAX_INTERVAL_SECONDS
    ):
        raise InvalidScheduleError(
            f"interval_seconds must be an integer between {MIN_INTERVAL_SECONDS} "
            f"and {MAX_INTERVAL_SECONDS}"
        )


async def run_due_schedules(session: AsyncSession, now: datetime) -> list[ScheduleRunOutcome]:
    """Worker entry point: claim and execute every due tick (no principal).

    Owner principals resolve per schedule from the user table, so the
    worker needs no ambient identity. The caller owns the commit; a crash
    before commit leaves claimed ticks due (idempotent retry), while a
    crash after commit never re-runs them (claims already advanced).
    """
    repository = ScheduleRepository(session)
    outcomes: list[ScheduleRunOutcome] = []
    for schedule in await repository.due_schedules(now):
        claimed = await repository.claim_due_schedule(
            schedule.id, now=now, interval_seconds=schedule.interval_seconds
        )
        if not claimed:
            continue  # lost the race: another worker owns this tick
        outcomes.append(await execute_for_owner(session, schedule, now))
    return outcomes


async def execute_for_owner(
    session: AsyncSession, schedule: ScanSchedule, now: datetime
) -> ScheduleRunOutcome:
    """Resolve the schedule owner's principal, then execute gated."""
    from src.domain.users.user_service import UserAccount
    from src.infrastructure.database.repositories.user_repository import UserRepository

    user = await UserRepository(session).get_by_id(schedule.owner_user_id)
    if user is None or not user.is_active:
        outcome = ScheduleRunOutcome(
            schedule_id=schedule.id,
            status=STATUS_SKIPPED_OWNER_INACTIVE,
            detail="owner account missing or inactive",
        )
        await record_run(session, schedule, outcome, now)
        return outcome
    principal = UserAccount(id=user.id, email=user.email, created_at=user.created_at)
    return await execute_schedule(session, schedule, principal, now)


async def execute_schedule(
    session: AsyncSession,
    schedule: ScanSchedule,
    principal: UserAccount,
    now: datetime,
) -> ScheduleRunOutcome:
    """One gated execution: visibility, archive, attestation, limits."""
    from src.domain.scans.scan_service import ScanService
    from src.domain.targets.target_service import TargetService
    from src.infrastructure.database.repositories.scan_repository import _profile_code

    try:
        target = await TargetService(session, principal).get_target(schedule.target_id)
    except NotFoundError:
        outcome = ScheduleRunOutcome(
            schedule_id=schedule.id,
            status=STATUS_SKIPPED_TARGET_UNAVAILABLE,
            detail="target missing, archived away, or no longer visible",
        )
        await record_run(session, schedule, outcome, now)
        return outcome
    if target.is_archived:
        outcome = ScheduleRunOutcome(
            schedule_id=schedule.id,
            status=STATUS_SKIPPED_TARGET_ARCHIVED,
            detail="target is archived",
        )
        await record_run(session, schedule, outcome, now)
        return outcome
    try:
        profile_code = await _profile_code(session, schedule.scan_profile_id)
        details = await ScanService(session, principal).create_scan(
            target_id=target.id, scan_profile_code=profile_code
        )
    except AttestationNotConfirmedError:
        outcome = ScheduleRunOutcome(
            schedule_id=schedule.id,
            status=STATUS_BLOCKED_NO_ATTESTATION,
            detail="no active authorization attestation; tick blocked, nothing created",
        )
        await record_run(session, schedule, outcome, now)
        return outcome
    except (ScanRateLimitedError, ScanQueueFullError) as exc:
        outcome = ScheduleRunOutcome(
            schedule_id=schedule.id,
            status=STATUS_SKIPPED_RATE_LIMITED,
            detail=type(exc).__name__,
        )
        await record_run(session, schedule, outcome, now)
        return outcome
    except Exception as exc:  # noqa: BLE001 - recorded, never propagated past the tick
        outcome = ScheduleRunOutcome(
            schedule_id=schedule.id,
            status=STATUS_FAILED,
            detail=type(exc).__name__,
        )
        await record_run(session, schedule, outcome, now)
        return outcome
    outcome = ScheduleRunOutcome(
        schedule_id=schedule.id,
        status=STATUS_SCAN_CREATED,
        scan_id=details.id,
    )
    await record_run(session, schedule, outcome, now)
    return outcome


async def record_run(
    session: AsyncSession,
    schedule: ScanSchedule,
    outcome: ScheduleRunOutcome,
    now: datetime,
) -> None:
    """Stamp a tick outcome onto its schedule row (flush, caller commits).

    Every tick — created, blocked, skipped, or failed — also appends one
    ``SCHEDULE_RUN`` audit entry carrying the owner id (so the run stays
    visible to its owner under the fail-closed audit scoping), the outcome
    status, and the created scan id when there is one. The audit row joins
    the caller's transaction: a crash before commit leaves the tick due
    with no audit row (idempotent retry re-runs it); a crash after commit
    never re-runs it.
    """
    schedule.last_run_at = now
    schedule.last_status = outcome.status
    schedule.last_detail = outcome.detail[:500] if outcome.detail else None
    schedule.last_scan_id = outcome.scan_id
    await session.flush()
    await AuditService(session).record(
        action_code=ACTION_SCHEDULE_RUN,
        entity_type="scan_schedule",
        entity_id=schedule.id,
        metadata_json={
            "status": outcome.status,
            "detail": outcome.detail[:500] if outcome.detail else None,
            "scanId": str(outcome.scan_id) if outcome.scan_id else None,
            "targetId": str(schedule.target_id),
            "ownerUserId": str(schedule.owner_user_id),
        },
        actor_user_id=schedule.owner_user_id,
        occurred_at=now,
    )
