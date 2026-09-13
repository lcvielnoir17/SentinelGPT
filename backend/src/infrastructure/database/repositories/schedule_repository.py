"""Scan schedule repository: persistence access for schedules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from src.infrastructure.database.models import ScanSchedule

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


class ScheduleRepository:
    """Data-access boundary for the ``scan_schedule`` aggregate."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, schedule: ScanSchedule) -> None:
        """Stage a new schedule row; committed by the caller."""
        self._session.add(schedule)

    async def flush(self) -> None:
        await self._session.flush()

    async def get_for_owner(
        self, schedule_id: uuid.UUID, owner_id: uuid.UUID
    ) -> ScanSchedule | None:
        """Fetch one schedule visible to the owner (None covers foreign)."""
        stmt = select(ScanSchedule).where(
            ScanSchedule.id == schedule_id,
            ScanSchedule.owner_user_id == owner_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_owner(self, owner_id: uuid.UUID) -> list[ScanSchedule]:
        """All schedules owned by the user, oldest first (stable order)."""
        stmt = (
            select(ScanSchedule)
            .where(ScanSchedule.owner_user_id == owner_id)
            .order_by(ScanSchedule.created_at.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def due_schedules(self, now: datetime, *, limit: int = 100) -> list[ScanSchedule]:
        """Enabled schedules whose next run is due, earliest first."""
        stmt = (
            select(ScanSchedule)
            .where(ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at <= now)
            .order_by(ScanSchedule.next_run_at.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def claim_due_schedule(
        self, schedule_id: uuid.UUID, *, now: datetime, interval_seconds: int
    ) -> bool:
        """Atomically claim one due tick (the duplicate-execution guard).

        Advances ``next_run_at`` from now (never from the stale value, so
        downtime never triggers catch-up storms) only when the row is
        still enabled and due. Returns True exactly when this caller won
        the tick: a racing worker blocks on the row lock, then observes
        the advanced ``next_run_at`` and loses (False).
        """
        from datetime import timedelta

        result = await self._session.execute(
            update(ScanSchedule)
            .where(
                ScanSchedule.id == schedule_id,
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at <= now,
            )
            .values(
                next_run_at=now + timedelta(seconds=interval_seconds),
                last_run_at=now,
            )
        )
        return int(getattr(result, "rowcount", 0) or 0) == 1
