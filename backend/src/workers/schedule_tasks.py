"""Scheduled-scan ticks (Celery entry point for due schedules).

Operated by Celery Beat (or any operator cron) invoking the
``run_due_schedules_task`` by name on an interval:

    celery -A src.workers.celery_app beat --loglevel=info

Each tick claims due schedules atomically through
``run_due_schedules`` and executes them through the normal
scan-creation path, then enqueues created scans for execution.
Idempotency comes from the claim (a retry or restart re-evaluates due
state; won ticks never re-run because ``next_run_at`` already advanced
in the same transaction as the created scan).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from src.workers.celery_app import celery_app
from src.workers.scan_tasks import ScanJobTask, enqueue_scan


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    base=ScanJobTask,
    name="src.workers.schedule_tasks.run_due_schedules_task",
    acks_late=False,
)
def run_due_schedules_task(
    self: ScanJobTask,  # noqa: ARG001 - required by Celery bind=True
) -> dict[str, object]:
    """Claim due schedule ticks and execute them through scan creation."""
    outcomes = asyncio.run(_run_due_tick())
    return {"status": "completed", "outcomes": outcomes}


async def _run_due_tick() -> list[dict[str, object]]:
    """One tick: claim due schedules, execute, enqueue created scans."""
    from src.domain.schedules.schedule_service import run_due_schedules
    from src.infrastructure.database.connection import get_async_sessionmaker

    sessionmaker = get_async_sessionmaker()
    async with sessionmaker() as session:
        outcomes = await run_due_schedules(session, datetime.now(UTC))
        serializable: list[dict[str, object]] = []
        for outcome in outcomes:
            if outcome.status == "scan_created" and outcome.scan_id is not None:
                enqueue_scan(outcome.scan_id)
            serializable.append(
                {
                    "schedule_id": str(outcome.schedule_id),
                    "status": outcome.status,
                    "detail": outcome.detail,
                    "scan_id": str(outcome.scan_id) if outcome.scan_id else None,
                }
            )
        await session.commit()
        return serializable
