"""Celery task definitions for the ``scan`` queue.

These tasks are the worker-side seam for the secure scan execution chain
(SRS Ch6 §6). The task body is intentionally thin: it owns its own
database session, opens its own transaction, and delegates to the
domain-level :class:`ScanService` so all the policy, attestation,
lifecycle, and persistence rules live in exactly one place.

The API process NEVER imports this module; it dispatches by Celery task
name via ``celery_app.send_task`` (or by the convenient ``enqueue_scan``
helper exported here for in-process callers that have already loaded the
app). This keeps the worker's heavyweight scanning imports — sandbox,
Docker, httpx — out of the API request path.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

from celery import Task

from src.config.settings import get_settings
from src.domain.errors import (
    AttestationNotConfirmedError,
    ScannerExecutionBlockedError,
    TargetUnresolvedError,
)
from src.infrastructure.database.connection import get_async_sessionmaker
from src.infrastructure.logging.logger import get_logger
from src.workers.celery_app import celery_app

logger = get_logger(__name__)


def enqueue_scan(scan_id: uuid.UUID) -> str:
    """Dispatch a scan for asynchronous execution (API-side helper).

    Returns the Celery task id so the caller can correlate logs/metrics.
    Respects the ``scanner_execution_enabled`` gate: when the operator
    has not flipped the switch, the scan is left in ``QUEUED`` and no
    task is enqueued. This mirrors the FastAPI ``BackgroundTasks`` path
    so a deployment that has not yet adopted the worker tier behaves
    identically.
    """
    settings = get_settings()
    if not settings.scanner_execution_enabled:
        logger.info(
            "scan_enqueue_skipped_execution_disabled",
            scan_id=str(scan_id),
        )
        return ""
    async_result = celery_app.send_task(
        "src.workers.scan_tasks.execute_scan_job_task",
        kwargs={"scan_id": str(scan_id)},
        queue="scan",
    )
    task_id: str = str(getattr(async_result, "id", "") or "")
    return task_id


class ScanJobTask(Task):  # type: ignore[misc]
    """Per-task hooks for retry/idempotency bookkeeping.

    Celery's retry is intentionally NOT configured: scan execution is
    long, stateful, and the domain state machine already exposes the
    truthful outcome. An unexpected exception in the worker becomes a
    ``REJECTED`` scan with an error message; a transient infrastructure
    blip is surfaced the same way rather than silently re-running the
    secure chain twice.
    """

    name = "src.workers.scan_tasks.execute_scan_job_task"

    def on_failure(
        self,
        exc: BaseException,
        task_id: str,
        args: tuple[object, ...],
        kwargs: dict[str, object],
        einfo: Any,  # noqa: ARG002 - required by Celery signature
    ) -> None:
        scan_id = kwargs.get("scan_id") or (args[0] if args else None)
        logger.exception(
            "scan_job_task_failed",
            scan_id=str(scan_id) if scan_id else None,
            task_id=task_id,
            error_type=type(exc).__name__,
            error_message=str(exc)[:500],
        )


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    base=ScanJobTask,
    name="src.workers.scan_tasks.execute_scan_job_task",
    acks_late=False,
)
def execute_scan_job_task(
    self: ScanJobTask,  # noqa: ARG001 - required by Celery bind=True
    scan_id: str,
) -> dict[str, str]:
    """Run the authorized secure chain for one QUEUED scan.

    The Celery task is the canonical worker entry point. It mirrors
    ``ScanService.build_background_job`` so the domain orchestration
    remains the single source of truth for the execution chain.

    The execution gate is enforced here as well as at enqueue time: a task
    that was queued while execution was enabled but runs after the
    operator disabled it is REJECTED instead of executed, so the gate is a
    true kill-switch (incident response, misconfigured worker).
    """
    logger.info("scan_job_task_started", scan_id=scan_id)
    scan_uuid = uuid.UUID(scan_id)
    if not get_settings().scanner_execution_enabled:
        logger.info("scan_job_task_skipped_execution_disabled", scan_id=scan_id)
        asyncio.run(_mark_scan_rejected(scan_uuid, "execution_disabled"))
        return {"scan_id": scan_id, "status": "rejected"}
    try:
        asyncio.run(_run_scan_job(scan_uuid))
    except (AttestationNotConfirmedError, ScannerExecutionBlockedError, TargetUnresolvedError):
        # Honest expected outcomes: the domain service has already moved
        # the scan to its terminal status and recorded the audit event.
        logger.info("scan_job_task_expected_failure", scan_id=scan_id)
    except Exception as exc:  # noqa: BLE001 - map to terminal scan state
        logger.exception("scan_job_task_unexpected_failure", scan_id=scan_id, error=str(exc))
        asyncio.run(_mark_scan_rejected(scan_uuid, type(exc).__name__))
    finally:
        logger.info("scan_job_task_finished", scan_id=scan_id)
    return {"scan_id": scan_id, "status": "completed"}


async def _run_scan_job(scan_id: uuid.UUID) -> None:
    """Open a fresh session, run the secure chain, commit per stage."""
    from src.domain.scans.scan_service import ScanService
    from src.domain.webhooks.dispatch import fanout_events
    from src.infrastructure.ai.factory import maybe_evidence_analyzer
    from src.infrastructure.database.repositories.scan_repository import ScanRepository

    sessionmaker = get_async_sessionmaker()
    async with sessionmaker() as session:
        service = ScanService(session, principal=None)
        events = await service.execute_scan_job(scan_id, ai_analyzer=maybe_evidence_analyzer())
        if events:
            scan = await ScanRepository(session).get_by_id(scan_id)
            if scan is not None:
                delivery_ids = await fanout_events(session, scan.initiated_by_user_id, events)
                await session.commit()
                for delivery_id in delivery_ids:
                    celery_app.send_task(
                        "src.workers.webhook_tasks.deliver_webhook_task",
                        kwargs={"delivery_id": str(delivery_id)},
                        queue="scan",
                    )


async def _mark_scan_rejected(scan_id: uuid.UUID, reason: str) -> None:
    """Move a stuck scan to REJECTED when the worker cannot recover.

    A worker failure may occur before the scan is claimed (QUEUED), right
    after the claim (RUNNING), or between the stage commits of
    ``execute_scan_job`` (SCAN_COMPLETE, PARTIALLY_COMPLETE, AI_ANALYSIS).
    This implementation tries every non-terminal post-claim state in
    pipeline order and is a no-op if the scan is already terminal
    (REPORT_READY*, REJECTED, CANCELLED), so the worker remains idempotent
    on retry.
    """
    from datetime import UTC, datetime

    from sqlalchemy import select

    from src.config.constants import (
        ENGINE_HEADERS,
        SCAN_STATUS_AI_ANALYSIS,
        SCAN_STATUS_PARTIALLY_COMPLETE,
        SCAN_STATUS_QUEUED,
        SCAN_STATUS_REJECTED,
        SCAN_STATUS_RUNNING,
        SCAN_STATUS_SCAN_COMPLETE,
    )
    from src.domain.audit.audit_service import ACTION_SCAN_STATE_TRANSITION, AuditService
    from src.infrastructure.database.models import Scan, ScanEngine
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
        ScanRepository,
    )

    sessionmaker = get_async_sessionmaker()
    async with sessionmaker() as session:
        repository = ScanRepository(session)
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        status_ids = await repository.status_ids_by_code()

        # Try the post-claim states first in pipeline order (the failure
        # paths that used to strand scans), then fall back to the pre-claim
        # QUEUED state so the original worker gate is preserved exactly.
        # If none matches, the scan is already terminal or in another
        # non-terminal state managed by the domain path; the optimistic
        # guard makes this naturally idempotent on retry.
        candidate_attempts: list[tuple[str, int]] = [
            (SCAN_STATUS_RUNNING, status_ids[SCAN_STATUS_RUNNING]),
            (SCAN_STATUS_SCAN_COMPLETE, status_ids[SCAN_STATUS_SCAN_COMPLETE]),
            (SCAN_STATUS_PARTIALLY_COMPLETE, status_ids[SCAN_STATUS_PARTIALLY_COMPLETE]),
            (SCAN_STATUS_AI_ANALYSIS, status_ids[SCAN_STATUS_AI_ANALYSIS]),
            (SCAN_STATUS_QUEUED, status_ids[SCAN_STATUS_QUEUED]),
        ]

        claimed_from_code: str | None = None
        for from_code, from_status_id in candidate_attempts:
            moved = await repository.try_transition(
                scan.id,
                from_status_id=from_status_id,
                to_status_id=status_ids[SCAN_STATUS_REJECTED],
                set_completed_at=datetime.now(UTC),
            )
            if moved:
                claimed_from_code = from_code
                break

        if claimed_from_code is not None:
            engine_id_row = (
                await session.execute(
                    select(ScanEngine.id).where(ScanEngine.code == ENGINE_HEADERS)
                )
            ).first()
            if engine_id_row is not None:
                executions = ScanEngineExecutionRepository(session)
                execution_row = await executions.create(
                    scan_id=scan.id,
                    scan_engine_id=int(engine_id_row[0]),
                    tool_version_snapshot="worker-unknown",
                    status="FAILED",
                )
                await executions.mark(
                    execution_row.id,
                    status="FAILED",
                    completed_at=datetime.now(UTC),
                    error_message=reason[:500],
                )
            await AuditService(session).record(
                action_code=ACTION_SCAN_STATE_TRANSITION,
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": claimed_from_code,
                    "to": SCAN_STATUS_REJECTED,
                    "reason": f"worker_crashed:{reason}",
                    "ownerUserId": str(scan.initiated_by_user_id),
                },
            )
        await session.commit()


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    base=ScanJobTask,
    name="src.workers.scan_tasks.reap_stale_running_scans_task",
    acks_late=False,
)
def reap_stale_running_scans_task(
    self: ScanJobTask,  # noqa: ARG001 - required by Celery bind=True
) -> dict[str, object]:
    """Beat-driven reaper for hard worker losses (SIGKILL/OOM/eviction).

    Those paths run no Python handler, so without this the scan row
    would strand in RUNNING and permanently consume quota. Runs every
    few minutes; each execution only touches rows older than twice the
    task time limit, and the conditional transition keeps it safe
    against a still-running worker racing the reaper.
    """
    return asyncio.run(_reap_stale_running_scans())


async def _reap_stale_running_scans() -> dict[str, object]:
    """Own session, reap, commit (mirrors the scan-job seam)."""
    from src.domain.scans.scan_service import ScanService

    sessionmaker = get_async_sessionmaker()
    async with sessionmaker() as session:
        reaped = await ScanService(session, principal=None).reap_stale_running_scans()
        await session.commit()
        logger.info("stale_running_scans_reaped", reaped=reaped)
        return {"reaped": reaped}


__all__ = ["celery_app", "enqueue_scan", "execute_scan_job_task"]
