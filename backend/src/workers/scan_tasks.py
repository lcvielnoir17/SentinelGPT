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
    """
    logger.info("scan_job_task_started", scan_id=scan_id)
    scan_uuid = uuid.UUID(scan_id)
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
    from src.infrastructure.ai.gemini_provider import GeminiEvidenceAnalyzer

    sessionmaker = get_async_sessionmaker()
    async with sessionmaker() as session:
        ai_analyzer: Any = None
        if get_settings().gemini_api_key:
            try:
                ai_analyzer = GeminiEvidenceAnalyzer.from_settings()
            except Exception:  # noqa: BLE001 - AI must degrade, never block scans
                ai_analyzer = None
        service = ScanService(session, principal=None)
        await service.execute_scan_job(scan_id, ai_analyzer=ai_analyzer)


async def _mark_scan_rejected(scan_id: uuid.UUID, reason: str) -> None:
    """Move a stuck scan to REJECTED when the worker cannot recover."""
    from datetime import UTC, datetime

    from sqlalchemy import select

    from src.config.constants import SCAN_STATUS_QUEUED, SCAN_STATUS_REJECTED
    from src.domain.audit.audit_service import AuditService
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
        claimed = await repository.try_transition(
            scan.id,
            from_status_id=status_ids[SCAN_STATUS_QUEUED],
            to_status_id=status_ids[SCAN_STATUS_REJECTED],
            set_completed_at=datetime.now(UTC),
        )
        if claimed:
            engine_id_row = (
                await session.execute(
                    select(ScanEngine.id).where(ScanEngine.code == "headers-analyzer")
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
                action_code="SCAN_STATE_TRANSITION",
                entity_type="scan",
                entity_id=scan.id,
                metadata_json={
                    "from": SCAN_STATUS_QUEUED,
                    "to": SCAN_STATUS_REJECTED,
                    "reason": f"worker_crashed:{reason}",
                },
            )
        await session.commit()


__all__ = ["celery_app", "enqueue_scan", "execute_scan_job_task"]
