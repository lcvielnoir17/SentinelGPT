"""Webhook delivery tasks (retry with backoff, idempotent ledger).

``deliver_webhook_task`` owns one delivery row to terminal state:
pending → sent, pending → failed (terminal), or pending → pending with
a later ``next_retry_at`` via Celery retry. Re-entry is always safe:
sent/cancelled/failed rows are no-ops, and a missing row (webhook
deleted mid-flight, deliveries cascade) is a no-op, never an error.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from src.infrastructure.logging.logger import get_logger
from src.workers.celery_app import celery_app
from src.workers.scan_tasks import ScanJobTask

logger = get_logger(__name__)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

MAX_ATTEMPTS = 4
RETRY_DELAYS_SECONDS = (60, 300, 900)


@celery_app.task(  # type: ignore[untyped-decorator]
    bind=True,
    base=ScanJobTask,
    name="src.workers.webhook_tasks.deliver_webhook_task",
    acks_late=False,
)
def deliver_webhook_task(
    self: ScanJobTask,  # noqa: ARG001 - required by Celery bind=True
    delivery_id: str,
) -> dict[str, object]:
    """Deliver one ledger row to its webhook (or record the outcome)."""
    return asyncio.run(_deliver(delivery_id, _retry_later))


async def _retry_later(delivery_id: str, countdown: int) -> None:
    deliver_webhook_task.apply_async(args=[delivery_id], countdown=countdown)


async def _deliver(
    delivery_id: str, retry: Callable[[str, int], Awaitable[None]]
) -> dict[str, object]:
    """State machine: pending → sent | failed | scheduled-retry.

    Unexpected worker faults (decrypt/send raising outside the reviewed
    outcome contract, database blips) never strand a row in ``pending``:
    the tick maps to terminal ``failed`` with an honest error so the
    ledger stays the truth and a retry storm can never build.
    """
    try:
        row_id = uuid.UUID(delivery_id)
    except ValueError:
        return {"delivery_id": delivery_id, "status": "ignored"}
    from src.infrastructure.database.connection import get_async_sessionmaker
    from src.infrastructure.database.repositories.webhook_repository import (
        WebhookRepository,
    )

    sessionmaker = get_async_sessionmaker()
    async with sessionmaker() as session:
        repository = WebhookRepository(session)
        try:
            return await _deliver_attempt(session, repository, row_id, delivery_id, retry)
        except Exception as exc:  # noqa: BLE001 - terminal honesty, never strand pending
            try:
                row = await repository.get_delivery(row_id)
                if row is not None and row.status in ("pending", "sending"):
                    row.status = "failed"
                    row.last_error = f"worker_error:{type(exc).__name__}"[:500]
                    await session.commit()
            except Exception:
                logger.exception("webhook_delivery_terminal_mark_failed", extra={})
            return {"delivery_id": delivery_id, "status": "failed"}


async def _deliver_attempt(
    session: Any,
    repository: Any,
    row_id: uuid.UUID,
    delivery_id: str,
    retry: Callable[[str, int], Awaitable[None]],
) -> dict[str, object]:
    """One delivery attempt against a live session (raises on worker fault)."""
    from src.infrastructure.database.models import Webhook
    from src.infrastructure.notifications.sender import send_delivery
    from src.infrastructure.secrets.secret_box import (
        WebhookSecretsNotConfiguredError,
        decrypt_secret,
    )

    row = await repository.claim_delivery(row_id)
    if row is None:
        return {"delivery_id": delivery_id, "status": "ignored"}
    if row.next_retry_at is not None and row.next_retry_at > datetime.now(UTC):
        await repository.release_claim(row_id)
        await session.commit()
        return {"delivery_id": delivery_id, "status": "not-due"}

    webhook = await session.get(Webhook, row.webhook_id)
    if webhook is None or not webhook.enabled:
        row.status = "cancelled"
        row.last_error = "webhook missing or disabled"
        await session.commit()
        return {"delivery_id": delivery_id, "status": "cancelled"}

    try:
        secret = decrypt_secret(webhook.secret_encrypted)
    except WebhookSecretsNotConfiguredError as exc:
        row.status = "failed"
        row.last_error = str(exc)[:500]
        await session.commit()
        return {"delivery_id": delivery_id, "status": "failed"}

    outcome = await send_delivery(
        url=webhook.url,
        secret=secret,
        event_id=row.event_id,
        payload=dict(row.event_payload or {}),
        timeout_seconds=webhook.timeout_seconds,
    )
    row.attempts = (row.attempts or 0) + 1
    if outcome.delivered:
        row.status = "sent"
        row.last_error = None
        await session.commit()
        return {"delivery_id": delivery_id, "status": "sent"}

    row.last_error = outcome.detail[:500]
    if outcome.retryable and row.attempts < MAX_ATTEMPTS:
        delay = RETRY_DELAYS_SECONDS[min(row.attempts - 1, len(RETRY_DELAYS_SECONDS) - 1)]
        row.next_retry_at = datetime.now(UTC) + timedelta(seconds=delay)
        row.status = "pending"
        await session.commit()
        await retry(delivery_id, delay)
        return {"delivery_id": delivery_id, "status": "retry-scheduled"}
    row.status = "failed"
    await session.commit()
    return {"delivery_id": delivery_id, "status": "failed"}
