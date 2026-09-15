"""Webhook repository: subscriptions, deliveries, idempotent fanout."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select, update

from src.infrastructure.database.models import Webhook, WebhookDelivery

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession


class WebhookRepository:
    """Data-access boundary for webhooks and their delivery ledger."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def add(self, webhook: Webhook) -> None:
        """Stage a new webhook row; committed by the caller."""
        self._session.add(webhook)

    async def flush(self) -> None:
        await self._session.flush()

    async def get_for_owner(self, webhook_id: uuid.UUID, owner_id: uuid.UUID) -> Webhook | None:
        """Fetch one webhook visible to the owner (None covers foreign)."""
        stmt = select(Webhook).where(
            Webhook.id == webhook_id,
            Webhook.owner_user_id == owner_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_owner(self, owner_id: uuid.UUID) -> list[Webhook]:
        """All webhooks owned by the user, oldest first (stable order)."""
        stmt = (
            select(Webhook)
            .where(Webhook.owner_user_id == owner_id)
            .order_by(Webhook.created_at.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_enabled_for_owner(self, owner_id: uuid.UUID) -> list[Webhook]:
        """Enabled subscriptions only (fanout input)."""
        stmt = (
            select(Webhook)
            .where(Webhook.owner_user_id == owner_id, Webhook.enabled.is_(True))
            .order_by(Webhook.created_at.asc())
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def cancel_pending(self, webhook_id: uuid.UUID) -> None:
        """Cancel pending deliveries (disable must not send surprises)."""
        await self._session.execute(
            update(WebhookDelivery)
            .where(
                WebhookDelivery.webhook_id == webhook_id,
                WebhookDelivery.status == "pending",
            )
            .values(status="cancelled")
        )

    async def get_delivery(self, delivery_id: uuid.UUID) -> WebhookDelivery | None:
        """Fetch one delivery row by id (fanout/worker only)."""
        return await self._session.get(WebhookDelivery, delivery_id)

    async def claim_delivery(self, delivery_id: uuid.UUID) -> WebhookDelivery | None:
        """Atomically claim a pending delivery for this worker (or None).

        The conditional UPDATE is the concurrency gate: exactly one
        worker moves pending → sending, so concurrent duplicate task
        executions cannot both reach the external POST. Callers must
        settle the claim (sent/failed/pending) on every path.
        """
        result = await self._session.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == delivery_id, WebhookDelivery.status == "pending")
            .values(status="sending")
        )
        if getattr(result, "rowcount", 0) != 1:
            return None
        return await self._session.get(WebhookDelivery, delivery_id)

    async def release_claim(self, delivery_id: uuid.UUID, *, to_status: str = "pending") -> None:
        """Return a claimed (sending) row to a queued status (retry/not-due)."""
        await self._session.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == delivery_id, WebhookDelivery.status == "sending")
            .values(status=to_status)
        )

    async def list_deliveries(self, webhook_id: uuid.UUID, *, limit: int) -> list[WebhookDelivery]:
        """Deliveries for one webhook, newest first (bounded)."""
        stmt = (
            select(WebhookDelivery)
            .where(WebhookDelivery.webhook_id == webhook_id)
            .order_by(WebhookDelivery.created_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def record_delivery(
        self,
        *,
        webhook_id: uuid.UUID,
        event_id: str,
        event_type: str,
        event_payload: dict[str, Any],
    ) -> uuid.UUID | None:
        """Ledger one delivery; None when the (webhook, event) pair exists.

        The unique constraint is the duplicate-delivery guard; a racing
        fanout loses here instead of double-sending. The insert runs in a
        SAVEPOINT so a duplicate rolls back only itself, never sibling
        deliveries staged in the same transaction. The flushed row id is
        returned for dispatch (server-populated via RETURNING).
        """
        from sqlalchemy.exc import IntegrityError

        try:
            async with self._session.begin_nested():
                row = WebhookDelivery(
                    webhook_id=webhook_id,
                    event_id=event_id,
                    event_type=event_type,
                    status="pending",
                    attempts=0,
                    event_payload=dict(event_payload),
                )
                self._session.add(row)
                await self._session.flush()
                return row.id
        except IntegrityError:
            return None
