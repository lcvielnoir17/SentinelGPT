"""Event fanout: deterministic events to subscribed webhook ledgers.

Fanout runs after a unit of domain work commits its events (scan job,
remediation write): for every event, every enabled subscription of the
owning user whose event filter matches gets one ledger row. Duplicates
collapse on the (webhook, event) unique identity — retries, restarts,
and duplicate fanout invocations create no extra rows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.infrastructure.database.repositories.webhook_repository import (
    WebhookRepository,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.events.events import DomainEvent


def build_webhook_payload(event: DomainEvent) -> dict[str, Any]:
    """Safe receiver payload: identifiers and transition codes only.

    Deliberately excludes titles, evidence, cookies, remediation notes,
    and actor internals — receivers get what changed and where, never
    sensitive scan content.
    """
    payload: dict[str, Any] = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "occurred_at": event.occurred_at.isoformat(),
        "version": event.version,
    }
    if event.target_id is not None:
        payload["target_id"] = event.target_id
    if event.scan_id is not None:
        payload["scan_id"] = event.scan_id
    if event.fingerprint is not None:
        payload["fingerprint"] = event.fingerprint
    if event.transition is not None:
        payload["transition"] = event.transition
    severity = event.payload.get("severity")
    if isinstance(severity, str):
        payload["severity"] = severity
    return payload


async def fanout_events(
    session: AsyncSession,
    owner_id: uuid.UUID,
    events: list[DomainEvent],
) -> list[uuid.UUID]:
    """Ledger deliveries for matching subscriptions; returns new row ids.

    Each created row still needs dispatch (the caller enqueues delivery
    tasks). Rows are staged uncommitted — the caller owns the commit, so
    fanout participates in the surrounding transaction atomically.
    """
    if not events:
        return []
    repository = WebhookRepository(session)
    webhooks = await repository.list_enabled_for_owner(owner_id)
    created: list[uuid.UUID] = []
    for event in events:
        payload = build_webhook_payload(event)
        for webhook in webhooks:
            subscribed = webhook.events or []
            if event.event_type not in subscribed:
                continue
            row_id = await repository.record_delivery(
                webhook_id=webhook.id,
                event_id=event.event_id,
                event_type=event.event_type,
                event_payload=payload,
            )
            if row_id is not None:
                created.append(row_id)
    return created
