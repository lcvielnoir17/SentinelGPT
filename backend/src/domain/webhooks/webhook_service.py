"""Webhook subscriptions: CRUD over operator-owned callback endpoints."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.domain.audit.audit_service import AuditService
from src.domain.errors import NotFoundError
from src.domain.events.events import EVENT_TYPES
from src.domain.webhooks.errors import InvalidWebhookError, WebhooksNotConfiguredError
from src.infrastructure.database.models import Webhook
from src.infrastructure.database.repositories.webhook_repository import (
    WebhookRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount

ACTION_WEBHOOK_CREATED = "WEBHOOK_CREATED"
ACTION_WEBHOOK_UPDATED = "WEBHOOK_UPDATED"
ACTION_WEBHOOK_DELETED = "WEBHOOK_DELETED"

MIN_TIMEOUT_SECONDS = 5
MAX_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class WebhookDetails:
    """Framework-agnostic webhook entity (secret never included)."""

    id: uuid.UUID
    owner_user_id: uuid.UUID
    url: str
    events: tuple[str, ...]
    enabled: bool
    timeout_seconds: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class CreatedWebhook:
    """Create response: details plus the raw secret (shown exactly once)."""

    details: WebhookDetails
    secret: str


class WebhookService:
    """Business rules for webhook subscriptions."""

    def __init__(self, session: AsyncSession, principal: UserAccount) -> None:
        self._principal = principal
        self._session = session
        self._repository = WebhookRepository(session)

    async def create_webhook(
        self,
        *,
        url: str,
        events: list[str],
        timeout_seconds: int = 10,
    ) -> CreatedWebhook:
        """Subscribe an owned callback URL (secret returned exactly once)."""
        from src.infrastructure.network.webhook_target import (
            InvalidWebhookUrlError,
            validate_webhook_url,
        )
        from src.infrastructure.secrets.secret_box import (
            WebhookSecretsNotConfiguredError,
            decrypt_secret,
            encrypt_secret,
            generate_secret,
        )

        clean_events = _validate_events(events)
        _validate_timeout(timeout_seconds)
        try:
            validated = validate_webhook_url(url)
        except InvalidWebhookUrlError as exc:
            raise InvalidWebhookError(str(exc)) from exc
        try:
            secret = generate_secret()
            encrypted = encrypt_secret(secret)
            # Round-trip now: a misconfigured key must fail creation, not
            # the first delivery hours later.
            assert decrypt_secret(encrypted) == secret
        except WebhookSecretsNotConfiguredError as exc:
            raise WebhooksNotConfiguredError() from exc
        now = datetime.now(UTC)
        webhook = Webhook(
            id=uuid.uuid4(),
            owner_user_id=self._principal.id,
            url=validated.url,
            events=list(clean_events),
            secret_encrypted=encrypted,
            enabled=True,
            timeout_seconds=timeout_seconds,
            created_at=now,
            updated_at=now,
        )
        self._repository.add(webhook)
        await self._repository.flush()
        await AuditService(self._session).record(
            action_code=ACTION_WEBHOOK_CREATED,
            entity_type="webhook",
            entity_id=webhook.id,
            metadata_json={"urlHost": validated.host, "events": list(clean_events)},
            actor_user_id=self._principal.id,
            occurred_at=now,
        )
        return CreatedWebhook(details=_to_details(webhook), secret=secret)

    async def get_webhook(self, webhook_id: uuid.UUID) -> WebhookDetails:
        """Fetch one owned webhook (foreign ids are 404, never 403)."""
        return _to_details(await self._get_owned_webhook(webhook_id))

    async def list_webhooks(self) -> list[WebhookDetails]:
        """All webhooks owned by the principal, oldest first."""
        rows = await self._repository.list_for_owner(self._principal.id)
        return [_to_details(row) for row in rows]

    async def update_webhook(
        self,
        webhook_id: uuid.UUID,
        *,
        url: str | None = None,
        events: list[str] | None = None,
        enabled: bool | None = None,
        timeout_seconds: int | None = None,
    ) -> WebhookDetails:
        """Mutate an owned webhook (URL changes re-validate the destination).

        A URL change also cancels pending deliveries: rows ledgered against
        the old destination must never surprise the new one. Disabling
        cancels pending for the same reason.
        """
        from src.infrastructure.network.webhook_target import (
            InvalidWebhookUrlError,
            validate_webhook_url,
        )

        webhook = await self._get_owned_webhook(webhook_id)
        changes: dict[str, object] = {}
        if url is not None and url != webhook.url:
            try:
                validated = validate_webhook_url(url)
            except InvalidWebhookUrlError as exc:
                raise InvalidWebhookError(str(exc)) from exc
            webhook.url = validated.url
            changes["urlHost"] = validated.host
            await self._repository.cancel_pending(webhook.id)
        if events is not None:
            clean = _validate_events(events)
            if list(clean) != list(webhook.events or []):
                webhook.events = list(clean)
                changes["events"] = list(clean)
        if enabled is not None and enabled != webhook.enabled:
            webhook.enabled = enabled
            changes["enabled"] = enabled
            if not enabled:
                await self._repository.cancel_pending(webhook.id)
        if timeout_seconds is not None and timeout_seconds != webhook.timeout_seconds:
            _validate_timeout(timeout_seconds)
            webhook.timeout_seconds = timeout_seconds
            changes["timeoutSeconds"] = timeout_seconds
        await self._repository.flush()
        if changes:
            await AuditService(self._session).record(
                action_code=ACTION_WEBHOOK_UPDATED,
                entity_type="webhook",
                entity_id=webhook.id,
                metadata_json=changes,
                actor_user_id=self._principal.id,
            )
        return _to_details(webhook)

    async def delete_webhook(self, webhook_id: uuid.UUID) -> None:
        """Delete an owned webhook (deliveries cascade)."""
        webhook = await self._get_owned_webhook(webhook_id)
        await self._session.delete(webhook)
        await self._session.flush()
        await AuditService(self._session).record(
            action_code=ACTION_WEBHOOK_DELETED,
            entity_type="webhook",
            entity_id=webhook_id,
            actor_user_id=self._principal.id,
        )

    async def _get_owned_webhook(self, webhook_id: uuid.UUID) -> Webhook:
        webhook = await self._repository.get_for_owner(webhook_id, self._principal.id)
        if webhook is None:
            raise NotFoundError()
        return webhook


def _validate_events(events: object) -> tuple[str, ...]:
    if not isinstance(events, list) or not events:
        raise InvalidWebhookError("events must be a non-empty list of event types")
    clean = tuple(e for e in events if isinstance(e, str))
    if len(clean) != len(events) or not clean:
        raise InvalidWebhookError("events must be a non-empty list of event types")
    unknown = sorted(set(clean) - set(EVENT_TYPES))
    if unknown:
        raise InvalidWebhookError(f"unknown event types: {unknown}")
    return tuple(sorted(set(clean)))


def _validate_timeout(timeout_seconds: object) -> None:
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise InvalidWebhookError(
            f"timeout_seconds must be an integer between {MIN_TIMEOUT_SECONDS} "
            f"and {MAX_TIMEOUT_SECONDS}"
        )


def _to_details(webhook: Webhook) -> WebhookDetails:
    events = tuple(webhook.events or [])
    return WebhookDetails(
        id=webhook.id,
        owner_user_id=webhook.owner_user_id,
        url=webhook.url,
        events=events,
        enabled=bool(webhook.enabled),
        timeout_seconds=webhook.timeout_seconds,
        created_at=webhook.created_at,
        updated_at=webhook.updated_at,
    )


__all__ = [
    "WebhookService",
    "WebhookDetails",
    "CreatedWebhook",
    "ACTION_WEBHOOK_CREATED",
    "ACTION_WEBHOOK_UPDATED",
    "ACTION_WEBHOOK_DELETED",
]
