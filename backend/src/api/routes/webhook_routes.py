"""Webhook subscription endpoints (event notifications).

The HMAC secret is returned exactly once, inside the 201 create
response. No other endpoint ever exposes it.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query, status
from pydantic import BaseModel, ConfigDict, Field

from src.api.dependencies import CurrentUser, SessionDep  # noqa: TC001 - FastAPI runtime
from src.domain.webhooks.webhook_service import WebhookDetails, WebhookService

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


class CreateWebhookRequest(BaseModel):
    """POST /webhooks request body."""

    url: str = Field(min_length=1, max_length=2000)
    events: list[str] = Field(min_length=1)
    timeout_seconds: int = Field(default=10, validation_alias="timeoutSeconds")


class UpdateWebhookRequest(BaseModel):
    """PATCH /webhooks/{id} body — any subset of mutable fields."""

    model_config = ConfigDict(extra="forbid")

    url: str | None = Field(default=None, max_length=2000)
    events: list[str] | None = None
    enabled: bool | None = None
    timeout_seconds: int | None = Field(default=None, validation_alias="timeoutSeconds")


class WebhookResponse(BaseModel):
    """Subscription representation (secret never included)."""

    id: uuid.UUID
    url: str
    events: list[str]
    enabled: bool
    timeout_seconds: int = Field(serialization_alias="timeoutSeconds")
    created_at: str = Field(serialization_alias="createdAt")


class CreatedWebhookResponse(WebhookResponse):
    """Create response: subscription plus the secret, shown exactly once."""

    secret: str = Field(description="Raw HMAC secret; shown once, never again")


class DeliveryResponse(BaseModel):
    """Delivery ledger row (operational visibility, no secrets)."""

    id: uuid.UUID
    webhook_id: uuid.UUID = Field(serialization_alias="webhookId")
    event_id: str = Field(serialization_alias="eventId")
    event_type: str = Field(serialization_alias="eventType")
    status: str
    attempts: int
    next_retry_at: str | None = Field(default=None, serialization_alias="nextRetryAt")
    last_error: str | None = Field(default=None, serialization_alias="lastError")
    created_at: str = Field(serialization_alias="createdAt")


def _to_response(details: WebhookDetails) -> WebhookResponse:
    return WebhookResponse(
        id=details.id,
        url=details.url,
        events=list(details.events),
        enabled=details.enabled,
        timeout_seconds=details.timeout_seconds,
        created_at=details.created_at.isoformat(),
    )


def _service(session: Any, current_user: Any) -> WebhookService:
    return WebhookService(session, current_user)


@router.post(
    "",
    response_model=CreatedWebhookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Subscribe a callback URL to domain events",
)
async def create_webhook(
    payload: CreateWebhookRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> CreatedWebhookResponse:
    """Create a subscription; the HMAC secret appears here exactly once."""
    created = await _service(session, current_user).create_webhook(
        url=payload.url,
        events=payload.events,
        timeout_seconds=payload.timeout_seconds,
    )
    response = _to_response(created.details)
    return CreatedWebhookResponse(**response.model_dump(), secret=created.secret)


@router.get("", response_model=list[WebhookResponse], summary="List owned webhooks")
async def list_webhooks(session: SessionDep, current_user: CurrentUser) -> list[WebhookResponse]:
    rows = await _service(session, current_user).list_webhooks()
    return [_to_response(row) for row in rows]


@router.get("/{webhook_id}", response_model=WebhookResponse, summary="Get webhook detail")
async def get_webhook(
    webhook_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> WebhookResponse:
    return _to_response(await _service(session, current_user).get_webhook(webhook_id))


@router.patch("/{webhook_id}", response_model=WebhookResponse, summary="Update a webhook")
async def update_webhook(
    webhook_id: uuid.UUID,
    payload: UpdateWebhookRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> WebhookResponse:
    details = await _service(session, current_user).update_webhook(
        webhook_id,
        url=payload.url,
        events=payload.events,
        enabled=payload.enabled,
        timeout_seconds=payload.timeout_seconds,
    )
    return _to_response(details)


@router.delete(
    "/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a webhook",
)
async def delete_webhook(
    webhook_id: uuid.UUID, session: SessionDep, current_user: CurrentUser
) -> None:
    await _service(session, current_user).delete_webhook(webhook_id)


@router.get(
    "/{webhook_id}/deliveries",
    response_model=list[DeliveryResponse],
    summary="List delivery attempts",
)
async def list_deliveries(
    webhook_id: uuid.UUID,
    session: SessionDep,
    current_user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DeliveryResponse]:
    from src.infrastructure.database.repositories.webhook_repository import (
        WebhookRepository,
    )

    service = _service(session, current_user)
    await service.get_webhook(webhook_id)  # ownership gate (404 for foreign)
    rows = await WebhookRepository(session).list_deliveries(webhook_id, limit=limit)
    return [
        DeliveryResponse(
            id=row.id,
            webhook_id=row.webhook_id,
            event_id=row.event_id,
            event_type=row.event_type,
            status=row.status,
            attempts=row.attempts or 0,
            next_retry_at=row.next_retry_at.isoformat() if row.next_retry_at else None,
            last_error=row.last_error,
            created_at=row.created_at.isoformat(),
        )
        for row in rows
    ]
