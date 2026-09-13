"""Webhook domain errors mapped by the centralized error handlers."""

from __future__ import annotations

from src.domain.errors import DomainError, FeatureDisabledError


class InvalidWebhookError(DomainError):
    """Webhook parameters failed validation (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid webhook parameters."


class WebhooksNotConfiguredError(FeatureDisabledError):
    """WEBHOOK_SECRET_KEY is absent: webhook creation is disabled (503)."""

    def __init__(self) -> None:
        super().__init__("Webhook delivery is not configured on this deployment.")


__all__ = ["InvalidWebhookError", "WebhooksNotConfiguredError"]
