"""MFA domain errors mapped by the centralized error handlers."""

from __future__ import annotations

from src.domain.errors import DomainError


class InvalidMfaError(DomainError):
    """An MFA request failed validation (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid MFA request."


class MfaConflictError(DomainError):
    """MFA state conflicts with the request (409, e.g. already enrolled)."""

    status_code = 409
    code = "CONFLICT"
    message = "MFA state conflicts with the request."


class MfaRateLimitedError(DomainError):
    """Too many MFA verification attempts in the current window (429)."""

    status_code = 429
    code = "RATE_LIMITED"
    message = "Too many verification attempts; wait a minute and try again."
    retry_after: int | None = 60


class MfaNotConfiguredError(DomainError):
    """MFA_SECRET_KEY is absent: MFA is disabled on this deployment (503)."""

    status_code = 503
    code = "FEATURE_DISABLED"
    message = "Multi-factor authentication is not configured on this deployment."


__all__ = [
    "InvalidMfaError",
    "MfaConflictError",
    "MfaNotConfiguredError",
    "MfaRateLimitedError",
]
