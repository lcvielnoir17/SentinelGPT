"""CI/CD domain errors mapped by the centralized error handlers."""

from __future__ import annotations

from src.domain.errors import DomainError


class InvalidCiError(DomainError):
    """A CI request failed validation (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid CI request."


class CiAuthError(DomainError):
    """CI credential missing, unknown, revoked, or expired (401).

    One generic envelope for every credential failure so the endpoint
    reveals nothing about which credentials exist.
    """

    status_code = 401
    code = "UNAUTHENTICATED"
    message = "Invalid CI credential."


class CiConflictError(DomainError):
    """An idempotent retry raced an in-flight creation (409).

    The winning claim holds a scan-less row; the loser must retry and
    will then observe the completed mapping.
    """

    status_code = 409
    code = "CONFLICT"
    message = "A scan request with this idempotency key is already in progress."
    retry_after: int | None = 5


__all__ = ["CiAuthError", "CiConflictError", "InvalidCiError"]
