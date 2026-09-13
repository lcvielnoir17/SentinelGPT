"""Compliance domain errors mapped by the centralized error handlers."""

from __future__ import annotations

from src.domain.errors import DomainError


class InvalidComplianceError(DomainError):
    """A compliance request failed validation (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid compliance request."


__all__ = ["InvalidComplianceError"]
