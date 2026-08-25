"""Domain-specific exceptions mapped to the SRS error catalog (Chapter 5,
Section 14) by the centralized FastAPI exception handlers."""

from __future__ import annotations


class DomainError(Exception):
    """Base class for business-rule violations with HTTP mapping metadata."""

    status_code: int
    code: str
    message: str

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.message)


class EmailAlreadyRegisteredError(DomainError):
    """Registration attempted with an email that already exists (409 CONFLICT)."""

    status_code = 409
    code = "CONFLICT"
    message = "An account with this email already exists."


class InvalidCredentialsError(DomainError):
    """Login failed — identical for unknown email and wrong password (401)."""

    status_code = 401
    code = "UNAUTHENTICATED"
    message = "Invalid email or password."
