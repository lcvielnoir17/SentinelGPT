"""Investigation domain errors mapped by the centralized error handlers."""

from __future__ import annotations

from src.domain.errors import DomainError


class InvestigationQuestionTooLongError(DomainError):
    """The submitted question exceeds the configured size cap (413)."""

    status_code = 413
    code = "QUESTION_TOO_LONG"
    message = "Question exceeds the maximum allowed length."


class InvestigationRateLimitedError(DomainError):
    """Too many investigation queries in the current window (429)."""

    status_code = 429
    code = "RATE_LIMITED"
    message = "Too many AI requests; slow down and try again in a minute."
    retry_after: int | None = 60


class EmptyQuestionError(DomainError):
    """A question with no content was submitted (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Question must not be empty."


__all__ = [
    "EmptyQuestionError",
    "InvestigationQuestionTooLongError",
    "InvestigationRateLimitedError",
]
