"""Conversation domain errors mapped by the centralized error handlers."""

from __future__ import annotations

from src.domain.errors import DomainError


class ConversationAiUnavailableError(DomainError):
    """Gemini could not produce a reply (503 AI_UNAVAILABLE).

    The user's message is already persisted when this is raised, so the
    turn can be retried without losing the question.
    """

    status_code = 503
    code = "AI_UNAVAILABLE"
    message = "The AI analyst is unavailable right now; try again shortly."


class ConversationRateLimitedError(DomainError):
    """Too many assistant replies requested in the current window (429)."""

    status_code = 429
    code = "RATE_LIMITED"
    message = "Too many AI requests; slow down and try again in a minute."


class ConversationQuotaExceededError(DomainError):
    """The user already holds the maximum number of conversations (409)."""

    status_code = 409
    code = "CONVERSATION_LIMIT"
    message = "Conversation limit reached; delete older conversations first."


class ConversationMessageTooLongError(DomainError):
    """The submitted message exceeds the configured size cap (413)."""

    status_code = 413
    code = "MESSAGE_TOO_LONG"
    message = "Message exceeds the maximum allowed length."


class AiNotConfiguredError(DomainError):
    """No Gemini key is configured on this deployment (503)."""

    status_code = 503
    code = "AI_NOT_CONFIGURED"
    message = "AI analysis is not configured on this deployment."


class EmptyMessageError(DomainError):
    """A chat message with no content was submitted (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Message must not be empty."
