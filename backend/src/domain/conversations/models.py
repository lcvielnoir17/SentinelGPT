"""Conversation aggregate models (ADR-0011).

A Conversation is user-scoped AI application data: it belongs to exactly
one SentinelGPT account and optionally links to a scan/finding for
context assembly. Messages form the multi-turn history sent to Gemini.

Ownership is tracked redundantly:

* ``firebase_uid`` — the Firestore path scope
  (``users/{firebase_uid}/conversations/{id}``); storage keys on it.
* ``user_id`` — the canonical SentinelGPT account; the authorization
  boundary. Services must verify every access against it (defense in
  depth on top of the path scoping).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
ALLOWED_ROLES = (ROLE_USER, ROLE_ASSISTANT)


def new_conversation_id() -> str:
    return uuid.uuid4().hex


def new_message_id() -> str:
    return uuid.uuid4().hex


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ConversationMessage:
    """One turn of the multi-turn conversation."""

    id: str
    role: str
    content: str
    created_at: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if self.role not in ALLOWED_ROLES:
            raise ValueError(f"invalid message role: {self.role!r}")


@dataclass(frozen=True)
class Conversation:
    """A user-owned AI analysis thread, optionally anchored to a finding."""

    id: str
    user_id: uuid.UUID
    firebase_uid: str
    title: str
    scan_id: uuid.UUID | None = None
    finding_id: str | None = None
    message_count: int = 0
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
