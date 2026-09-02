"""Conversation persistence protocol (ADR-0011).

The storage seam behind the conversational analyst. Two implementations:

* :class:`~src.infrastructure.firestore.conversation_store.FirestoreConversationStore`
  — production persistence in Firestore (Ideathon requirement), one
  document subtree per user.
* :class:`~src.infrastructure.firestore.memory_store.InMemoryConversationStore`
  — process-local fallback for local development without Google
  credentials and for unit tests.

ISOLATION CONTRACT: every method scopes reads and writes under the
``firebase_uid`` argument, which callers derive from the *verified*
session identity — never from client input. A store implementation MUST
NOT offer any path that addresses documents outside that subtree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import uuid

    from src.domain.conversations.models import Conversation, ConversationMessage

MAX_CONVERSATIONS_PER_USER = 100
MAX_MESSAGES_PER_CONVERSATION = 200


class ConversationNotFoundError(Exception):
    """The conversation does not exist in the given user's scope."""


@runtime_checkable
class ConversationStore(Protocol):
    """User-scoped persistence for conversations and messages."""

    async def create_conversation(self, conversation: Conversation) -> Conversation:
        """Persist a new conversation document."""
        ...

    async def get_conversation(
        self, firebase_uid: str, conversation_id: str
    ) -> Conversation | None:
        """Load one conversation from the user's scope (None if absent)."""
        ...

    async def list_conversations(self, firebase_uid: str, *, limit: int = 50) -> list[Conversation]:
        """List the user's conversations, most recently active first."""
        ...

    async def delete_conversation(self, firebase_uid: str, conversation_id: str) -> bool:
        """Delete a conversation and its messages; True when it existed."""
        ...

    async def append_message(
        self, firebase_uid: str, conversation_id: str, message: ConversationMessage
    ) -> None:
        """Append one message and bump the conversation's activity stamp."""
        ...

    async def list_messages(
        self, firebase_uid: str, conversation_id: str, *, limit: int = 200
    ) -> list[ConversationMessage]:
        """List messages in chronological order."""
        ...

    async def count_conversations(self, firebase_uid: str) -> int:
        """Number of conversations in the user's scope (quota enforcement)."""
        ...


def ensure_scope(user_id: uuid.UUID, conversation: Conversation, firebase_uid: str) -> None:
    """Defense-in-depth: the stored owner must match the requesting identity.

    Storage paths already scope by ``firebase_uid``; this second check
    keeps the canonical ``user_id`` authoritative even if a document ever
    ended up under the wrong subtree.
    """
    if conversation.user_id != user_id or conversation.firebase_uid != firebase_uid:
        raise ConversationNotFoundError()
