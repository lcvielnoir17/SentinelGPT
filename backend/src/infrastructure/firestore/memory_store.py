"""In-memory ConversationStore (local development and unit tests).

Behaviorally identical to :class:`FirestoreConversationStore` (same
isolation contract, same ordering, same counts) minus durability: data
lives only for the process lifetime.

Used when the deployment has no Firebase project configured so local
development keeps working without Google credentials, and as the test
double for the conversation service suite. Production always wires the
Firestore store (ADR-0011).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.domain.conversations.models import Conversation, ConversationMessage
from src.domain.conversations.store import ConversationNotFoundError

if TYPE_CHECKING:
    import uuid


class InMemoryConversationStore:
    """Dictionary-backed ConversationStore keyed by (uid, conversation id)."""

    def __init__(self) -> None:
        # firebase_uid -> {conversation_id -> Conversation}
        self._conversations: dict[str, dict[str, Conversation]] = {}
        # firebase_uid -> {conversation_id -> {message_id -> ConversationMessage}}
        self._messages: dict[str, dict[str, dict[str, ConversationMessage]]] = {}

    async def create_conversation(self, conversation: Conversation) -> Conversation:
        scoped = self._conversations.setdefault(conversation.firebase_uid, {})
        scoped[conversation.id] = conversation
        self._messages.setdefault(conversation.firebase_uid, {})[conversation.id] = {}
        return conversation

    async def get_conversation(
        self, firebase_uid: str, conversation_id: str
    ) -> Conversation | None:
        return self._conversations.get(firebase_uid, {}).get(conversation_id)

    async def list_conversations(
        self, firebase_uid: str, *, limit: int = 50
    ) -> list[Conversation]:
        scoped = self._conversations.get(firebase_uid, {})
        ordered = sorted(scoped.values(), key=lambda c: c.updated_at, reverse=True)
        return ordered[:limit]

    async def delete_conversation(self, firebase_uid: str, conversation_id: str) -> bool:
        scoped = self._conversations.get(firebase_uid, {})
        if conversation_id not in scoped:
            return False
        del scoped[conversation_id]
        self._messages.get(firebase_uid, {}).pop(conversation_id, None)
        return True

    async def append_message(
        self, firebase_uid: str, conversation_id: str, message: ConversationMessage
    ) -> None:
        conversation = await self.get_conversation(firebase_uid, conversation_id)
        if conversation is None:
            raise ConversationNotFoundError()
        # Frozen dataclass: replace with an updated copy (count + activity).
        updated = Conversation(
            id=conversation.id,
            user_id=conversation.user_id,
            firebase_uid=conversation.firebase_uid,
            title=conversation.title,
            scan_id=conversation.scan_id,
            finding_id=conversation.finding_id,
            message_count=conversation.message_count + 1,
            created_at=conversation.created_at,
            updated_at=message.created_at,
        )
        self._conversations[firebase_uid][conversation_id] = updated
        self._messages[firebase_uid][conversation_id][message.id] = message

    async def list_messages(
        self, firebase_uid: str, conversation_id: str, *, limit: int = 200
    ) -> list[ConversationMessage]:
        if await self.get_conversation(firebase_uid, conversation_id) is None:
            raise ConversationNotFoundError()
        scoped = self._messages.get(firebase_uid, {}).get(conversation_id, {})
        ordered = sorted(scoped.values(), key=lambda m: (m.created_at, m.id))
        return ordered[:limit]

    async def count_conversations(self, firebase_uid: str) -> int:
        return len(self._conversations.get(firebase_uid, {}))

    @property
    def user_ids_with_data(self) -> set[str]:
        """Firebase UIDs that hold at least one conversation (test aid)."""
        return {uid for uid, scoped in self._conversations.items() if scoped}
