"""Firestore-backed conversation persistence (ADR-0011, Ideathon req. 3).

Document layout — strictly user-scoped::

    users/{firebase_uid}/conversations/{conversationId}
        title, userId, scanId?, findingId?, messageCount, createdAt, updatedAt
    users/{firebase_uid}/conversations/{conversationId}/messages/{messageId}
        role, content, createdAt

Every read and write addresses documents under
``users/{firebase_uid}/...`` where ``firebase_uid`` is supplied by the
caller from the *verified* session identity (ADR-0010 bridge), never from
client input. There is deliberately no API on this store that can address
another user's subtree.

All access is backend-only through the Admin SDK (the API ships a
deny-all client rules file, ``infra/firebase/firestore.rules``, as
defense in depth); authorization is enforced server-side by the
ConversationService before any store call.

The Firestore ``AsyncClient`` is injected (see :func:`from_settings`) so
unit tests can substitute a fake and never touch Google.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from src.domain.conversations.models import Conversation, ConversationMessage
from src.domain.conversations.store import (
    MAX_CONVERSATIONS_PER_USER,
    MAX_MESSAGES_PER_CONVERSATION,
    ConversationNotFoundError,
)

if TYPE_CHECKING:
    from src.config.settings import Settings


class FirestoreConversationStore:
    """ConversationStore over a Firestore AsyncClient."""

    def __init__(self, client: Any) -> None:
        # google.cloud.firestore.AsyncClient; typed as Any because the
        # google namespace is untyped in mypy (ignore_missing_imports).
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings) -> FirestoreConversationStore:
        """Build the production store from ADC + settings."""
        from google.cloud import firestore as gcf

        client = gcf.AsyncClient(
            project=settings.firebase_project_id,
            database=settings.firestore_database_id,
        )
        return cls(client)

    # ------------------------------------------------------------------ #
    # Paths                                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _conversation_ref(client: Any, firebase_uid: str, conversation_id: str) -> Any:
        return (
            client.collection("users")
            .document(firebase_uid)
            .collection("conversations")
            .document(conversation_id)
        )

    @staticmethod
    def _messages_ref(client: Any, firebase_uid: str, conversation_id: str) -> Any:
        return FirestoreConversationStore._conversation_ref(
            client, firebase_uid, conversation_id
        ).collection("messages")

    # ------------------------------------------------------------------ #
    # Serialization                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _to_firestore(conversation: Conversation) -> dict[str, Any]:
        return {
            "title": conversation.title,
            "userId": str(conversation.user_id),
            "firebaseUid": conversation.firebase_uid,
            "scanId": str(conversation.scan_id) if conversation.scan_id else None,
            "findingId": conversation.finding_id,
            "messageCount": conversation.message_count,
            "createdAt": conversation.created_at,
            "updatedAt": conversation.updated_at,
        }

    @staticmethod
    def _from_firestore(conversation_id: str, data: dict[str, Any]) -> Conversation:
        scan_id = data.get("scanId")
        return Conversation(
            id=conversation_id,
            user_id=uuid.UUID(data["userId"]),
            firebase_uid=data["firebaseUid"],
            title=data["title"],
            scan_id=uuid.UUID(scan_id) if scan_id else None,
            finding_id=data.get("findingId"),
            message_count=int(data.get("messageCount", 0)),
            created_at=_as_datetime(data.get("createdAt")),
            updated_at=_as_datetime(data.get("updatedAt")),
        )

    @staticmethod
    def _message_to_firestore(message: ConversationMessage) -> dict[str, Any]:
        return {"role": message.role, "content": message.content, "createdAt": message.created_at}

    @staticmethod
    def _message_from_firestore(message_id: str, data: dict[str, Any]) -> ConversationMessage:
        return ConversationMessage(
            id=message_id,
            role=data["role"],
            content=data["content"],
            created_at=_as_datetime(data.get("createdAt")),
        )

    # ------------------------------------------------------------------ #
    # ConversationStore protocol                                          #
    # ------------------------------------------------------------------ #

    async def create_conversation(self, conversation: Conversation) -> Conversation:
        ref = self._conversation_ref(self._client, conversation.firebase_uid, conversation.id)
        await ref.set(self._to_firestore(conversation))
        return conversation

    async def get_conversation(
        self, firebase_uid: str, conversation_id: str
    ) -> Conversation | None:
        snapshot = await self._conversation_ref(
            self._client, firebase_uid, conversation_id
        ).get()
        if not snapshot.exists:
            return None
        return self._from_firestore(snapshot.id, snapshot.to_dict() or {})

    async def list_conversations(
        self, firebase_uid: str, *, limit: int = 50
    ) -> list[Conversation]:
        query = (
            self._client.collection("users")
            .document(firebase_uid)
            .collection("conversations")
            .order_by("updatedAt", direction="DESCENDING")
            .limit(min(limit, MAX_CONVERSATIONS_PER_USER))
        )
        conversations: list[Conversation] = []
        async for snapshot in query.stream():
            data = snapshot.to_dict() or {}
            conversations.append(self._from_firestore(snapshot.id, data))
        return conversations

    async def delete_conversation(self, firebase_uid: str, conversation_id: str) -> bool:
        ref = self._conversation_ref(self._client, firebase_uid, conversation_id)
        snapshot = await ref.get()
        if not snapshot.exists:
            return False
        # Messages are a first-generation subcollection: delete them in
        # batches before removing the conversation document. Conversations
        # are bounded (MAX_MESSAGES_PER_CONVERSATION), so this is cheap.
        messages = self._messages_ref(self._client, firebase_uid, conversation_id)
        batch = self._client.batch()
        async for msg_snapshot in messages.stream():
            batch.delete(msg_snapshot.reference)
        await batch.commit()
        await ref.delete()
        return True

    async def append_message(
        self, firebase_uid: str, conversation_id: str, message: ConversationMessage
    ) -> None:
        conversation_ref = self._conversation_ref(self._client, firebase_uid, conversation_id)
        snapshot = await conversation_ref.get()
        if not snapshot.exists:
            raise ConversationNotFoundError()
        batch = self._client.batch()
        batch.set(
            self._messages_ref(self._client, firebase_uid, conversation_id).document(message.id),
            self._message_to_firestore(message),
        )
        batch.update(
            conversation_ref,
            {
                "messageCount": int(snapshot.to_dict().get("messageCount", 0) or 0) + 1,
                "updatedAt": message.created_at,
            },
        )
        await batch.commit()

    async def list_messages(
        self, firebase_uid: str, conversation_id: str, *, limit: int = 200
    ) -> list[ConversationMessage]:
        # Parent check keeps a missing conversation a 404 rather than an
        # indistinguishable "no messages" answer (matches the in-memory
        # store's contract and the service's isolation matrix).
        parent = await self._conversation_ref(self._client, firebase_uid, conversation_id).get()
        if not parent.exists:
            raise ConversationNotFoundError()
        query = (
            self._messages_ref(self._client, firebase_uid, conversation_id)
            .order_by("createdAt", direction="ASCENDING")
            .limit(min(limit, MAX_MESSAGES_PER_CONVERSATION))
        )
        messages: list[ConversationMessage] = []
        async for snapshot in query.stream():
            data = snapshot.to_dict() or {}
            messages.append(self._message_from_firestore(snapshot.id, data))
        return messages

    async def count_conversations(self, firebase_uid: str) -> int:
        # Counts run per login-scoped request against a bounded subtree; a
        # streaming count avoids the extra aggregation-query dependency.
        total = 0
        stream = (
            self._client.collection("users")
            .document(firebase_uid)
            .collection("conversations")
            .select([])
            .stream()
        )
        async for _ in stream:
            total += 1
        return total


def _as_datetime(value: Any) -> datetime:
    """Firestore returns datetimes already; tolerate ISO strings for fakes."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    raise TypeError(f"unsupported timestamp type: {type(value)!r}")
