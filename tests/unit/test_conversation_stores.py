"""ConversationStore behavior tests (ADR-0011).

One shared isolation/behavior matrix runs against BOTH implementations:

* :class:`InMemoryConversationStore` — the local-dev/test store.
* :class:`FirestoreConversationStore` — driven by an in-memory fake of the
  Firestore ``AsyncClient`` surface the store actually uses, so the real
  serialization + path-building code is exercised offline.

The isolation contract under test: storage operations scoped to one
firebase_uid can never observe another uid's conversations.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.domain.conversations.models import (
    Conversation,
    ConversationMessage,
    new_conversation_id,
    new_message_id,
)
from src.domain.conversations.store import ConversationNotFoundError
from src.infrastructure.firestore.conversation_store import FirestoreConversationStore
from src.infrastructure.firestore.memory_store import InMemoryConversationStore

UID_A = "uid-aaa"
UID_B = "uid-bbb"


# --------------------------------------------------------------------------- #
# Fake Firestore client                                                       #
# --------------------------------------------------------------------------- #


class FakeQuery:
    def __init__(self, snapshots: list[FakeSnapshot], field: str | None = None) -> None:
        self._snapshots = snapshots
        self._field = field

    def order_by(self, field: str, direction: str = "ASCENDING") -> FakeQuery:
        self._field = field
        self._snapshots.sort(
            key=lambda s: s.to_dict().get(field) or "",
            reverse=(direction == "DESCENDING"),
        )
        return self

    def limit(self, value: int) -> FakeQuery:
        self._snapshots = self._snapshots[:value]
        return self

    def stream(self):  # type: ignore[no-untyped-def]
        async def _gen():
            for snapshot in self._snapshots:
                yield snapshot

        return _gen()


class FakeSnapshot:
    def __init__(self, doc_id: str, data: dict, reference: FakeDocument | None = None) -> None:
        self.id = doc_id
        self._data = data
        self.exists = True
        self.reference = reference

    def to_dict(self) -> dict:
        return self._data


class FakeCollection:
    def __init__(self, store: FakeFirestore, path: tuple[str, ...]) -> None:
        self._store = store
        self._path = path

    def document(self, doc_id: str) -> FakeDocument:
        return FakeDocument(self._store, self._path + (doc_id,))

    def _documents(self) -> list[FakeSnapshot]:
        prefix = self._path
        out: list[FakeSnapshot] = []
        for path, data in self._store.docs.items():
            if len(path) == len(prefix) + 1 and path[: len(prefix)] == prefix:
                out.append(FakeSnapshot(path[-1], data, FakeDocument(self._store, path)))
        return out

    def order_by(self, field: str, direction: str = "ASCENDING") -> FakeQuery:
        return FakeQuery(self._documents()).order_by(field, direction=direction)

    def limit(self, value: int) -> FakeQuery:
        return FakeQuery(self._documents()).limit(value)

    def select(self, _fields: list[str]) -> FakeCollection:
        return self

    def stream(self):  # type: ignore[no-untyped-def]
        return FakeQuery(self._documents()).stream()


class FakeDocument:
    def __init__(self, store: FakeFirestore, path: tuple[str, ...]) -> None:
        self._store = store
        self._path = path
        self.reference = self

    async def set(self, data: dict) -> None:  # type: ignore[type-arg]
        self._store.docs[self._path] = dict(data)

    async def get(self) -> FakeSnapshot:
        data = self._store.docs.get(self._path)
        if data is None:
            snap = FakeSnapshot(self._path[-1], {})
            snap.exists = False
            return snap
        return FakeSnapshot(self._path[-1], data)

    async def delete(self) -> None:
        self._store.docs.pop(self._path, None)

    def collection(self, name: str) -> FakeCollection:
        return FakeCollection(self._store, self._path + (name,))

    async def update(self, data: dict) -> None:  # type: ignore[type-arg]
        current = self._store.docs.get(self._path)
        if current is None:
            raise KeyError(f"missing document: {self._path}")
        current.update(data)


class FakeBatch:
    def __init__(self, store: FakeFirestore) -> None:
        self._store = store
        self._ops: list[tuple[str, FakeDocument, dict | None]] = []

    def set(self, doc: FakeDocument, data: dict) -> None:  # type: ignore[type-arg]
        self._ops.append(("set", doc, data))

    def update(self, doc: FakeDocument, data: dict) -> None:  # type: ignore[type-arg]
        self._ops.append(("update", doc, data))

    def delete(self, doc: FakeDocument) -> None:
        self._ops.append(("delete", doc, None))

    async def commit(self) -> None:
        for op, doc, data in self._ops:
            if op == "set":
                await doc.set(data or {})
            elif op == "update":
                await doc.update(data or {})
            elif op == "delete":
                await doc.delete()
        self._ops.clear()


class FakeFirestore:
    """Minimal AsyncClient double: collections, documents, batches."""

    def __init__(self) -> None:
        self.docs: dict[tuple[str, ...], dict] = {}  # type: ignore[type-arg]

    def collection(self, name: str) -> FakeCollection:
        return FakeCollection(self, (name,))

    def batch(self) -> FakeBatch:
        return FakeBatch(self)


# --------------------------------------------------------------------------- #
# Shared matrix                                                               #
# --------------------------------------------------------------------------- #


def _conversation(uid: str, *, user_id=None, scan_id=None, finding_id=None) -> Conversation:
    import uuid

    return Conversation(
        id=new_conversation_id(),
        user_id=user_id or uuid.uuid4(),
        firebase_uid=uid,
        title="Investigate missing CSP",
        scan_id=scan_id,
        finding_id=finding_id,
    )


@pytest.fixture(params=["memory", "firestore"])
def store(request) -> InMemoryConversationStore | FirestoreConversationStore:
    if request.param == "memory":
        return InMemoryConversationStore()
    return FirestoreConversationStore(FakeFirestore())


async def test_create_and_get_roundtrip(store) -> None:
    conversation = _conversation(UID_A)
    await store.create_conversation(conversation)
    loaded = await store.get_conversation(UID_A, conversation.id)
    assert loaded is not None
    assert loaded.id == conversation.id
    assert loaded.title == conversation.title
    assert loaded.user_id == conversation.user_id
    assert loaded.firebase_uid == UID_A
    assert loaded.message_count == 0


async def test_get_missing_returns_none(store) -> None:
    assert await store.get_conversation(UID_A, "does-not-exist") is None


async def test_cross_uid_isolation_read(store) -> None:
    conversation = _conversation(UID_A)
    await store.create_conversation(conversation)
    assert await store.get_conversation(UID_B, conversation.id) is None
    assert await store.list_conversations(UID_B) == []


async def test_cross_uid_isolation_write(store) -> None:
    conversation = _conversation(UID_A)
    await store.create_conversation(conversation)
    message = ConversationMessage(
        id=new_message_id(), role="user", content="hello", created_at=datetime.now(UTC)
    )
    with pytest.raises(ConversationNotFoundError):
        await store.append_message(UID_B, conversation.id, message)
    with pytest.raises(ConversationNotFoundError):
        await store.list_messages(UID_B, conversation.id)


async def test_list_orders_most_recent_first(store) -> None:
    base = datetime.now(UTC)
    first = _conversation(UID_A)
    second = _conversation(UID_A)
    await store.create_conversation(first)
    await store.create_conversation(second)
    # Activity: bump the second conversation with a later message.
    await store.append_message(
        UID_A,
        second.id,
        ConversationMessage(
            id=new_message_id(), role="user", content="x", created_at=base + timedelta(minutes=5)
        ),
    )
    listed = await store.list_conversations(UID_A)
    assert [c.id for c in listed] == [second.id, first.id]


async def test_append_message_updates_count_and_ordering(store) -> None:
    conversation = _conversation(UID_A)
    await store.create_conversation(conversation)
    base = datetime.now(UTC)
    first = ConversationMessage(
        id=new_message_id(), role="user", content="first", created_at=base
    )
    second = ConversationMessage(
        id=new_message_id(), role="assistant", content="second", created_at=base + timedelta(seconds=1)
    )
    await store.append_message(UID_A, conversation.id, first)
    await store.append_message(UID_A, conversation.id, second)

    loaded = await store.get_conversation(UID_A, conversation.id)
    assert loaded is not None and loaded.message_count == 2

    messages = await store.list_messages(UID_A, conversation.id)
    assert [m.content for m in messages] == ["first", "second"]
    assert [m.role for m in messages] == ["user", "assistant"]


async def test_append_message_to_missing_conversation_raises(store) -> None:
    message = ConversationMessage(
        id=new_message_id(), role="user", content="x", created_at=datetime.now(UTC)
    )
    with pytest.raises(ConversationNotFoundError):
        await store.append_message(UID_A, "missing", message)


async def test_delete_removes_conversation_and_messages(store) -> None:
    conversation = _conversation(UID_A)
    await store.create_conversation(conversation)
    await store.append_message(
        UID_A,
        conversation.id,
        ConversationMessage(
            id=new_message_id(), role="user", content="x", created_at=datetime.now(UTC)
        ),
    )
    assert await store.delete_conversation(UID_A, conversation.id) is True
    assert await store.get_conversation(UID_A, conversation.id) is None
    # Messages are gone too (re-creating and listing yields nothing).
    with pytest.raises(ConversationNotFoundError):
        await store.list_messages(UID_A, conversation.id)
    # Delete of an already-deleted conversation reports False.
    assert await store.delete_conversation(UID_A, conversation.id) is False


async def test_delete_is_uid_scoped(store) -> None:
    conversation = _conversation(UID_A)
    await store.create_conversation(conversation)
    assert await store.delete_conversation(UID_B, conversation.id) is False
    assert await store.get_conversation(UID_A, conversation.id) is not None


async def test_count_conversations_per_uid(store) -> None:
    await store.create_conversation(_conversation(UID_A))
    await store.create_conversation(_conversation(UID_A))
    await store.create_conversation(_conversation(UID_B))
    assert await store.count_conversations(UID_A) == 2
    assert await store.count_conversations(UID_B) == 1
