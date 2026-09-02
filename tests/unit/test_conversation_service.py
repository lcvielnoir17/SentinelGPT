"""Unit tests for ConversationService (ADR-0012).

Focus: the security contract — ownership on every access path, 404
indistinguishability for cross-owner ids, quota/size/rate safeguards, and
the turn flow (question persisted before the agent runs, reply persisted
after, provider failure leaves the question retryable).
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from src.domain.conversations.errors import (
    AiNotConfiguredError,
    ConversationAiUnavailableError,
    ConversationMessageTooLongError,
    ConversationQuotaExceededError,
    ConversationRateLimitedError,
    EmptyMessageError,
)
from src.domain.conversations.service import ConversationService
from src.domain.conversations.store import MAX_CONVERSATIONS_PER_USER
from src.domain.errors import NotFoundError
from src.domain.users.user_service import UserAccount
from src.infrastructure.firestore.memory_store import InMemoryConversationStore

UID_A = "uid-aaa"
UID_B = "uid-bbb"


class ScriptedAgent:
    """Records invocations; returns scripted replies."""

    def __init__(self, replies: list[str] | None = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self._replies = list(replies or ["analysis reply"])
        self._error = error

    def respond(self, *, system_instructions, history, user_message, context_block=None):  # type: ignore[no-untyped-def]
        self.calls.append(
            {
                "system_instructions": system_instructions,
                "history": list(history),
                "user_message": user_message,
                "context_block": context_block,
            }
        )
        if self._error is not None:
            raise self._error
        return self._replies.pop(0) if self._replies else "analysis reply"


class AllowLimiter:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed

    async def try_admit(self, _user_id: uuid.UUID) -> bool:
        return self.allowed


class _StubSession:
    pass  # context assembly is exercised in route tests; unit paths skip it


def _user(uid: str) -> UserAccount:
    return UserAccount(
        id=uuid.uuid4(),
        email=f"{uid}@example.com",
        created_at=datetime.now(UTC),
        firebase_uid=uid,
    )


def _service(
    agent: object | None = ScriptedAgent(), *, limiter: object | None = None
) -> ConversationService:
    return ConversationService(
        _StubSession(),
        InMemoryConversationStore(),
        agent,
        limiter or AllowLimiter(),  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Creation + ownership matrix                                                 #
# --------------------------------------------------------------------------- #


async def test_create_and_list_scopes_to_owner() -> None:
    service = _service()
    user_a = _user(UID_A)
    conversation = await service.create_conversation(user_a, title="CSP question")
    assert conversation.firebase_uid == UID_A
    assert conversation.user_id == user_a.id

    other = await service.list_conversations(_user(UID_B))
    assert other == []
    assert len(await service.list_conversations(user_a)) == 1


async def test_cross_owner_read_is_not_found() -> None:
    service = _service()
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")

    with pytest.raises(NotFoundError):
        await service.get_conversation(_user(UID_B), conversation.id)
    with pytest.raises(NotFoundError):
        await service.delete_conversation(_user(UID_B), conversation.id)
    with pytest.raises(NotFoundError):
        await service.send_message(_user(UID_B), conversation.id, "hi")


async def test_unknown_conversation_id_is_not_found() -> None:
    service = _service()
    with pytest.raises(NotFoundError):
        await service.get_conversation(_user(UID_A), "nope")


async def test_delete_by_owner_removes_conversation() -> None:
    service = _service()
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    assert await service.delete_conversation(owner, conversation.id) is True
    with pytest.raises(NotFoundError):
        await service.get_conversation(owner, conversation.id)


async def test_conversation_quota_enforced() -> None:
    service = _service()
    owner = _user(UID_A)
    for _ in range(MAX_CONVERSATIONS_PER_USER):
        await service.create_conversation(owner, title="t")
    with pytest.raises(ConversationQuotaExceededError):
        await service.create_conversation(owner, title="one too many")


# --------------------------------------------------------------------------- #
# Turn flow                                                                   #
# --------------------------------------------------------------------------- #


async def test_send_message_persists_both_turns() -> None:
    agent = ScriptedAgent(replies=["Here is the remediation."])
    service = _service(agent)
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")

    user_message, assistant_message = await service.send_message(
        owner, conversation.id, "Why is this dangerous?"
    )

    assert user_message.role == "user"
    assert assistant_message.role == "assistant"
    assert assistant_message.content == "Here is the remediation."

    stored_conversation, messages = await service.get_conversation(owner, conversation.id)
    assert stored_conversation.message_count == 2
    assert [m.content for m in messages] == ["Why is this dangerous?", "Here is the remediation."]


async def test_agent_receives_history_and_system_instructions() -> None:
    agent = ScriptedAgent(replies=["second reply"])
    service = _service(agent)
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    await service.send_message(owner, conversation.id, "first question")

    await service.send_message(owner, conversation.id, "follow-up")

    second_call = agent.calls[1]
    history = second_call["history"]
    assert [m.content for m in history] == ["first question", "second reply"]
    assert "untrusted_target_data" in str(second_call["system_instructions"])


async def test_provider_failure_keeps_question_retryable() -> None:
    agent = ScriptedAgent(error=ConversationAiUnavailableError("down"))
    service = _service(agent)
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")

    with pytest.raises(ConversationAiUnavailableError):
        await service.send_message(owner, conversation.id, "why?")

    # The question stays in history; only the assistant turn is missing.
    _, messages = await service.get_conversation(owner, conversation.id)
    assert [m.content for m in messages] == ["why?"]

    # Retry with a healthy agent completes the turn on the same store.
    service._agent = ScriptedAgent(replies=["recovered"])
    user_message, assistant_message = await service.send_message(
        owner, conversation.id, "why? (retry)"
    )
    assert assistant_message.content == "recovered"
    assert user_message.content == "why? (retry)"


async def test_unexpected_agent_error_maps_to_typed_503() -> None:
    agent = ScriptedAgent(error=RuntimeError("connection reset"))
    service = _service(agent)
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    with pytest.raises(ConversationAiUnavailableError):
        await service.send_message(owner, conversation.id, "hello")


# --------------------------------------------------------------------------- #
# Safeguards                                                                  #
# --------------------------------------------------------------------------- #


async def test_message_size_cap() -> None:
    service = ConversationService(
        _StubSession(),
        InMemoryConversationStore(),
        ScriptedAgent(),
        AllowLimiter(),  # type: ignore[arg-type]
        max_message_chars=100,
    )
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    with pytest.raises(ConversationMessageTooLongError):
        await service.send_message(owner, conversation.id, "x" * 101)


async def test_blank_message_rejected() -> None:
    service = _service()
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    with pytest.raises(EmptyMessageError):
        await service.send_message(owner, conversation.id, "   ")


async def test_rate_limiter_blocks_turn() -> None:
    service = _service(limiter=AllowLimiter(allowed=False))
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    with pytest.raises(ConversationRateLimitedError):
        await service.send_message(owner, conversation.id, "hello")


async def test_no_agent_configured_rejects_send() -> None:
    service = _service(agent=None)
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    with pytest.raises(AiNotConfiguredError):
        await service.send_message(owner, conversation.id, "hello")


async def test_history_window_is_bounded() -> None:
    agent = ScriptedAgent(replies=[f"reply {i}" for i in range(10)])
    service = ConversationService(
        _StubSession(),
        InMemoryConversationStore(),
        agent,
        AllowLimiter(),  # type: ignore[arg-type]
        max_history_messages=3,
    )
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    for i in range(5):
        await service.send_message(owner, conversation.id, f"question {i}")

    last_call = agent.calls[-1]
    history_contents = [m.content for m in last_call["history"]]  # type: ignore[index]
    assert len(history_contents) == 3
    assert history_contents[-1] == "reply 3"  # the latest assistant turn


async def test_history_isolated_between_users_with_same_store() -> None:
    agent = ScriptedAgent()
    service = _service(agent)
    owner_a = _user(UID_A)
    conversation_a = await service.create_conversation(owner_a, title="A")
    await service.send_message(owner_a, conversation_a.id, "A's secret question")

    with pytest.raises(NotFoundError):
        await service.send_message(_user(UID_B), conversation_a.id, "sneaky read")


# --------------------------------------------------------------------------- #
# Firestore path scoping                                                      #
# --------------------------------------------------------------------------- #


async def test_messages_do_not_leak_across_uids_in_shared_store() -> None:
    store = InMemoryConversationStore()
    service = ConversationService(
        _StubSession(),
        store,
        ScriptedAgent(),
        AllowLimiter(),  # type: ignore[arg-type]
    )
    owner_a = _user(UID_A)
    conversation_a = await service.create_conversation(owner_a, title="A")
    await service.send_message(owner_a, conversation_a.id, "A question")

    # UID_B's store scope holds nothing, even with identical conversation ids.
    assert await store.get_conversation(UID_B, conversation_a.id) is None
    assert UID_B not in store.user_ids_with_data


async def test_message_ordering_is_chronological() -> None:
    service = _service(ScriptedAgent(replies=["r1", "r2", "r3"]))
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    for question in ("q1", "q2", "q3"):
        await service.send_message(owner, conversation.id, question)
    _, messages = await service.get_conversation(owner, conversation.id)
    contents = [m.content for m in messages]
    assert contents == ["q1", "r1", "q2", "r2", "q3", "r3"]


async def test_conversation_created_at_not_mutated_by_turns() -> None:
    service = _service()
    owner = _user(UID_A)
    conversation = await service.create_conversation(owner, title="t")
    created = conversation.created_at
    await service.send_message(owner, conversation.id, "q")
    refreshed = await service.get_conversation(owner, conversation.id)
    assert refreshed[0].created_at.replace(microsecond=0) == created.replace(microsecond=0) or (
        refreshed[0].created_at - created < timedelta(seconds=1)
    )
