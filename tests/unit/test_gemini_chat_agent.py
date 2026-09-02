"""Unit tests for the Gemini multi-turn chat agent (ADR-0012).

Fake client factory keeps everything offline; assertions cover the
contents-construction contract (role mapping, context framing position,
history replay), response extraction, error mapping, and size caps.
"""

import pytest
from google.genai import errors as genai_errors

from src.domain.conversations.errors import ConversationAiUnavailableError
from src.domain.conversations.models import ConversationMessage
from src.infrastructure.ai.gemini_chat_agent import GeminiConversationAgent


class FakeModels:
    def __init__(
        self, text: str | None = "a helpful reply", error: Exception | None = None
    ) -> None:
        self.calls: list[dict[str, object]] = []
        self._text = text
        self._error = error

    def generate_content(self, *, model, contents, config):  # type: ignore[no-untyped-def]
        self.calls.append({"model": model, "contents": contents, "config": config})
        if self._error is not None:
            raise self._error

        class _Response:
            text = self._text

        return _Response()


class FakeClient:
    def __init__(self, models: FakeModels) -> None:
        self.models = models


def _agent(models: FakeModels) -> GeminiConversationAgent:
    return GeminiConversationAgent(
        api_key="test-key",
        model="gemini-test",
        client_factory=lambda _key, _timeout: FakeClient(models),
    )


def _history(*pairs: tuple[str, str]) -> list[ConversationMessage]:
    out = []
    for role, content in pairs:
        out.append(ConversationMessage(id=f"id-{len(out)}", role=role, content=content))
    return out


def test_replays_history_with_gemini_roles() -> None:
    models = FakeModels()
    agent = _agent(models)
    history = _history(("user", "first"), ("assistant", "first answer"))

    reply = agent.respond(
        system_instructions="be safe",
        history=history,
        user_message="follow-up question",
    )

    assert reply == "a helpful reply"
    contents = models.calls[0]["contents"]
    roles = [c["role"] for c in contents]
    assert roles == ["user", "model", "user"]
    texts = [c["parts"][0]["text"] for c in contents]
    assert texts == ["first", "first answer", "follow-up question"]


def test_context_block_leads_and_is_acknowledged() -> None:
    models = FakeModels()
    agent = _agent(models)

    agent.respond(
        system_instructions="be safe",
        history=[],
        user_message="what now?",
        context_block="<untrusted_target_data>finding data</untrusted_target_data>",
    )

    contents = models.calls[0]["contents"]
    assert contents[0]["parts"][0]["text"].startswith("<untrusted_target_data>")
    # The model turn acknowledges the framing so it is not mistaken for a
    # real user turn.
    assert contents[1]["role"] == "model"


def test_system_instructions_reach_config() -> None:
    models = FakeModels()
    agent = _agent(models)
    agent.respond(system_instructions="SYS", history=[], user_message="hi")
    config = models.calls[0]["config"]
    assert config.system_instruction == "SYS"


def test_api_error_maps_to_typed_failure() -> None:
    for code in (500, 429, 401, 504):
        models = FakeModels(error=genai_errors.APIError(code=code, response_json={}))
        agent = _agent(models)
        with pytest.raises(ConversationAiUnavailableError):
            agent.respond(system_instructions="s", history=[], user_message="q")


def test_blocked_response_maps_to_typed_failure() -> None:
    models = FakeModels(text="")
    agent = _agent(models)
    with pytest.raises(ConversationAiUnavailableError):
        agent.respond(system_instructions="s", history=[], user_message="q")


def test_missing_key_rejected_at_construction() -> None:
    with pytest.raises(ConversationAiUnavailableError):
        GeminiConversationAgent(api_key="", client_factory=lambda _k, _t: FakeClient(FakeModels()))


def test_oversized_reply_rejected() -> None:
    models = FakeModels(text="x" * 70_000)
    agent = _agent(models)
    with pytest.raises(ConversationAiUnavailableError):
        agent.respond(system_instructions="s", history=[], user_message="q")
