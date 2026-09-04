"""Agent-cache key hygiene for the conversation stack (ADR-0012).

``get_conversation_agent`` caches the Gemini agent per (key, model) pair.
The cache must retain only a digest of the API key — never the raw secret
— while still reusing the agent across turns and rebuilding on rotation.
"""

import pytest

from src.api import dependencies
from src.config.settings import Settings


@pytest.fixture(autouse=True)
def _clean_agent_cache():
    dependencies._agent_cache = None
    yield
    dependencies._agent_cache = None


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "test",
        "gemini_api_key": "env-key",
        "gemini_flash_model": "gemini-2.0-flash",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


class _StubAgent:
    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model


def _patch_stack(mocker, *, api_key: str):  # type: ignore[no-untyped-def]
    import src.infrastructure.ai.gemini_chat_agent as chat_module
    import src.infrastructure.secrets as secrets_pkg

    mocker.patch.object(dependencies, "get_settings", return_value=_settings())
    mocker.patch.object(secrets_pkg, "get_gemini_api_key", return_value=api_key)
    return mocker.patch.object(
        chat_module,
        "GeminiConversationAgent",
        side_effect=lambda api_key, model: _StubAgent(api_key, model),
    )


def test_agent_reused_across_turns_without_retaining_raw_key(mocker) -> None:  # type: ignore[no-untyped-def]
    factory = _patch_stack(mocker, api_key="test-key-1")
    first = dependencies.get_conversation_agent()
    second = dependencies.get_conversation_agent()
    assert second is first
    assert factory.call_count == 1
    assert dependencies._agent_cache is not None
    digest, _model, cached = dependencies._agent_cache
    assert cached is first
    # The retained identifier is a SHA-256 hex digest, not the secret.
    assert len(digest) == 64
    assert all(part != "test-key-1" for part in dependencies._agent_cache)


def test_key_rotation_builds_new_agent(mocker) -> None:  # type: ignore[no-untyped-def]
    import src.infrastructure.secrets as secrets_pkg

    factory = _patch_stack(mocker, api_key="test-key-1")
    first = dependencies.get_conversation_agent()
    assert factory.call_count == 1
    secrets_pkg.get_gemini_api_key.return_value = "test-key-2"  # type: ignore[attr-defined]
    second = dependencies.get_conversation_agent()
    assert second is not first
    assert factory.call_count == 2
    assert isinstance(second, _StubAgent)
    assert second.api_key == "test-key-2"  # type: ignore[attr-defined]


def test_missing_key_returns_none_without_building(mocker) -> None:  # type: ignore[no-untyped-def]
    factory = _patch_stack(mocker, api_key="")
    assert dependencies.get_conversation_agent() is None
    assert factory.call_count == 0
    assert dependencies._agent_cache is None
