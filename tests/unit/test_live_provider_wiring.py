"""M19 provider wiring: the configured research model reaches the agent.

Every test here is offline: the real ``GeminiConversationAgent`` class
is replaced with a recording double, the key resolver returns a fake
key, and no network call is made. The suite exercises the shipped
``default_provider_factory()`` and ``main()`` code paths rather than
re-implementing model selection.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from scripts import collect_live_transcripts as collector_script

from src.research.live_config import DEFAULT_MODEL, MODEL_VARIABLE, resolve_config

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")
_FAKE_KEY = "k" * 30


def _answer() -> dict:
    return {
        "summary": "One open gap.",
        "key_points": ["note"],
        "citations": [{"finding_id": "fp", "note": "open"}],
        "recommended_actions": ["Harden the header"],
        "compliance_notes": [{"control_id": "2.2", "note": "gap"}],
    }


def _opt_in_env(model: str | None = None) -> dict[str, str]:
    env = {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "real-secret-value-12345"}
    if model is not None:
        env[MODEL_VARIABLE] = model
    return env


class _RecordingAgentClass:
    """Double for the real agent class: records construction, never dials out."""

    last_kwargs: dict | None = None

    def __init__(self, api_key: str = "", *, model: str = "") -> None:
        type(self).last_kwargs = {"api_key": api_key, "model": model}
        self.model = model

    def respond(self, **_kwargs: object) -> str:
        return json.dumps(_answer())


def _patch_agent(
    monkeypatch: pytest.MonkeyPatch, *, respond_reply: str | None = None
) -> type[_RecordingAgentClass]:
    class _Agent(_RecordingAgentClass):
        def respond(self, **_kwargs: object) -> str:
            return respond_reply if respond_reply is not None else json.dumps(_answer())

    monkeypatch.setattr("src.infrastructure.ai.gemini_chat_agent.GeminiConversationAgent", _Agent)
    monkeypatch.setattr("src.infrastructure.secrets.get_gemini_api_key", lambda: _FAKE_KEY)
    return _Agent


def test_m19_default_model_is_gemini_25_flash() -> None:
    assert DEFAULT_MODEL == "gemini-2.5-flash"
    assert resolve_config(_opt_in_env()).model == "gemini-2.5-flash"


def test_live_provider_model_override_flows_through_config() -> None:
    assert resolve_config(_opt_in_env("custom-research-model")).model == ("custom-research-model")


def test_factory_passes_explicit_model_to_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_cls = _patch_agent(monkeypatch)
    agent = collector_script.default_provider_factory(model="explicit-m")
    assert isinstance(agent, agent_cls)
    assert agent_cls.last_kwargs is not None
    assert agent_cls.last_kwargs["model"] == "explicit-m"
    assert agent_cls.last_kwargs["api_key"] == _FAKE_KEY


def test_factory_resolves_model_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_cls = _patch_agent(monkeypatch)
    monkeypatch.setenv("RESEARCH_LIVE_PROVIDER", "1")
    monkeypatch.setenv("GEMINI_API_KEY", _FAKE_KEY)
    monkeypatch.setenv(MODEL_VARIABLE, "env-selected-model")
    collector_script.default_provider_factory()
    assert agent_cls.last_kwargs is not None
    assert agent_cls.last_kwargs["model"] == "env-selected-model"


def test_factory_does_not_use_production_agent_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M19 construction bypasses the production shared-agent helper."""
    import src.api.dependencies as dependencies

    def _forbidden() -> object:
        raise AssertionError("production get_conversation_agent must not be called")

    monkeypatch.setattr(dependencies, "get_conversation_agent", _forbidden)
    agent_cls = _patch_agent(monkeypatch)
    collector_script.default_provider_factory(model="m19-only-model")
    assert agent_cls.last_kwargs is not None
    assert agent_cls.last_kwargs["model"] == "m19-only-model"


def test_main_wires_config_model_end_to_end(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real main(): env model -> factory -> agent -> transcripts + metadata."""
    agent_cls = _patch_agent(monkeypatch)
    monkeypatch.setenv("RESEARCH_LIVE_PROVIDER", "1")
    monkeypatch.setenv("GEMINI_API_KEY", _FAKE_KEY)
    monkeypatch.setenv(MODEL_VARIABLE, "e2e-research-model")

    exit_code = collector_script.main(
        ["--out", str(tmp_path), "--dataset", str(DATASET_PATH.resolve())]
    )

    assert exit_code == 0
    assert agent_cls.last_kwargs is not None
    assert agent_cls.last_kwargs["model"] == "e2e-research-model"
    metadata = json.loads((tmp_path / "live-metadata.json").read_text())
    assert metadata["model"] == "e2e-research-model"
    stored = json.loads((tmp_path / "live-transcripts.json").read_text())
    assert isinstance(stored, list) and len(stored) == 12
    assert {t["model"] for t in stored} == {"e2e-research-model"}


def test_no_stale_production_model_when_override_set(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An explicit M19 model is never silently replaced by production config."""
    from src.config.settings import get_settings

    agent_cls = _patch_agent(monkeypatch)
    production_model = get_settings().gemini_flash_model
    assert production_model != "override-wins-model"
    monkeypatch.setenv("RESEARCH_LIVE_PROVIDER", "1")
    monkeypatch.setenv("GEMINI_API_KEY", _FAKE_KEY)
    monkeypatch.setenv(MODEL_VARIABLE, "override-wins-model")

    exit_code = collector_script.main(
        ["--out", str(tmp_path), "--dataset", str(DATASET_PATH.resolve())]
    )

    assert exit_code == 0
    assert agent_cls.last_kwargs is not None
    assert agent_cls.last_kwargs["model"] == "override-wins-model"
    assert agent_cls.last_kwargs["model"] != production_model


def test_production_provider_configuration_untouched() -> None:
    """Static pins: production wiring still owns the production model knob."""
    dependencies_src = pathlib.Path("backend/src/api/dependencies.py").read_text()
    assert "settings.gemini_flash_model" in dependencies_src
    assert "LIVE_PROVIDER_MODEL" not in dependencies_src
    settings_src = pathlib.Path("backend/src/config/settings.py").read_text()
    assert 'gemini_flash_model: str = "gemini-2.0-flash"' in settings_src


def test_factory_never_exposes_key_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "real-secret-value-12345"

    class _Boom:
        def __init__(self, _api_key: str = "", *, model: str = "") -> None:
            raise RuntimeError(f"construction blew up for {model}")

    monkeypatch.setattr("src.infrastructure.ai.gemini_chat_agent.GeminiConversationAgent", _Boom)
    monkeypatch.setattr("src.infrastructure.secrets.get_gemini_api_key", lambda: secret)
    monkeypatch.setenv("RESEARCH_LIVE_PROVIDER", "1")
    monkeypatch.setenv("GEMINI_API_KEY", secret)
    monkeypatch.setenv(MODEL_VARIABLE, "secret-safety-model")

    with pytest.raises(Exception) as excinfo:
        collector_script.default_provider_factory()

    assert secret not in str(excinfo.value)
    assert secret not in repr(excinfo.value)
