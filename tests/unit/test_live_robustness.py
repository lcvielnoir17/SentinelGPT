"""M19 collector robustness: fences, stale files, pacing, bounded retry.

Every test here is offline: scripted doubles stand in for the provider
and a recording sleeper stands in for time. The suite exercises the
shipped ``collect_transcripts()``/``_collect_one()`` paths rather than
re-implementing them.
"""

from __future__ import annotations

import json
import pathlib

from src.research.live_collect import collect_transcripts
from src.research.live_prompts import get_prompt_set

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")
_FAKE_KEY = "k" * 30


def _dataset() -> dict:
    return json.loads(DATASET_PATH.read_text())


def _env() -> dict[str, str]:
    return {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": _FAKE_KEY}


def _valid_answer() -> dict:
    return {
        "summary": "One open gap.",
        "key_points": ["note"],
        "citations": [],
        "recommended_actions": ["Harden the header"],
        "compliance_notes": [],
    }


class _ScriptedAgent:
    """Provider double following a per-call script (replies or errors)."""

    def __init__(self, script: list) -> None:
        self._script = list(script)
        self.model = "fake-live-model"
        self.calls: list[dict] = []

    def respond(self, **kwargs: object) -> str:
        self.calls.append(dict(kwargs))
        action = self._script.pop(0) if self._script else json.dumps(_valid_answer())
        if isinstance(action, BaseException):
            raise action
        return action


class _Recorder:
    def __init__(self) -> None:
        self.sleeps: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.sleeps.append(seconds)


def _collect(agent: _ScriptedAgent, tmp_path: pathlib.Path, **kwargs: object) -> dict:
    return collect_transcripts(
        _dataset(), out_dir=tmp_path, agent=agent, environment=_env(), **kwargs
    )


def test_fenced_json_reply_accepted(tmp_path: pathlib.Path) -> None:
    """A schema-shaped reply in ```json fences is unwrapped, not malformed."""
    agent = _ScriptedAgent(["```json\n" + json.dumps(_valid_answer()) + "\n```"])
    summary = _collect(agent, tmp_path, pace_seconds=0)
    assert summary["attempts"][0]["outcome"] == "completed_accepted"
    stored = json.loads((tmp_path / "q01-priority.json").read_text())
    assert set(stored["response"]) == {
        "summary",
        "key_points",
        "citations",
        "recommended_actions",
        "compliance_notes",
    }
    assert "__malformed__" not in stored["response"]


def test_plain_json_reply_unchanged(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent([json.dumps(_valid_answer())])
    summary = _collect(agent, tmp_path, pace_seconds=0)
    assert summary["attempts"][0]["outcome"] == "completed_accepted"


def test_unclosed_fence_stays_malformed(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent(["```json\n" + json.dumps(_valid_answer())])
    summary = _collect(agent, tmp_path, pace_seconds=0)
    assert summary["attempts"][0]["outcome"] == "completed_rejected"
    stored = json.loads((tmp_path / "q01-priority.json").read_text())
    assert "__malformed__" in stored["response"]


def test_free_prose_stays_malformed(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent(["Here is my analysis in plain words with no JSON at all."])
    summary = _collect(agent, tmp_path, pace_seconds=0)
    assert summary["attempts"][0]["outcome"] == "completed_rejected"


def test_invalid_schema_inside_fences_still_rejected(tmp_path: pathlib.Path) -> None:
    """Fence-stripping never weakens the validator: bad content still fails."""
    agent = _ScriptedAgent(["```json\n" + json.dumps({"bogus": True}) + "\n```"])
    summary = _collect(agent, tmp_path, pace_seconds=0)
    assert summary["attempts"][0]["outcome"] == "completed_rejected"
    assert "summary is required" in summary["attempts"][0]["detail"]


def test_stale_per_question_file_removed_on_rerun(tmp_path: pathlib.Path) -> None:
    """A rerun that now fails must not silently reuse the old transcript."""
    stale = tmp_path / "q01-priority.json"
    stale.write_text(json.dumps({"stale": True}))
    # 500s are retryable: 12 prompts x (initial + one retry) exhaust the script.
    agent = _ScriptedAgent([RuntimeError("gemini error 500: boom")] * 24)
    summary = _collect(agent, tmp_path, pace_seconds=0)
    assert summary["transcripts_stored"] == 0
    assert not stale.exists()


def test_clearing_preserves_aggregates_and_foreign_files(tmp_path: pathlib.Path) -> None:
    aggregate = tmp_path / "live-transcripts.json"
    aggregate.write_text("[]")
    foreign = tmp_path / "notes.json"
    foreign.write_text("{}")
    agent = _ScriptedAgent([json.dumps(_valid_answer())] * 12)
    _collect(agent, tmp_path, pace_seconds=0)
    assert aggregate.read_text() == "[]"
    assert foreign.read_text() == "{}"


def test_pacing_sleeps_between_attempts(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent([json.dumps(_valid_answer())] * 12)
    recorder = _Recorder()
    _collect(agent, tmp_path, pace_seconds=5, sleeper=recorder)
    assert recorder.sleeps == [5.0] * 11


def test_no_pacing_by_default(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent([json.dumps(_valid_answer())] * 12)
    recorder = _Recorder()
    _collect(agent, tmp_path, pace_seconds=0, sleeper=recorder)
    assert recorder.sleeps == []


def test_retryable_failure_retried_once_then_succeeds(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent(
        [RuntimeError("gemini error 429: quota exceeded, please retry in 3s")]
        + [json.dumps(_valid_answer())] * 12
    )
    recorder = _Recorder()
    summary = _collect(agent, tmp_path, pace_seconds=0, sleeper=recorder)
    assert summary["attempts"][0]["outcome"] == "completed_accepted"
    assert recorder.sleeps == [3.0]


def test_persistent_retryable_failure_retried_once_only(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent([RuntimeError("gemini error 503: overloaded, retry in 4s")] * 30)
    recorder = _Recorder()
    summary = _collect(agent, tmp_path, pace_seconds=0, sleeper=recorder)
    assert summary["attempts"][0]["outcome"] == "provider_failed"
    assert "retried once" in summary["attempts"][0]["detail"]
    # One initial call plus exactly one retry per prompt; pacing disabled
    # so every recorded sleep is the honored retry-after hint.
    assert len(agent.calls) == 24
    assert recorder.sleeps == [4.0] * 12


def test_non_retryable_failure_not_retried(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent([RuntimeError("gemini error 404: NOT_FOUND no such model")] * 12)
    recorder = _Recorder()
    summary = _collect(agent, tmp_path, pace_seconds=0, sleeper=recorder)
    assert {a["outcome"] for a in summary["attempts"]} == {"provider_failed"}
    assert len(agent.calls) == 12
    assert recorder.sleeps == []
    assert "retried once" not in summary["attempts"][0]["detail"]


def test_timeout_not_retried(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent([TimeoutError("request timed out")] * 12)
    recorder = _Recorder()
    summary = _collect(agent, tmp_path, pace_seconds=0, sleeper=recorder)
    assert {a["outcome"] for a in summary["attempts"]} == {"timeout"}
    assert len(agent.calls) == 12
    assert recorder.sleeps == []


def test_retry_after_hint_capped(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent(
        [RuntimeError("gemini error 429: quota, please retry in 9999s")]
        + [json.dumps(_valid_answer())] * 12
    )
    recorder = _Recorder()
    summary = _collect(agent, tmp_path, pace_seconds=0, sleeper=recorder)
    assert summary["attempts"][0]["outcome"] == "completed_accepted"
    assert recorder.sleeps == [120.0]


def test_question_order_deterministic(tmp_path: pathlib.Path) -> None:
    agent = _ScriptedAgent([json.dumps(_valid_answer())] * 12)
    summary = _collect(agent, tmp_path, pace_seconds=0)
    expected = [p.question_id for p in get_prompt_set()]
    assert [a["question_id"] for a in summary["attempts"]] == expected


def test_live_entry_defaults_to_production_pacing() -> None:
    """Library default stays fast (0) while the shipped pacing constant is on."""
    import inspect

    from src.research import live_collect

    assert live_collect.PACING_DELAY_S > 0
    signature = inspect.signature(live_collect.collect_transcripts)
    assert signature.parameters["pace_seconds"].default == 0
