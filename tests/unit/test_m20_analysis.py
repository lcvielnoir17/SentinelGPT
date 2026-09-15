"""M20 combined analysis: deterministic builder behavior (offline only).

All fixtures here are synthetic: live quarantine directories are
assembled with scripted provider doubles through the real
collect/transcript paths, never with network calls.
"""

from __future__ import annotations

import json
import pathlib

from scripts import analyze_research_results as analyzer

from src.research.live_collect import collect_transcripts
from src.research.live_prompts import get_prompt_set

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")
_FAKE_KEY = "k" * 30


def _dataset() -> dict:
    return json.loads(DATASET_PATH.read_text())


def _answer() -> dict:
    return {
        "summary": "One open gap.",
        "key_points": ["note"],
        "citations": [],
        "recommended_actions": ["Harden the header"],
        "compliance_notes": [],
    }


class _FakeAgent:
    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.model = "fake-live-model"

    def respond(self, **_kwargs: object) -> object:
        if isinstance(self.reply, BaseException):
            raise self.reply
        return self.reply


def _make_live_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Assemble a synthetic quarantine dir through shipped code paths."""
    from src.research.live_artifacts import write_artifacts
    from src.research.live_metrics import evaluate_attempts
    from src.research.transcripts import replay_all

    live_dir = tmp_path / "quarantine"
    agent = _FakeAgent(json.dumps(_answer()))
    summary = collect_transcripts(
        _dataset(),
        out_dir=live_dir,
        agent=agent,
        environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": _FAKE_KEY},
        pace_seconds=0,
    )
    assert summary["transcripts_stored"] == 12
    from src.research.live_discovery import discover_transcripts

    transcripts = discover_transcripts(live_dir)
    replays = replay_all(_dataset(), transcripts)
    metrics = evaluate_attempts(summary["attempts"], replays)
    write_artifacts(
        live_dir,
        transcripts=transcripts,
        replays=replays,
        metrics=metrics,
        metadata={"provider": "p", "model": "m"},
    )
    return live_dir


def test_builder_produces_seven_canonical_files(tmp_path: pathlib.Path) -> None:
    live_dir = _make_live_dir(tmp_path)
    package = analyzer.build_package(_dataset(), live_dir)
    assert sorted(package) == [
        "combined-summary.json",
        "deterministic-results.json",
        "error-analysis.json",
        "live-provider-results.json",
        "provider-failures.json",
        "research-tables.json",
        "validator-analysis.json",
    ]
    live = package["live-provider-results.json"]
    assert live["transcript_count"] == 12
    assert [a["question_id"] for a in live["attempts"]] == [p.question_id for p in get_prompt_set()]
    for name, payload in package.items():
        text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        assert json.loads(text) == payload, name


def test_limitations_name_outstanding_measures(tmp_path: pathlib.Path) -> None:
    live_dir = _make_live_dir(tmp_path)
    package = analyzer.build_package(_dataset(), live_dir)
    limitations = package["combined-summary.json"]["limitations"]
    assert (
        "No independent expert-judgment or analyst-timing study was conducted; "
        "these planned measures remain outstanding." in limitations
    )
    assert package["combined-summary.json"]["threats_to_validity"] == limitations


def test_builder_rejects_hash_mismatch(tmp_path: pathlib.Path) -> None:
    import pytest

    live_dir = _make_live_dir(tmp_path)
    stored = json.loads((live_dir / "live-transcripts.json").read_text())
    stored[0]["evidence_hash"] = "f" * 64
    (live_dir / "live-transcripts.json").write_text(json.dumps(stored))
    with pytest.raises(analyzer.IntegrityError, match="hash mismatch"):
        analyzer.build_package(_dataset(), live_dir)


def test_builder_handles_empty_live_dir(tmp_path: pathlib.Path) -> None:
    live_dir = tmp_path / "empty"
    live_dir.mkdir()
    (live_dir / "live-transcripts.json").write_text("[]")
    (live_dir / "live-evaluation.json").write_text(
        json.dumps({"attempts_by_outcome": {}, "attempt_diagnostics": []})
    )
    (live_dir / "live-metadata.json").write_text(json.dumps({"provider": "p", "model": "m"}))
    package = analyzer.build_package(_dataset(), live_dir)
    assert package["live-provider-results.json"]["transcript_count"] == 0
    assert package["provider-failures.json"] == {"failures": []}


def test_secret_tripwire_blocks_write(tmp_path: pathlib.Path) -> None:
    live_dir = _make_live_dir(tmp_path)
    evaluation = json.loads((live_dir / "live-evaluation.json").read_text())
    evaluation["attempt_diagnostics"][0]["detail"] = "leak GEMINI_API_KEY=topsecret123"
    (live_dir / "live-evaluation.json").write_text(json.dumps(evaluation))
    assert analyzer.main(["--live-dir", str(live_dir), "--out", str(tmp_path / "out")]) == 2


def test_builder_deterministic_bytes(tmp_path: pathlib.Path) -> None:
    live_dir = _make_live_dir(tmp_path)
    dataset = _dataset()
    first = {
        name: json.dumps(payload, indent=2, sort_keys=True) + "\n"
        for name, payload in analyzer.build_package(dataset, live_dir).items()
    }
    second = {
        name: json.dumps(payload, indent=2, sort_keys=True) + "\n"
        for name, payload in analyzer.build_package(dataset, live_dir).items()
    }
    assert first == second


def test_main_missing_live_dir_returns_usage_error(tmp_path: pathlib.Path) -> None:
    assert (
        analyzer.main(["--live-dir", str(tmp_path / "absent"), "--out", str(tmp_path / "out")]) == 2
    )
