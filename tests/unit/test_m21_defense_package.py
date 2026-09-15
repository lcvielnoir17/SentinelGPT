"""M21 defense package builder behavior (offline only).

Tests run the shipped builder against the real M20 results inputs
assembled through shipped code paths; no network calls are made.
"""

from __future__ import annotations

import json
import pathlib

from scripts import analyze_research_results as analyzer
from scripts import build_defense_package as defense

from src.research.live_collect import collect_transcripts

EXPECTED_FILES = [
    "claim-matrix.json",
    "conclusion.md",
    "defense-questions.md",
    "discussion.md",
    "executive-summary.md",
    "human-review.md",
    "limitations.md",
    "reproducibility.md",
    "research-methodology.md",
    "results.md",
    "tables.json",
]

EXPECTED_FIGURES = [
    "grouping-f1.svg",
    "live-outcomes.svg",
    "priority-agreement.svg",
    "regression-resolution.svg",
]

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")
_FAKE_KEY = "k" * 30


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


def _make_inputs(tmp_path: pathlib.Path) -> pathlib.Path:
    """Assemble real M20 results inputs through shipped code paths."""
    from src.research.live_artifacts import write_artifacts
    from src.research.live_discovery import discover_transcripts
    from src.research.live_metrics import evaluate_attempts
    from src.research.transcripts import replay_all

    dataset = json.loads(DATASET_PATH.read_text())
    live_dir = tmp_path / "quarantine"
    agent = _FakeAgent(json.dumps(_answer()))
    summary = collect_transcripts(
        dataset,
        out_dir=live_dir,
        agent=agent,
        environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": _FAKE_KEY},
        pace_seconds=0,
    )
    assert summary["transcripts_stored"] == 12
    transcripts = discover_transcripts(live_dir)
    replays = replay_all(dataset, transcripts)
    metrics = evaluate_attempts(summary["attempts"], replays)
    write_artifacts(
        live_dir,
        transcripts=transcripts,
        replays=replays,
        metrics=metrics,
        metadata={"provider": "p", "model": "m"},
    )
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    package = analyzer.build_package(dataset, live_dir)
    for name, payload in package.items():
        (results_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return results_dir


def test_builder_writes_complete_package(tmp_path: pathlib.Path) -> None:
    results_dir = _make_inputs(tmp_path)
    out_dir = tmp_path / "defense"
    assert defense.main(["--results-dir", str(results_dir), "--out", str(out_dir)]) == 0
    assert sorted(p.name for p in out_dir.iterdir() if p.is_file()) == EXPECTED_FILES
    assert sorted(p.name for p in (out_dir / "figures").iterdir()) == EXPECTED_FIGURES
    for figure in EXPECTED_FIGURES:
        text = (out_dir / "figures" / figure).read_text()
        assert text.startswith("<svg") and text.rstrip().endswith("</svg>")


def test_numbers_trace_to_inputs(tmp_path: pathlib.Path) -> None:
    results_dir = _make_inputs(tmp_path)
    files = defense.build_package(results_dir)
    tables = json.loads(files["tables.json"])
    assert (
        tables["table_3_deterministic_metric_comparison"]["per_pipeline"]["sentinelgpt"][
            "grouping_f1"
        ]
        == 1.0
    )
    results_md = files["results.md"]
    assert "## Table 1" in results_md and "## Table 10" in results_md
    assert "NOT representative" in files["figures/live-outcomes.svg"]
    assert "Controlled synthetic evaluation" in files["executive-summary.md"]
    assert "PENDING HUMAN REVIEW" in files["human-review.md"]
    assert "100% accurate" not in files["conclusion.md"]
    assert "proven superior" not in files["conclusion.md"].lower()
    assert "universally superior" not in files["conclusion.md"].lower()


def test_builder_missing_input_fails_closed(tmp_path: pathlib.Path) -> None:
    assert defense.main(["--results-dir", str(tmp_path / "absent")]) == 2


def test_builder_deterministic_bytes(tmp_path: pathlib.Path) -> None:
    results_dir = _make_inputs(tmp_path)
    first = defense.build_package(results_dir)
    second = defense.build_package(results_dir)
    assert first == second


def test_review_completion_counts_sections(tmp_path: pathlib.Path) -> None:
    from src.research.live_review import review_completion

    assert review_completion("") == (0, 0)
    assert review_completion("## q01 (f)\n- Reviewer/date: PENDING HUMAN REVIEW\n") == (0, 1)
    assert review_completion("## q01 (f)\n- Reviewer/date: Karl / today\n") == (1, 1)


def test_completed_review_updates_narrative(tmp_path: pathlib.Path) -> None:
    results_dir = _make_inputs(tmp_path)
    review = (
        "## q01 (f)\n- Human usefulness assessment: Moderately useful\n"
        "- Reviewer/date: Karl / today\n"
        "## q02 (f)\n- Human usefulness assessment: Moderately useful\n"
        "- Reviewer/date: Karl / today\n"
    )
    files = defense.build_package(results_dir, human_review_text=review)
    assert "Moderately useful" in files["discussion.md"]
    assert "review pending" not in files["discussion.md"]
    assert "broader human evaluation" in files["conclusion.md"]
    assert "human usefulness review," not in files["defense-questions.md"]


def test_absent_review_keeps_pending_wording(tmp_path: pathlib.Path) -> None:
    results_dir = _make_inputs(tmp_path)
    files = defense.build_package(results_dir)
    assert "review pending" in files["discussion.md"]
    assert files["discussion.md"].count("Moderately useful") == 0


def test_completed_review_preserved_on_rebuild(tmp_path: pathlib.Path) -> None:
    """A completed human review is never overwritten by the template."""
    results_dir = _make_inputs(tmp_path)
    out_dir = tmp_path / "defense"
    assert defense.main(["--results-dir", str(results_dir), "--out", str(out_dir)]) == 0
    completed = (
        out_dir / "human-review.md"
    ).read_text() + "\n- Reviewer/date: Test Human / today\n"
    (out_dir / "human-review.md").write_text(completed)
    assert defense.main(["--results-dir", str(results_dir), "--out", str(out_dir)]) == 0
    assert (out_dir / "human-review.md").read_text() == completed


def test_fresh_dir_receives_pending_template(tmp_path: pathlib.Path) -> None:
    results_dir = _make_inputs(tmp_path)
    out_dir = tmp_path / "defense"
    assert defense.main(["--results-dir", str(results_dir), "--out", str(out_dir)]) == 0
    assert "PENDING HUMAN REVIEW" in (out_dir / "human-review.md").read_text()
