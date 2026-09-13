"""Research metrics & evaluation (M14): formulas, mismatches, aggregates.

Proves every metric against hand-computed values (perfect runs score
1.0, engineered failures score exactly as the formulas dictate, empty
inputs report None instead of misleading zeros), that evaluation
exposes per-fixture mismatches verbatim, that aggregates are honest
means, and that the whole dataset evaluates deterministically offline.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from src.research import metrics
from src.research.evaluate import evaluate_dataset, evaluate_fixture
from src.research.schema import DATASET_VERSION, validate_dataset

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")


def _dataset() -> dict:
    return validate_dataset(json.loads(DATASET_PATH.read_text()))


def _groups(*member_lists: list[str]) -> list[set[str]]:
    return [set(members) for members in member_lists]


# --------------------------------------------------------------------------- #
# Formula unit proofs                                                         #
# --------------------------------------------------------------------------- #


def test_grouping_perfect_scores() -> None:
    predicted = _groups(["a", "b"], ["c"])
    scores = metrics.grouping_scores(predicted, [set(g) for g in predicted])
    assert scores == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_grouping_split_and_merge() -> None:
    # Exact member-set matching: a split matches nothing (honest zeros).
    scores = metrics.grouping_scores(_groups(["a"], ["b"]), _groups(["a", "b"]))
    assert scores["precision"] == 0.0
    assert scores["recall"] == 0.0
    assert scores["f1"] == 0.0


def test_grouping_empty_conventions() -> None:
    assert metrics.grouping_scores([], []) == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    empty_predicted = metrics.grouping_scores([], _groups(["a"]))
    assert empty_predicted["precision"] is None and empty_predicted["recall"] == 0.0
    assert empty_predicted["f1"] is None


def test_duplicate_reduction_rate() -> None:
    assert metrics.duplicate_reduction_rate(1, 3) == pytest.approx(2 / 3)
    assert metrics.duplicate_reduction_rate(3, 3) == 0.0
    assert metrics.duplicate_reduction_rate(0, 0) is None


def test_field_agreement() -> None:
    predicted = [{"severity": "HIGH"}, {"severity": "LOW"}]
    expected = [{"severity": "HIGH"}, {"severity": "MEDIUM"}]
    assert metrics.field_agreement(predicted, expected, [(0, 0), (1, 1)], "severity") == 0.5
    assert metrics.field_agreement(predicted, expected, [], "severity") is None


def test_detection_rates() -> None:
    expected = [
        {"key": "a", "lifecycle": "REGRESSED"},
        {"key": "b", "lifecycle": "NEW"},
    ]
    by_key = {"a": {"lifecycle": "REGRESSED"}}
    assert metrics.detection_rate(expected, by_key, "REGRESSED") == 1.0
    assert metrics.detection_rate(expected, {}, "REGRESSED") == 0.0
    assert metrics.detection_rate(expected, by_key, "RESOLVED") is None


def test_false_rates() -> None:
    assert metrics.false_positive_rate(_groups(["a"], ["x"]), _groups(["a"])) == 0.5
    assert metrics.false_negative_rate(_groups(["a"]), _groups(["a"], ["y"])) == 0.5
    assert metrics.false_positive_rate([], _groups(["a"])) is None
    assert metrics.false_negative_rate(_groups(["a"]), []) is None


def test_kendall_tau() -> None:
    assert metrics.kendall_tau_b({"a": 4, "b": 2}, {"a": 4, "b": 2}) == 1.0
    assert metrics.kendall_tau_b({"a": 2, "b": 4}, {"a": 4, "b": 2}) == -1.0
    # Ties on either side are skipped, not counted.
    assert metrics.kendall_tau_b({"a": 4, "b": 4, "c": 1}, {"a": 4, "b": 2, "c": 1}) == 1.0
    assert metrics.kendall_tau_b({"a": 1}, {"a": 1}) is None
    assert metrics.kendall_tau_b({}, {}) is None


def test_citation_and_grounding_rates() -> None:
    assert metrics.citation_validity(3, 4) == 0.75
    assert metrics.citation_validity(0, 0) is None
    assert metrics.evidence_grounding_rate([{"evidence_count": 2}, {"evidence_count": 0}]) == 0.5
    assert metrics.evidence_grounding_rate([]) is None


# --------------------------------------------------------------------------- #
# Evaluation honesty                                                          #
# --------------------------------------------------------------------------- #


def test_sentinelgpt_perfect_grouping_on_dataset() -> None:
    """The curated dataset is solvable: SentinelGPT matches every group."""
    for fixture in _dataset()["fixtures"]:
        entry = evaluate_fixture(fixture)["pipelines"]["sentinelgpt"]
        assert entry["metrics"]["grouping_f1"] == 1.0, fixture["id"]
        assert entry["mismatches"] == [], fixture["id"]


def test_baselines_show_honest_mismatches() -> None:
    """Baselines visibly fail where they must (nothing hidden)."""
    dataset = _dataset()
    by_id = {f["id"]: evaluate_fixture(f) for f in dataset["fixtures"]}
    # Scanner-only cannot deduplicate or resolve: singletons match nothing.
    dup = by_id["dup-headers-01"]["pipelines"]["baseline-a"]
    assert dup["metrics"]["grouping_f1"] == 0.0
    assert dup["metrics"]["grouping_precision"] == 0.0
    assert dup["metrics"]["grouping_recall"] == 0.0
    assert any(m["kind"] == "false_positive" for m in dup["mismatches"])
    # Rule-based splits the title variant the fingerprint merges.
    variants = by_id["title-variants-merge"]["pipelines"]["baseline-b"]
    assert variants["metrics"]["grouping_recall"] == 0.0
    # Rule-based has no history: regression reads as NEW.
    regressed = by_id["regression"]["pipelines"]["baseline-b"]
    assert regressed["metrics"]["regression_detection_rate"] == 0.0
    assert any(m["kind"] == "lifecycle_mismatch" for m in regressed["mismatches"])
    # Scanner-only never resolves.
    resolved = by_id["resolution"]["pipelines"]["baseline-a"]
    assert resolved["metrics"]["resolution_detection_rate"] == 0.0


def test_severity_rule_contrast() -> None:
    """First-seen (B) vs max-rank (SentinelGPT) disagree by construction."""
    entry = evaluate_fixture(
        next(f for f in _dataset()["fixtures"] if f["id"] == "severity-conflict")
    )
    assert entry["pipelines"]["baseline-b"]["metrics"]["severity_consistency"] == 0.0
    assert entry["pipelines"]["sentinelgpt"]["metrics"]["severity_consistency"] == 1.0


def test_mismatch_schema() -> None:
    for fixture in _dataset()["fixtures"]:
        for pipeline, result in evaluate_fixture(fixture)["pipelines"].items():
            for mismatch in result["mismatches"]:
                assert mismatch["pipeline"] == pipeline
                assert mismatch["kind"] in {
                    "false_positive",
                    "false_negative",
                    "severity_mismatch",
                    "lifecycle_mismatch",
                    "priority_level_mismatch",
                }


def test_aggregate_is_honest_mean() -> None:
    result = evaluate_dataset(_dataset())
    assert result["dataset_version"] == DATASET_VERSION
    assert result["pipeline_version"].startswith("sgpt.research.pipeline.v")
    assert set(result["baseline_definitions"]) == {"baseline-a", "baseline-b", "sentinelgpt"}
    assert "grouping_precision" in result["metric_definitions"]
    sentinel = result["aggregate"]["sentinelgpt"]
    assert sentinel["grouping_f1"] == 1.0
    assert sentinel["fixture_count"] == 14
    # Baseline A cannot resolve anything anywhere it matters.
    assert result["aggregate"]["baseline-a"]["resolution_detection_rate"] == 0.0
    # Every aggregate mean recomputes from fixture values (no hidden math).
    for name in ("baseline-a", "baseline-b", "sentinelgpt"):
        values = [
            f["pipelines"][name]["metrics"]["grouping_f1"]
            for f in result["fixtures"]
            if isinstance(f["pipelines"][name]["metrics"]["grouping_f1"], float)
        ]
        assert result["aggregate"][name]["grouping_f1"] == sum(values) / len(values)


def test_evaluation_deterministic() -> None:
    dataset = _dataset()
    first = evaluate_dataset(dataset)
    second = evaluate_dataset(validate_dataset(json.loads(DATASET_PATH.read_text())))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_empty_scope_behavior() -> None:
    """Single-scan fixtures still resolve; validator surface stays typed."""
    fixture = next(f for f in _dataset()["fixtures"] if f["id"] == "tls-weaknesses")
    entry = evaluate_fixture(fixture)["pipelines"]["sentinelgpt"]
    assert entry["metrics"]["regression_detection_rate"] is None
    assert entry["metrics"]["resolution_detection_rate"] is None


def test_expected_metric_values_documented() -> None:
    """Spot-check hand-computed aggregates (formulas, not vibes)."""
    result = evaluate_dataset(_dataset())
    dup_b = next(f for f in result["fixtures"] if f["fixture_id"] == "dup-headers-01")["pipelines"][
        "baseline-b"
    ]["metrics"]
    # Exact-title grouping merges all three: perfect grouping, first-seen MEDIUM.
    assert dup_b["grouping_f1"] == 1.0
    assert dup_b["severity_consistency"] == 1.0
    assert dup_b["duplicate_reduction_rate"] == pytest.approx(2 / 3)


# --------------------------------------------------------------------------- #
# AI evaluation as interpretation (scripted provider, M12 validator)          #
# --------------------------------------------------------------------------- #


def _scripted_answer(finding_id: str = "f-1", control_id: str = "4.2") -> dict:
    return {
        "summary": "One open gap.",
        "key_points": ["fp-1 is new"],
        "citations": [{"finding_id": finding_id, "note": "open"}],
        "recommended_actions": ["Harden the header"],
        "compliance_notes": [{"control_id": control_id, "note": "gap"}],
    }


def _scripted_evidence() -> object:
    from src.domain.investigation.evidence import InvestigationEvidence

    return InvestigationEvidence(
        target_id="t",
        scan_id="s",
        scan_status="REPORT_READY",
        generated_at="2026-01-01T00:00:00+00:00",
        finding_ids=frozenset({"f-1"}),
        evidence_ids=frozenset({"ev-1"}),
        control_ids=frozenset({"4.2"}),
        cve_set=frozenset({"CVE-2024-1234"}),
    )


def test_citation_validity_with_validator() -> None:
    """Valid script accepted; unknown/invented references rejected."""
    from src.domain.investigation.validator import validate_investigation_response

    evidence = _scripted_evidence()
    accepted = validate_investigation_response(_scripted_answer(), evidence).accepted
    assert accepted is True
    rejected = [
        _scripted_answer(finding_id="ghost"),
        {
            "summary": "x",
            "key_points": [],
            "citations": [],
            "recommended_actions": [],
            "compliance_notes": [{"control_id": "9.9", "note": "x"}],
        },
        {**_scripted_answer(), "summary": "CVE-2099-0001 is critical."},
    ]
    for reply in rejected:
        assert validate_investigation_response(reply, evidence).accepted is False
    assert metrics.citation_validity(1, 4) == 0.25


def test_prompt_injection_fixture_scores_clean() -> None:
    """The adversarial fixture groups exactly; injection text changes nothing."""
    entry = evaluate_fixture(
        next(f for f in _dataset()["fixtures"] if f["id"] == "prompt-injection")
    )["pipelines"]["sentinelgpt"]
    assert entry["metrics"]["grouping_f1"] == 1.0
    assert entry["mismatches"] == []


def test_runner_functions_are_pure() -> None:
    """Pipeline entry points take fixtures, return dicts, touch no I/O."""
    import inspect

    from src.research import evaluate as evaluate_module
    from src.research import pipeline as pipeline_module

    for module in (pipeline_module, evaluate_module):
        source = inspect.getsource(module)
        for banned in ("open(", "socket", "httpx", "requests", "session."):
            assert banned not in source, (module.__name__, banned)
