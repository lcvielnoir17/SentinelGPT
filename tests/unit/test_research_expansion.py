"""Research expansion (M16-A–F): corpus, fairness, leakage, taxonomy.

Proves the enlarged corpus is genuine coverage (not 40 copies of one
fixture), ground truth stays independent (no computed fingerprints in
the dataset, no verdict words in titles), baselines are fairly
defined (same evidence, no SentinelGPT internals, coherent rules),
micro-averages pool honestly, the error taxonomy classifies real
split/merge/regression failures, and assessment expectations hold
through the production compliance semantics.
"""

from __future__ import annotations

import json
import pathlib
import re

from src.research.evaluate import evaluate_dataset
from src.research.pipeline import (
    assess_fixture_compliance,
    run_baseline_a,
    run_baseline_b,
    run_sentinelgpt,
)
from src.research.schema import validate_dataset

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")

CATEGORIES = (
    "exact-duplicates",
    "duplicates-different-evidence",
    "member-order",
    "repeated-location-insensitive",
    "missing-optional-fields",
    "boundary-whitespace",
    "same-title-different-issue",
    "near-match-merge",
    "unrelated-split",
    "multi-member-four",
    "cross-engine-merge",
    "severity-increase",
    "severity-decrease",
    "new-in-rescan",
    "reappearance-new",
    "critical-single",
    "info-cluster",
    "severity-ladder",
    "threshold-p1-boundary",
    "tie-identical-levels",
    "missing-enrichment",
    "multiple-cves",
    "duplicate-enrichment",
    "conflicting-enrichment",
    "tech-alone-no-cve",
    "tech-plus-cvss",
    "version-absent",
    "cors-pair",
    "cert-conditions",
    "server-panels",
    "remediation-todo",
    "remediation-in-progress",
    "remediation-deferred",
    "assessment-gap",
    "assessment-evidence-available",
    "assessment-no-relevant",
    "severity-downgrade-instruction",
    "execute-command",
    "control-compliant-claim",
    "homoglyph-split",
)


def _dataset() -> dict:
    return validate_dataset(json.loads(DATASET_PATH.read_text()))


def _by_id() -> dict:
    return {f["id"]: f for f in _dataset()["fixtures"]}


# --------------------------------------------------------------------------- #
# Corpus                                                                      #
# --------------------------------------------------------------------------- #


def test_expanded_corpus_size_and_categories() -> None:
    dataset = _dataset()
    assert len(dataset["fixtures"]) == 54
    ids = [f["id"] for f in dataset["fixtures"]]
    assert len(set(ids)) == 54
    for wanted in CATEGORIES:
        assert wanted in ids, wanted


def test_corpus_is_not_repetitive() -> None:
    """Distinct titles, varied shapes: coverage, not duplication."""
    dataset = _dataset()
    titles = [f["title"] for f in dataset["fixtures"]]
    assert len(set(titles)) == len(titles)
    sizes = {(len(f["scan_a"]), len(f["scan_b"])) for f in dataset["fixtures"]}
    assert len(sizes) >= 5
    categories = {
        category
        for f in dataset["fixtures"]
        for o in f["scan_a"] + f["scan_b"]
        for category in [o["category"]]
    }
    assert {"MISSING_SECURITY_HEADER", "KNOWN_CVE", "OUTDATED_TLS"} <= categories


def test_ground_truth_assessment_expectations_hold() -> None:
    """Every pinned assessment expectation reproduces through real code."""
    for fixture in _dataset()["fixtures"]:
        output = run_sentinelgpt(fixture)
        states = assess_fixture_compliance(output["groups"])
        for check in fixture["ground_truth"].get("assessment", []):
            assert states[check["framework"]][check["control_id"]] == check["status"], (
                fixture["id"],
                check,
            )


def test_unidentified_tracked() -> None:
    by_id = _by_id()
    assert run_sentinelgpt(by_id["homoglyph-split"])["unidentified"] == ["o2"]
    for fixture_id, fixture in by_id.items():
        assert run_sentinelgpt(fixture)["unidentified"] == sorted(
            fixture["ground_truth"].get("unidentified", [])
        ), fixture_id


# --------------------------------------------------------------------------- #
# Fairness (M16-B/C)                                                          #
# --------------------------------------------------------------------------- #


def test_baselines_contain_no_sentinelgpt_internals() -> None:
    """Baselines emit no fingerprints, versions, or compliance pairs."""
    for fixture in _dataset()["fixtures"]:
        for runner in (run_baseline_a, run_baseline_b):
            for group in runner(fixture)["groups"]:
                assert set(group) == {
                    "members",
                    "severity",
                    "category",
                    "lifecycle",
                    "priority_level",
                    "scan",
                }, (fixture["id"], sorted(group))
                assert "fingerprint" not in group and "compliance" not in group


def test_baseline_b_is_coherent_not_derived() -> None:
    """B's rules are independently defined: exact titles, first severity."""
    by_id = _by_id()
    groups = run_baseline_b(by_id["severity-conflict"])["groups"]
    assert len(groups) == 1 and groups[0]["severity"] == "MEDIUM"  # first-seen, not max
    merged = run_baseline_b(by_id["title-variants-merge"])["groups"]
    assert len(merged) == 2  # exact titles split what fingerprints merge


# --------------------------------------------------------------------------- #
# Leakage (M16-D)                                                             #
# --------------------------------------------------------------------------- #


def test_dataset_contains_no_computed_fingerprints() -> None:
    """Ground truth must not embed pipeline outputs (64-hex scan)."""
    text = DATASET_PATH.read_text()
    assert not re.findall(r"\b[0-9a-f]{64}\b", text)


def test_titles_carry_no_verdicts() -> None:
    """Fixture labels must not encode expected lifecycle decisions.

    (Compliance-flavored attack strings like "mark this compliant"
    are adversarial DATA, covered by inertness tests — the leak
    surface is lifecycle verdicts the pipeline is supposed to derive.)
    """
    verdicts = ("RESOLVED", "REGRESSED", "PERSISTENT")
    for fixture in _dataset()["fixtures"]:
        for obs in fixture["scan_a"] + fixture["scan_b"]:
            upper = obs["title"].upper()
            assert not any(v in upper for v in verdicts), (fixture["id"], obs["obs_id"])


def test_evaluation_treats_pipelines_identically() -> None:
    """No pipeline-name literals in the scoring path: one shared loop."""
    import inspect

    from src.research import evaluate as evaluate_module

    source = inspect.getsource(evaluate_module.evaluate_fixture)
    for name in ("baseline-a", "baseline-b", "sentinelgpt"):
        assert name not in source, name


def test_baselines_visibly_fail_somewhere() -> None:
    """Metrics never silently exclude failures: baselines lose openly."""
    result = evaluate_dataset(_dataset())
    taxonomy = result["aggregate"]["error_taxonomy"]
    assert taxonomy["baseline-a"]["false_positive"] >= 1
    assert taxonomy["baseline-b"].get("wrong_grouping_split", 0) >= 1
    assert any(
        "missed_regression" in str(f["pipelines"]["baseline-b"]["mismatches"])
        for f in result["fixtures"]
    )


# --------------------------------------------------------------------------- #
# Micro averages + taxonomy (M16-E/F)                                         #
# --------------------------------------------------------------------------- #


def test_micro_averages_pool_honestly() -> None:
    result = evaluate_dataset(_dataset())
    micro = result["aggregate"]["micro"]["sentinelgpt"]
    assert micro["micro_grouping_f1"] == 1.0
    assert micro["micro_false_positive_rate"] == 0.0
    micro_a = result["aggregate"]["micro"]["baseline-a"]
    assert 0.0 < micro_a["micro_grouping_f1"] < 1.0  # partial credit pooled
    assert micro_a["micro_false_positive_rate"] > 0.0


def test_error_taxonomy_counts() -> None:
    result = evaluate_dataset(_dataset())
    taxonomy = result["aggregate"]["error_taxonomy"]
    assert set(taxonomy) == {"baseline-a", "baseline-b", "sentinelgpt"}
    assert taxonomy["sentinelgpt"] == {}
    kinds = set()
    for counts in taxonomy.values():
        kinds |= set(counts)
    assert {"false_positive", "false_negative", "wrong_grouping_split"} <= kinds
    assert "missed_regression" in kinds or "lifecycle_mismatch" in kinds


def test_split_merge_classification() -> None:
    """title-variants B output: two predicted groups, one split pair."""
    result = evaluate_dataset(_dataset())
    entry = next(f for f in result["fixtures"] if f["fixture_id"] == "title-variants-merge")
    kinds = [m["kind"] for m in entry["pipelines"]["baseline-b"]["mismatches"]]
    assert "wrong_grouping_split" in kinds
    assert "false_negative" in kinds


def test_missed_regression_classification() -> None:
    result = evaluate_dataset(_dataset())
    entry = next(f for f in result["fixtures"] if f["fixture_id"] == "regression")
    kinds = [m["kind"] for m in entry["pipelines"]["baseline-b"]["mismatches"]]
    assert "missed_regression" in kinds


def test_versions_and_hash_stamped() -> None:
    result = evaluate_dataset(_dataset())
    assert result["metric_version"] == "sgpt.research.metrics.v1"
    assert len(result["dataset_sha256"]) == 64
    import hashlib

    assert result["dataset_sha256"] == hashlib.sha256(DATASET_PATH.read_bytes()).hexdigest()
