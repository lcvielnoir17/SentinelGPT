"""Deterministic evaluation runner: baselines vs SentinelGPT (M14).

For every fixture, all three pipelines consume the same observations;
each pipeline's groups are scored against the same ground truth, and
every mismatch is listed explicitly — nothing is hidden, averaged
away, or rounded up. Aggregates are means over fixtures with
unambiguous denominators; dimensions without data report None,
never 0. The result structure carries dataset/pipeline versions,
baseline definitions, metric definitions, raw values, mismatches,
and limitations, so a reader can reproduce or dispute any number.
"""

from __future__ import annotations

from typing import Any

from src.research import metrics
from src.research.metrics import METRIC_VERSION
from src.research.pipeline import run_baseline_a, run_baseline_b, run_sentinelgpt
from src.research.schema import DATASET_VERSION

PIPELINE_VERSION = "sgpt.research.pipeline.v1"

BASELINE_DEFINITIONS = {
    "baseline-a": (
        "Scanner-only: one finding per observation, as-reported severity, "
        "lifecycle always NEW, no priority, no compliance mapping."
    ),
    "baseline-b": (
        "Rule-based: exact normalized-title groups per category, "
        "first-seen severity, derive() lifecycle without history, static "
        "severity-to-priority map, no compliance mapping."
    ),
    "sentinelgpt": (
        "Full deterministic pipeline: fingerprint grouping, max-rank "
        "severity, lifecycle derivation with history, priority v2 with "
        "CVE/CVSS/technology signals, curated compliance mapping."
    ),
}

METRIC_DEFINITIONS = {
    "grouping_precision": "exact member-set matches / predicted groups",
    "grouping_recall": "exact member-set matches / expected canonical",
    "grouping_f1": "harmonic mean of grouping precision and recall",
    "duplicate_reduction_rate": "1 - groups / observations",
    "severity_consistency": "matched groups with expected severity / matches",
    "priority_agreement": "matched groups with expected level / matches",
    "ranking_tau_b": "Kendall tau-b over priority ranks (ties skipped)",
    "regression_detection_rate": "expected REGRESSED reproduced / expected REGRESSED",
    "resolution_detection_rate": "expected RESOLVED reproduced / expected RESOLVED",
    "false_positive_rate": "predicted groups matching nothing / predicted",
    "false_negative_rate": "expected groups matched by nothing / expected",
    "evidence_grounding_rate": "groups with >=1 evidence ref / groups",
    "micro_grouping_precision": "pooled member sets (fixture-prefixed) precision",
    "micro_grouping_recall": "pooled member sets (fixture-prefixed) recall",
    "micro_grouping_f1": "pooled member sets F1",
    "micro_false_positive_rate": "pooled false-positive rate",
    "micro_false_negative_rate": "pooled false-negative rate",
    "error_<kind>": "count of inspectable mismatch kind per pipeline",
}

PIPELINES = {
    "baseline-a": run_baseline_a,
    "baseline-b": run_baseline_b,
    "sentinelgpt": run_sentinelgpt,
}


def evaluate_fixture(fixture: dict[str, Any]) -> dict[str, Any]:
    """Score all pipelines on one fixture (mismatches listed verbatim)."""
    expected = fixture["ground_truth"]["canonical"]
    expected_sets = [set(e["members"]) for e in expected]
    observation_count = len(fixture["scan_a"]) + len(fixture["scan_b"])
    results: dict[str, Any] = {}
    for name, runner in PIPELINES.items():
        output = runner(fixture)
        predicted_sets = [set(g["members"]) for g in output["groups"]]
        matches = metrics.exact_matches(predicted_sets, expected_sets)
        scores = metrics.grouping_scores(predicted_sets, expected_sets)
        keyed = _keyed_predictions(output["groups"], expected, matches)
        result_metrics: dict[str, float | None] = {
            "grouping_precision": scores["precision"],
            "grouping_recall": scores["recall"],
            "grouping_f1": scores["f1"],
            "duplicate_reduction_rate": metrics.duplicate_reduction_rate(
                len(output["groups"]), observation_count
            ),
            "severity_consistency": metrics.field_agreement(
                output["groups"], expected, matches, "severity"
            ),
            "priority_agreement": metrics.field_agreement(
                output["groups"], expected, matches, "priority_level"
            ),
            "ranking_tau_b": metrics.kendall_tau_b(
                _priority_ranks(keyed), _priority_ranks({str(e["key"]): e for e in expected})
            ),
            "regression_detection_rate": metrics.detection_rate(expected, keyed, "REGRESSED"),
            "resolution_detection_rate": metrics.detection_rate(expected, keyed, "RESOLVED"),
            "false_positive_rate": metrics.false_positive_rate(predicted_sets, expected_sets),
            "false_negative_rate": metrics.false_negative_rate(predicted_sets, expected_sets),
            "evidence_grounding_rate": metrics.evidence_grounding_rate(output["groups"]),
        }
        results[name] = {
            "metrics": result_metrics,
            "mismatches": _mismatches(name, output["groups"], expected, matches),
        }
    return {"fixture_id": fixture["id"], "pipelines": results}


def evaluate_dataset(dataset: dict[str, Any]) -> dict[str, Any]:
    """Evaluate every fixture; aggregate by mean over defined values."""
    fixtures = [evaluate_fixture(f) for f in dataset["fixtures"]]
    aggregate: dict[str, Any] = {}
    for name in PIPELINES:
        per_metric: dict[str, list[float]] = {}
        keys: set[str] = set()
        for entry in fixtures:
            for metric, value in entry["pipelines"][name]["metrics"].items():
                keys.add(metric)
                if isinstance(value, (int, float)):
                    per_metric.setdefault(metric, []).append(float(value))
        aggregate[name] = {
            metric: (
                sum(per_metric[metric]) / len(per_metric[metric]) if metric in per_metric else None
            )
            for metric in sorted(keys)
        }
        aggregate[name]["fixture_count"] = len(fixtures)
    aggregate["micro"] = _micro_averages(dataset)
    aggregate["error_taxonomy"] = _error_taxonomy(fixtures)
    return {
        "dataset_version": dataset.get("dataset_version", DATASET_VERSION),
        "pipeline_version": PIPELINE_VERSION,
        "metric_version": METRIC_VERSION,
        "dataset_sha256": _dataset_sha256(),
        "baseline_definitions": dict(BASELINE_DEFINITIONS),
        "metric_definitions": dict(METRIC_DEFINITIONS),
        "fixtures": fixtures,
        "aggregate": aggregate,
        "limitations": [
            "Synthetic fixtures only: results do not transfer to live targets.",
            "Matching is exact member-set equality; near-misses count as full misses.",
            "Priority ground truth pins v2 outputs; a priority-algorithm change "
            "requires re-pinning expectations, not code.",
            "Macro aggregates weight every fixture equally; micro aggregates "
            "pool member sets across fixtures (prefixed by fixture id)."
            "Error taxonomy counts inspectable mismatch kinds per pipeline.",
        ],
    }


def _micro_averages(dataset: dict[str, Any]) -> dict[str, Any]:
    """Pool member sets across fixtures (fixture-prefixed) for rate metrics.

    Micro-averaging is mathematically appropriate for precision/recall
    style rates: every observation weighs equally regardless of which
    fixture it belongs to. Fixture-id prefixing prevents obs-id
    collisions between fixtures from merging identities.
    """
    micro: dict[str, Any] = {}
    for name in PIPELINES:
        pooled_predicted: list[set[str]] = []
        pooled_expected: list[set[str]] = []
        for raw in dataset["fixtures"]:
            prefix = str(raw["id"]) + "|"
            output = PIPELINES[name](raw)
            for group in output["groups"]:
                pooled_predicted.append({prefix + str(m) for m in group["members"]})
            for want in raw["ground_truth"]["canonical"]:
                pooled_expected.append({prefix + str(m) for m in want["members"]})
        scores = metrics.grouping_scores(pooled_predicted, pooled_expected)
        micro[name] = {
            "micro_grouping_precision": scores["precision"],
            "micro_grouping_recall": scores["recall"],
            "micro_grouping_f1": scores["f1"],
            "micro_false_positive_rate": metrics.false_positive_rate(
                pooled_predicted, pooled_expected
            ),
            "micro_false_negative_rate": metrics.false_negative_rate(
                pooled_predicted, pooled_expected
            ),
        }
    return micro


def _error_taxonomy(evaluated: list[dict[str, Any]]) -> dict[str, Any]:
    """Inspectable mismatch-kind counts per pipeline (no hidden failures)."""
    taxonomy: dict[str, Any] = {}
    for entry in evaluated:
        for name in PIPELINES:
            counts = taxonomy.setdefault(name, {})
            for mismatch in entry["pipelines"][name]["mismatches"]:
                kind = str(mismatch["kind"])
                counts[kind] = counts.get(kind, 0) + 1
    for name in PIPELINES:
        taxonomy.setdefault(name, {})
    return taxonomy


def _dataset_sha256() -> str:
    """Hex digest of the exact dataset bytes evaluated (reproducibility pin)."""
    import hashlib
    import pathlib

    raw = pathlib.Path("backend/src/research/dataset.json").read_bytes()
    return hashlib.sha256(raw).hexdigest()


def _keyed_predictions(
    groups: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    matches: list[tuple[int, int]],
) -> dict[str, dict[str, Any]]:
    """Map ground-truth keys to predicted groups via exact matches."""
    keyed: dict[str, dict[str, Any]] = {}
    for i, j in matches:
        key = str(expected[j].get("key"))
        keyed[key] = groups[i]
    return keyed


def _priority_ranks(by_key: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Best-first numeric ranks from priority levels (unranked → -1)."""
    from src.research.metrics import PRIORITY_ORDER

    return {
        key: PRIORITY_ORDER.get(str(row.get("priority_level")), -1) for key, row in by_key.items()
    }


def _mismatches(
    name: str,
    groups: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    matches: list[tuple[int, int]],
) -> list[dict[str, Any]]:
    """Every disagreement, verbatim (nothing hidden)."""
    keyed = _keyed_predictions(groups, expected, matches)
    mismatches: list[dict[str, Any]] = []
    matched_predicted = {i for i, _ in matches}
    matched_expected = {j for _, j in matches}
    for i, group in enumerate(groups):
        if i not in matched_predicted:
            mismatches.append(
                {
                    "kind": _split_or_merge_kind(i, group, groups, expected),
                    "pipeline": name,
                    "members": sorted(str(m) for m in group["members"]),
                    "severity": group.get("severity"),
                    "lifecycle": group.get("lifecycle"),
                }
            )
    for j, want in enumerate(expected):
        if j in matched_expected:
            predicted = keyed[str(want.get("key"))]
            for field in ("severity", "lifecycle", "priority_level"):
                if predicted.get(field) != want.get(field):
                    kind = f"{field}_mismatch"
                    if field == "lifecycle" and want.get("lifecycle") == "REGRESSED":
                        kind = "missed_regression"
                    elif field == "lifecycle" and want.get("lifecycle") == "RESOLVED":
                        kind = "missed_resolution"
                    mismatches.append(
                        {
                            "kind": kind,
                            "pipeline": name,
                            "key": want.get("key"),
                            "expected": want.get(field),
                            "predicted": predicted.get(field),
                        }
                    )
        else:
            mismatches.append(
                {
                    "kind": "false_negative",
                    "pipeline": name,
                    "key": want.get("key"),
                    "members": list(want.get("members", [])),
                }
            )
    mismatches.sort(key=lambda m: (m["kind"], str(m.get("key", ""))))
    return mismatches


def group_members(groups: list[dict[str, Any]]) -> list[set[str]]:
    """Member sets of predicted groups (split/merge analysis helper)."""
    return [{str(m) for m in g["members"]} for g in groups]


def _split_or_merge_kind(
    index: int,
    group: dict[str, Any],
    groups: list[dict[str, Any]],
    expected: list[dict[str, Any]],
) -> str:
    """Classify an unmatched predicted group by member overlap.

    * ``wrong_grouping_merge`` — its members span ≥2 expected groups.
    * ``wrong_grouping_split`` — it is a strict subset of one expected
      group (a sibling predicted group holds the rest).
    * ``false_positive`` — no meaningful overlap (genuinely extra).
    """
    members = {str(m) for m in group["members"]}
    overlapped = sum(1 for want in expected if members & {str(m) for m in want.get("members", [])})
    if overlapped >= 2:
        return "wrong_grouping_merge"
    for want in expected:
        want_members = {str(m) for m in want.get("members", [])}
        if members and members < want_members:
            others = [{str(m) for m in g["members"]} for k, g in enumerate(groups) if k != index]
            if any(members & other for other in others) or any(
                (want_members - members) & other for other in others
            ):
                return "wrong_grouping_split"
    return "false_positive"


__all__ = [
    "BASELINE_DEFINITIONS",
    "METRIC_DEFINITIONS",
    "PIPELINES",
    "PIPELINE_VERSION",
    "evaluate_dataset",
    "evaluate_fixture",
]
