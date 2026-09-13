"""Research metrics: precise, documented, reproducible (M14).

Every metric below states its denominator and meaning; none collapse
unrelated dimensions into a single "accuracy" number. Matching between
predicted groups and expected canonical findings is by EXACT member
observation-id sets — partial overlaps match nothing, so near-misses
are visible as simultaneous false positives and false negatives
instead of being silently rounded up.

Formulas (P = predicted groups, E = expected canonical, M = exact
member-set matches):

* grouping precision = |M| / |P| (0 when P empty and E non-empty is
  undefined → reported as None; both empty → 1.0 by vacuous truth —
  each case documented at the call site, never silently 0/1)
* grouping recall = |M| / |E| (same empty conventions)
* grouping F1 = harmonic mean (None when either side is undefined;
  0.0 when both sides are defined-but-zero, the standard zero-division
  convention; 1.0 only on vacuous both-empty truth)
* duplicate reduction rate = 1 − |groups| / |observations|
* severity consistency = matched groups with expected severity / |M|
  (None when M empty)
* priority agreement = matched groups with expected level / |M|
* Kendall tau-b over canonical ranking by (priority rank, severity
  rank): pairs tied on either side are skipped (documented tie
  handling); None when fewer than 2 comparable pairs exist
* regression detection rate = expected REGRESSED found as REGRESSED /
  expected REGRESSED (None when denominator is 0)
* resolution detection rate = same for RESOLVED
* false-positive rate = predicted groups matching nothing / |P|
* false-negative rate = expected groups matched by nothing / |E|
* citation validity = scripted replies accepted by the M12 validator /
  scripted replies evaluated
* evidence grounding rate = canonical groups with ≥1 evidence ref / |P|
"""

from __future__ import annotations

from typing import Any


def exact_matches(predicted: list[set[str]], expected: list[set[str]]) -> list[tuple[int, int]]:
    """Index pairs with identical member sets (deterministic order)."""
    matches: list[tuple[int, int]] = []
    used: set[int] = set()
    for i, group in enumerate(predicted):
        for j, want in enumerate(expected):
            if j not in used and group == want:
                matches.append((i, j))
                used.add(j)
                break
    return matches


def _ratio(matched: int, total: int, *, both_empty: bool) -> float | None:
    if total == 0:
        return 1.0 if both_empty else None
    return matched / total


def grouping_scores(predicted: list[set[str]], expected: list[set[str]]) -> dict[str, float | None]:
    """Precision/recall/F1 over exact member-set matches."""
    matches = exact_matches(predicted, expected)
    precision = _ratio(len(matches), len(predicted), both_empty=not expected)
    recall = _ratio(len(matches), len(expected), both_empty=not predicted)
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def duplicate_reduction_rate(group_count: int, observation_count: int) -> float | None:
    """1 − groups/observations (None when there are no observations)."""
    if observation_count == 0:
        return None
    return 1.0 - group_count / observation_count


def field_agreement(
    predicted: list[dict[str, Any]],
    expected: list[dict[str, Any]],
    matches: list[tuple[int, int]],
    field: str,
) -> float | None:
    """Fraction of matched groups agreeing on one field (None if no matches)."""
    if not matches:
        return None
    agreed = sum(1 for i, j in matches if predicted[i].get(field) == expected[j].get(field))
    return agreed / len(matches)


def detection_rate(
    expected: list[dict[str, Any]], predicted_by_key: dict[str, dict[str, Any]], status: str
) -> float | None:
    """Expected items with lifecycle `status` reproduced as `status`.

    `predicted_by_key` maps ground-truth keys to predicted groups (the
    evaluator aligns them by exact member sets first). None when the
    fixture expects no such items.
    """
    want = [e for e in expected if e.get("lifecycle") == status]
    if not want:
        return None
    hits = sum(
        1 for e in want if predicted_by_key.get(str(e.get("key")), {}).get("lifecycle") == status
    )
    return hits / len(want)


def false_positive_rate(predicted: list[set[str]], expected: list[set[str]]) -> float | None:
    """Predicted groups matching nothing / predicted (None when P empty)."""
    if not predicted:
        return None
    matched_predicted = {i for i, _ in exact_matches(predicted, expected)}
    return (len(predicted) - len(matched_predicted)) / len(predicted)


def false_negative_rate(predicted: list[set[str]], expected: list[set[str]]) -> float | None:
    """Expected groups matched by nothing / expected (None when E empty)."""
    if not expected:
        return None
    matched_expected = {j for _, j in exact_matches(predicted, expected)}
    return (len(expected) - len(matched_expected)) / len(expected)


PRIORITY_ORDER = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "NONE": 0}

METRIC_VERSION = "sgpt.research.metrics.v1"


def kendall_tau_b(predicted_ranks: dict[str, int], expected_ranks: dict[str, int]) -> float | None:
    """Rank agreement over shared keys; pairs tied on either side skipped.

    Ranks are best-first comparable numbers (higher = more important).
    Returns None when fewer than two jointly-ranked untied pairs exist.
    """
    keys = [k for k in expected_ranks if k in predicted_ranks]
    concordant = discordant = 0
    for a in range(len(keys)):
        for b in range(a + 1, len(keys)):
            key_a, key_b = keys[a], keys[b]
            expected_sign = (expected_ranks[key_a] > expected_ranks[key_b]) - (
                expected_ranks[key_a] < expected_ranks[key_b]
            )
            observed_sign = (predicted_ranks[key_a] > predicted_ranks[key_b]) - (
                predicted_ranks[key_a] < predicted_ranks[key_b]
            )
            if expected_sign == 0 or observed_sign == 0:
                continue
            if observed_sign == expected_sign:
                concordant += 1
            else:
                discordant += 1
    total = concordant + discordant
    if total == 0:
        return None
    return (concordant - discordant) / total


def citation_validity(accepted: int, evaluated: int) -> float | None:
    """Accepted scripted replies / evaluated (None when none evaluated)."""
    if evaluated == 0:
        return None
    return accepted / evaluated


def evidence_grounding_rate(groups: list[dict[str, Any]]) -> float | None:
    """Canonical groups carrying ≥1 evidence reference / groups."""
    if not groups:
        return None
    grounded = sum(1 for g in groups if int(g.get("evidence_count", 0)) > 0)
    return grounded / len(groups)


__all__ = [
    "METRIC_VERSION",
    "PRIORITY_ORDER",
    "citation_validity",
    "detection_rate",
    "duplicate_reduction_rate",
    "evidence_grounding_rate",
    "exact_matches",
    "false_negative_rate",
    "false_positive_rate",
    "field_agreement",
    "grouping_scores",
    "kendall_tau_b",
]
