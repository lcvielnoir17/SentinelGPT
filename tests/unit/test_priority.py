"""Deterministic contextual priority model (v1).

Proves: same inputs always score identically, severity orders scores,
regression bumps, resolved zeroes, missing signals are safe, the
calculation is versioned, and boundaries hold.
"""

from src.domain.scans.priority import (
    PRIORITY_VERSION,
    PriorityInputs,
    calculate_priority,
)


def test_same_inputs_same_score() -> None:
    inputs = PriorityInputs(severity="HIGH", lifecycle_status="PERSISTENT")
    first = calculate_priority(inputs)
    second = calculate_priority(inputs)
    assert first == second
    assert first.version == PRIORITY_VERSION


def test_higher_severity_scores_higher() -> None:
    scores = [
        calculate_priority(PriorityInputs(severity=severity)).score
        for severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    ]
    assert scores == sorted(scores)
    assert len(set(scores)) == len(scores)


def test_regression_increases_priority() -> None:
    base = calculate_priority(PriorityInputs(severity="HIGH"))
    regressed = calculate_priority(PriorityInputs(severity="HIGH", lifecycle_status="REGRESSED"))
    assert regressed.score == base.score + 15
    assert "regressed=+15" in regressed.factors


def test_severity_increase_counts_as_regression() -> None:
    steady = calculate_priority(PriorityInputs(severity="HIGH", previous_severity="HIGH"))
    worsened = calculate_priority(PriorityInputs(severity="HIGH", previous_severity="MEDIUM"))
    assert worsened.score > steady.score
    assert steady.score == calculate_priority(PriorityInputs(severity="HIGH")).score


def test_resolved_scores_zero() -> None:
    result = calculate_priority(PriorityInputs(severity="CRITICAL", lifecycle_status="RESOLVED"))
    assert result.score == 0
    assert result.level == "NONE"
    assert result.factors == ("resolved",)


def test_known_vuln_and_severe_cvss_stack() -> None:
    plain = calculate_priority(PriorityInputs(severity="MEDIUM"))
    enriched = calculate_priority(PriorityInputs(severity="MEDIUM", has_cve=True, cvss_score=9.8))
    assert enriched.score == plain.score + 5 + 10
    assert "known-cve=+5" in enriched.factors
    assert "cvss>=9=+10" in enriched.factors


def test_missing_signals_are_safe() -> None:
    result = calculate_priority(PriorityInputs(severity="MEDIUM"))
    assert result.score == 40
    assert result.level == "P3"
    assert result.factors == ("severity:MEDIUM=40",)


def test_unknown_severity_has_floor() -> None:
    result = calculate_priority(PriorityInputs(severity="WEIRD"))
    assert result.score == 10
    assert result.level == "P4"


def test_score_capped_at_hundred() -> None:
    result = calculate_priority(
        PriorityInputs(
            severity="CRITICAL", lifecycle_status="REGRESSED", has_cve=True, cvss_score=10.0
        )
    )
    assert result.score == 100
    assert result.level == "P1"


def test_levels_cover_boundaries() -> None:
    assert calculate_priority(PriorityInputs(severity="CRITICAL")).level == "P1"  # 80
    assert calculate_priority(PriorityInputs(severity="HIGH")).level == "P2"  # 60
    assert calculate_priority(PriorityInputs(severity="MEDIUM")).level == "P3"  # 40
    assert calculate_priority(PriorityInputs(severity="LOW")).level == "P4"  # 20
    assert calculate_priority(PriorityInputs(severity="INFO")).level == "P4"  # 5


def test_report_bridge_activates_enrichment_signals() -> None:
    """The assembler bridge feeds enrichment rows into the v2 model."""
    from src.domain.scans.priority import PRIORITY_VERSION_V2
    from src.reporting.assembler import _priority_for

    plain = _priority_for("HIGH", None, None)
    assert plain.score == 60
    assert plain.version == PRIORITY_VERSION_V2
    enriched = _priority_for(
        "HIGH",
        None,
        [{"cve_id": "CVE-2014-0160", "cvss_score": 7.5}],
    )
    # v2: 60 base + 5 CVE + 5 CVSS>=7 (v1 scored 65 here — frozen, see above).
    assert enriched.score == 60 + 5 + 5
    assert enriched.version == PRIORITY_VERSION_V2
    assert "cvss>=7=+5" in enriched.factors
    severe = _priority_for("HIGH", None, [{"cve_id": "CVE-2021-44228", "cvss_score": 10.0}])
    assert severe.score == 60 + 5 + 10
