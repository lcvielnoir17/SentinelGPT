"""Deterministic contextual priority model (v2).

Proves the v2 contract on top of frozen v1: identical bases/levels for
tech-free inputs, tiered CVSS, technology relevance only with paired
CVE/CVSS enrichment evidence, sanitized hostile inputs, versioned
snapshots, and v1/v2 comparability without silent mixing.
"""

from src.domain.scans.priority import (
    PRIORITY_VERSION,
    PRIORITY_VERSION_V2,
    PriorityInputsV2,
    calculate_priority,
    calculate_priority_v2,
    match_technologies,
)
from src.domain.scans.priority import (
    PriorityInputs as PriorityInputsV1,
)


def v2(**kwargs: object) -> object:
    defaults: dict[str, object] = {"severity": "MEDIUM"}
    defaults.update(kwargs)
    return calculate_priority_v2(PriorityInputsV2(**defaults))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Baseline & modifiers                                                        #
# --------------------------------------------------------------------------- #


def test_v2_severity_baseline_matches_v1() -> None:
    for severity, expected in (
        ("CRITICAL", 80),
        ("HIGH", 60),
        ("MEDIUM", 40),
        ("LOW", 20),
        ("INFO", 5),
    ):
        result = v2(severity=severity)
        assert result.score == expected
        assert result.version == PRIORITY_VERSION_V2


def test_v2_regression_modifier() -> None:
    base = v2(severity="HIGH")
    regressed = v2(severity="HIGH", lifecycle_status="REGRESSED")
    assert regressed.score == base.score + 15
    assert "regressed=+15" in regressed.factors


def test_v2_severity_increase_and_decrease() -> None:
    steady = v2(severity="HIGH", previous_severity="HIGH")
    assert steady.score == 60
    worsened = v2(severity="HIGH", previous_severity="MEDIUM")
    assert worsened.score == 60 + 15
    improved = v2(severity="MEDIUM", previous_severity="HIGH")
    # A decrease lowers the base; no extra penalty is invented.
    assert improved.score == 40
    assert improved.factors == ("severity:MEDIUM=40",)


def test_v2_cve_signal() -> None:
    assert v2(severity="MEDIUM", has_cve=True).score == 45


def test_v2_cvss_tiers_and_boundaries() -> None:
    assert v2(severity="MEDIUM", cvss_score=9.8).score == 40 + 10
    assert v2(severity="MEDIUM", cvss_score=9.0).score == 40 + 10
    assert v2(severity="MEDIUM", cvss_score=7.5).score == 40 + 5
    assert v2(severity="MEDIUM", cvss_score=7.0).score == 40 + 5
    assert v2(severity="MEDIUM", cvss_score=6.9).score == 40
    assert v2(severity="MEDIUM", cvss_score=0.0).score == 40
    assert v2(severity="MEDIUM", cvss_score=10.0).score == 40 + 10


def test_v2_resolved_and_persistent() -> None:
    resolved = v2(severity="CRITICAL", has_cve=True, cvss_score=10.0, lifecycle_status="RESOLVED")
    assert (resolved.score, resolved.level) == (0, "NONE")
    assert resolved.factors == ("resolved",)
    persistent = v2(severity="HIGH", lifecycle_status="PERSISTENT")
    assert persistent.score == 60
    assert persistent.factors == ("severity:HIGH=60",)


def test_v2_deterministic() -> None:
    inputs = PriorityInputsV2(
        severity="HIGH",
        lifecycle_status="PERSISTENT",
        has_cve=True,
        cvss_score=9.8,
        technologies=("nginx",),
        matched_technologies=("nginx",),
    )
    assert calculate_priority_v2(inputs) == calculate_priority_v2(inputs)


def test_v2_factor_explanations() -> None:
    result = v2(
        severity="HIGH",
        lifecycle_status="REGRESSED",
        has_cve=True,
        cvss_score=9.8,
        technologies=("nginx",),
        matched_technologies=("nginx",),
    )
    assert result.score == 60 + 15 + 5 + 10 + 5
    assert result.level == "P1"
    assert "severity:HIGH=60" in result.factors
    assert "regressed=+15" in result.factors
    assert "known-cve=+5" in result.factors
    assert "cvss>=9=+10" in result.factors
    assert "tech-relevance:nginx=+5" in result.factors


# --------------------------------------------------------------------------- #
# Technology relevance                                                        #
# --------------------------------------------------------------------------- #


def _enrichment(
    cve: str | None = None, cvss: float | None = None, tech: str | None = None
) -> dict[str, object]:
    return {"cve_id": cve, "cvss_score": cvss, "affected_technology": tech}


def test_match_technologies_requires_evidence_and_mention() -> None:
    rows = [_enrichment("CVE-2021-44228", 9.8, "nginx HTTP server")]
    assert match_technologies(("nginx",), rows) == ("nginx",)
    # CVE alone without a technology mention matches nothing.
    assert match_technologies(("nginx",), [_enrichment("CVE-2021-44228")]) == ()
    # Mention alone without CVE/CVSS matches nothing.
    assert match_technologies(("nginx",), [_enrichment(tech="nginx server")]) == ()
    # CVSS alone (no CVE) still counts as advisory evidence.
    assert match_technologies(("nginx",), [_enrichment(cvss=7.5, tech="nginx")]) == ("nginx",)
    # Case-insensitive, sorted, deduplicated.
    rows = [_enrichment("CVE-1", tech="Nginx and PHP servers")]
    assert match_technologies(("php", "nginx"), rows) == ("nginx", "php")
    assert match_technologies((), rows) == ()


def test_technology_without_vulnerability_scores_nothing() -> None:
    result = v2(severity="LOW", technologies=("nginx", "php"))
    assert result.score == 20
    assert result.level == "P4"
    assert result.factors == ("severity:LOW=20",)


def test_technology_with_paired_evidence_scores() -> None:
    result = v2(
        severity="MEDIUM",
        has_cve=True,
        technologies=("nginx", "php"),
        matched_technologies=("nginx",),
    )
    assert result.score == 40 + 5 + 5
    assert "tech-relevance:nginx=+5" in result.factors


def test_unmatched_technologies_ignored() -> None:
    # matched ⊆ technologies is enforced: stray entries cannot score.
    result = v2(severity="MEDIUM", technologies=("php",), matched_technologies=("nginx",))
    assert result.score == 40
    assert all("tech-relevance" not in f for f in result.factors)


def test_missing_enrichment_and_technology_safe() -> None:
    assert v2(severity="HIGH").score == 60
    assert v2(severity="HIGH", technologies=()).score == 60


# --------------------------------------------------------------------------- #
# Hostile / malformed inputs                                                  #
# --------------------------------------------------------------------------- #


def test_cvss_sanitization() -> None:
    for bad in (float("nan"), float("inf"), float("-inf"), True, 10.5, -1.0, "9.8"):
        assert v2(severity="MEDIUM", cvss_score=bad).score == 40


def test_slug_normalization() -> None:
    result = v2(
        severity="MEDIUM", technologies=("  Nginx ", "", "NGINX"), matched_technologies=("nginx",)
    )
    assert result.score == 40 + 5


# --------------------------------------------------------------------------- #
# Versioning & history                                                        #
# --------------------------------------------------------------------------- #


def test_v1_frozen_and_v2_distinct() -> None:
    v1 = calculate_priority(PriorityInputsV1(severity="MEDIUM", has_cve=True, cvss_score=7.5))
    assert v1.score == 45  # v1 has no mid-tier CVSS: frozen behavior
    assert v1.version == PRIORITY_VERSION
    same = v2(severity="MEDIUM", has_cve=True)
    assert same.score == 45  # tech-free, sub-7 CVSS: identical
    assert same.version == PRIORITY_VERSION_V2
    assert PRIORITY_VERSION_V2 != PRIORITY_VERSION


def test_v1_v2_mismatch_never_silent() -> None:
    from src.domain.scans.scan_service import _priority_changed

    v1_snap = {"score": 65, "level": "P2", "version": PRIORITY_VERSION}
    v2_snap = {"score": 70, "level": "P2", "version": PRIORITY_VERSION_V2}
    changed, match = _priority_changed(v2_snap, v1_snap)
    assert match is False
    assert changed is True  # score differs AND versions differ: both visible


def test_historical_snapshot_reproducible() -> None:
    inputs = PriorityInputsV2(
        severity="HIGH",
        lifecycle_status="PERSISTENT",
        has_cve=True,
        cvss_score=9.8,
        technologies=("nginx",),
        matched_technologies=("nginx",),
    )
    first = calculate_priority_v2(inputs)
    second = calculate_priority_v2(inputs)
    assert first == second
    # The snapshot carries everything needed to explain itself later.
    assert first.version == PRIORITY_VERSION_V2
    assert len(first.factors) == 4  # severity, CVE, CVSS, tech


# --------------------------------------------------------------------------- #
# Combinations                                                                #
# --------------------------------------------------------------------------- #


def test_combo_high_regressed_cvss() -> None:
    result = v2(severity="HIGH", lifecycle_status="REGRESSED", has_cve=True, cvss_score=9.8)
    assert result.score == 60 + 15 + 5 + 10
    assert result.level == "P1"


def test_combo_medium_cve() -> None:
    result = v2(severity="MEDIUM", has_cve=True)
    assert (result.score, result.level) == (45, "P3")


def test_combo_low_technology_only() -> None:
    result = v2(severity="LOW", technologies=("nginx",))
    assert (result.score, result.level) == (20, "P4")


def test_combo_remediation_done_does_not_resolve() -> None:
    """Remediation state is not a v2 input: DONE + PERSISTENT still scores."""
    result = v2(severity="HIGH", lifecycle_status="PERSISTENT")
    assert result.score == 60
    assert result.level == "P2"


def test_combo_resolved_with_enrichment() -> None:
    result = v2(
        severity="HIGH",
        lifecycle_status="RESOLVED",
        has_cve=True,
        cvss_score=10.0,
        technologies=("nginx",),
        matched_technologies=("nginx",),
    )
    assert (result.score, result.level) == (0, "NONE")
