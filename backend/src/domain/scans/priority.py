"""Deterministic contextual priority (v1 frozen, v2 current).

v1 (``PRIORITY_VERSION`` / :func:`calculate_priority`) is FROZEN: existing
snapshots recompute identically forever, and its tests pin it exactly.
Do not modify v1 to change behavior; extend via v2.

v2 (``PRIORITY_VERSION_V2`` / :func:`calculate_priority_v2`) keeps every
v1 weight and level boundary — without technology or mid-range CVSS
signals the scores are identical — and adds:

* ``high-cvss`` — linked CVSS in [7.0, 9.0) (+5);
* ``tech-relevance`` — a detected target technology paired with
  CVE/CVSS enrichment evidence for it (+5). Technology alone never
  scores: ``matched_technologies`` must be non-empty, and matching
  requires advisory evidence, not mere presence.

Severity says how bad a finding *could* be; priority says what to do
*first*. Only signals the platform persists are combined — no model
calls, no invented inputs. A RESOLVED finding scores 0/NONE
unconditionally. Missing optional signals are simply absent.

Gemini may *explain* a priority; it must never calculate or mutate it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

PRIORITY_VERSION = "sgpt.priority.v1"
PRIORITY_VERSION_V2 = "sgpt.priority.v2"

_SEVERITY_BASE = {
    "CRITICAL": 80,
    "HIGH": 60,
    "MEDIUM": 40,
    "LOW": 20,
    "INFO": 5,
}
_UNKNOWN_SEVERITY_BASE = 10

_SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

_REGRESSION_BONUS = 15
_KNOWN_VULN_BONUS = 5
_SEVERE_CVSS_BONUS = 10
_SEVERE_CVSS_THRESHOLD = 9.0
_HIGH_CVSS_BONUS = 5
_HIGH_CVSS_THRESHOLD = 7.0
_TECH_RELEVANCE_BONUS = 5
_MAX_SCORE = 100


def _level_for(score: int) -> str:
    if score <= 0:
        return "NONE"
    if score >= 75:
        return "P1"
    if score >= 50:
        return "P2"
    if score >= 25:
        return "P3"
    return "P4"


@dataclass(frozen=True)
class PriorityInputs:
    """Everything v1 may consider. Optional signals default to absent."""

    severity: str
    lifecycle_status: str | None = None
    previous_severity: str | None = None
    has_cve: bool = False
    cvss_score: float | None = None


@dataclass(frozen=True)
class PriorityResult:
    """Explained outcome: never just an opaque number."""

    score: int
    level: str
    version: str
    factors: tuple[str, ...] = field(default_factory=tuple)


def calculate_priority(inputs: PriorityInputs) -> PriorityResult:
    """Deterministically score one finding (pure function)."""
    severity = (inputs.severity or "").upper()
    lifecycle = (inputs.lifecycle_status or "").upper()

    if lifecycle == "RESOLVED":
        return PriorityResult(
            score=0, level="NONE", version=PRIORITY_VERSION, factors=("resolved",)
        )

    base = _SEVERITY_BASE.get(severity, _UNKNOWN_SEVERITY_BASE)
    factors = [f"severity:{severity or 'UNKNOWN'}={base}"]
    score = base

    regressed = lifecycle == "REGRESSED"
    if not regressed and inputs.previous_severity:
        previous_rank = _SEVERITY_RANK.get(inputs.previous_severity.upper(), 0)
        regressed = _SEVERITY_RANK.get(severity, 0) > previous_rank
    if regressed:
        score += _REGRESSION_BONUS
        factors.append(f"regressed=+{_REGRESSION_BONUS}")

    if inputs.has_cve:
        score += _KNOWN_VULN_BONUS
        factors.append(f"known-cve=+{_KNOWN_VULN_BONUS}")

    if inputs.cvss_score is not None and inputs.cvss_score >= _SEVERE_CVSS_THRESHOLD:
        score += _SEVERE_CVSS_BONUS
        factors.append(f"cvss>=9=+{_SEVERE_CVSS_BONUS}")

    score = max(0, min(_MAX_SCORE, score))
    return PriorityResult(
        score=score,
        level=_level_for(score),
        version=PRIORITY_VERSION,
        factors=tuple(factors),
    )


# --------------------------------------------------------------------------- #
# v2 — everything above stays frozen                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PriorityInputsV2:
    """Everything v2 may consider. Optional signals default to absent.

    ``technologies`` are detected target-technology slugs; only the
    ``matched_technologies`` subset — paired with CVE/CVSS enrichment
    evidence by the caller via :func:`match_technologies` — scores.
    """

    severity: str
    lifecycle_status: str | None = None
    previous_severity: str | None = None
    has_cve: bool = False
    cvss_score: float | None = None
    technologies: tuple[str, ...] = ()
    matched_technologies: tuple[str, ...] = ()


def _clean_cvss(value: object) -> float | None:
    """Finite in-range CVSS or None (NaN/inf/bool/out-of-range are absent)."""
    if value is None or isinstance(value, bool):
        return None
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    score = float(value)
    if not 0.0 <= score <= 10.0:
        return None
    return score


def _clean_slugs(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Normalized, deduplicated technology slugs (defensive: never trust)."""
    cleaned = {str(v).strip().lower() for v in values if str(v).strip()}
    return tuple(sorted(s for s in cleaned if s))


def match_technologies(
    technologies: tuple[str, ...] | list[str],
    enrichment_rows: list[dict[str, object]],
) -> tuple[str, ...]:
    """Slugs paired with CVE/CVSS enrichment evidence mentioning them.

    A technology matters only with advisory evidence: the slug must occur
    (case-insensitive substring) in a row's ``affected_technology`` text
    AND that row must carry a CVE id or a finite CVSS score. Pure
    substring matching keeps the rule explicit — no regex, no invention.
    """
    slugs = _clean_slugs(tuple(technologies))
    if not slugs:
        return ()
    matched: set[str] = set()
    for row in enrichment_rows or []:
        cve = row.get("cve_id")
        cvss = _clean_cvss(row.get("cvss_score"))
        if not cve and cvss is None:
            continue
        haystack = str(row.get("affected_technology") or "").lower()
        if not haystack:
            continue
        for slug in slugs:
            if slug in haystack:
                matched.add(slug)
    return tuple(sorted(matched))


def calculate_priority_v2(inputs: PriorityInputsV2) -> PriorityResult:
    """Deterministically score one finding under v2 (pure function)."""
    severity = (inputs.severity or "").upper()
    lifecycle = (inputs.lifecycle_status or "").upper()

    if lifecycle == "RESOLVED":
        return PriorityResult(
            score=0, level="NONE", version=PRIORITY_VERSION_V2, factors=("resolved",)
        )

    technologies = _clean_slugs(inputs.technologies)
    matched = tuple(s for s in _clean_slugs(inputs.matched_technologies) if s in technologies)
    cvss = _clean_cvss(inputs.cvss_score)

    base = _SEVERITY_BASE.get(severity, _UNKNOWN_SEVERITY_BASE)
    factors = [f"severity:{severity or 'UNKNOWN'}={base}"]
    score = base

    regressed = lifecycle == "REGRESSED"
    if not regressed and inputs.previous_severity:
        previous_rank = _SEVERITY_RANK.get(str(inputs.previous_severity).upper(), 0)
        regressed = _SEVERITY_RANK.get(severity, 0) > previous_rank
    if regressed:
        score += _REGRESSION_BONUS
        factors.append(f"regressed=+{_REGRESSION_BONUS}")

    if inputs.has_cve:
        score += _KNOWN_VULN_BONUS
        factors.append(f"known-cve=+{_KNOWN_VULN_BONUS}")

    if cvss is not None:
        if cvss >= _SEVERE_CVSS_THRESHOLD:
            score += _SEVERE_CVSS_BONUS
            factors.append(f"cvss>=9=+{_SEVERE_CVSS_BONUS}")
        elif cvss >= _HIGH_CVSS_THRESHOLD:
            score += _HIGH_CVSS_BONUS
            factors.append(f"cvss>=7=+{_HIGH_CVSS_BONUS}")

    if matched:
        score += _TECH_RELEVANCE_BONUS
        factors.append(f"tech-relevance:{','.join(matched)}=+{_TECH_RELEVANCE_BONUS}")

    score = max(0, min(_MAX_SCORE, score))
    return PriorityResult(
        score=score,
        level=_level_for(score),
        version=PRIORITY_VERSION_V2,
        factors=tuple(factors),
    )
