"""Research processing pipelines: baselines vs SentinelGPT (M13/M14).

Three processors consume the SAME fixture observations:

* Baseline A (scanner-only): every observation is its own finding —
  no normalization, no correlation, no lifecycle tracking. Scan B
  members are NEW (correlation is impossible without identity), so
  the resolved set is honestly empty. This is not artificially weak:
  it is literally what unprocessed scanner output contains.
* Baseline B (rule-based): groups by exact normalized title within a
  category; severity = first-seen member (documented naive rule);
  lifecycle via the same derive function on title-groups (no
  history); priority from a static severity map (documented below).
* SentinelGPT: the REAL deterministic domain functions —
  ``generate_fingerprint_from_finding`` grouping, max-rank severity,
  ``derive_lifecycle_status`` with fixture history, v2 priority with
  CVE/CVSS/technology signals, and curated compliance mapping.
  Remediation rows pass through untouched: lifecycle output never
  reads them (DONE+PERSISTENT coexistence holds by construction).

All three share the output shape so metrics compare like with like.
"""

from __future__ import annotations

from typing import Any

from src.domain.compliance.catalog import controls_for_category, get_framework
from src.domain.scans.fingerprinting import (
    UnsupportedFingerprintCategory,
    generate_fingerprint_from_finding,
)
from src.domain.scans.lifecycle_finding import derive_lifecycle_status
from src.domain.scans.priority import (
    PRIORITY_VERSION_V2,
    PriorityInputsV2,
    calculate_priority_v2,
    match_technologies,
)

BASELINE_B_PRIORITY = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P4"}

_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

FRAMEWORKS = ("pci-dss", "iso-27001", "soc-2")


def normalize_title(title: str) -> str:
    """Baseline-B grouping key: lowercase, collapsed whitespace."""
    return " ".join(title.strip().lower().split())


def max_severity(severities: list[str]) -> str:
    """Highest-rank severity; ties break to earliest member (documented)."""
    best = "INFO"
    for severity in severities:
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(best, 0):
            best = severity
    return best


def run_baseline_a(fixture: dict[str, Any]) -> dict[str, Any]:
    """Scanner-only: singletons, as-reported severity, always NEW."""
    groups: list[dict[str, Any]] = []
    for scan_name in ("scan_a", "scan_b"):
        for obs in fixture[scan_name]:
            groups.append(
                {
                    "members": [obs["obs_id"]],
                    "severity": obs["severity"],
                    "category": str(obs["category"]).strip().upper(),
                    "lifecycle": "NEW",
                    "priority_level": None,
                    "scan": scan_name,
                }
            )
    return {"pipeline": "baseline-a", "groups": groups}


def run_baseline_b(fixture: dict[str, Any]) -> dict[str, Any]:
    """Rule-based: exact-title groups, first-seen severity, static priority."""
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    order: list[tuple[str, str]] = []
    for scan_name in ("scan_a", "scan_b"):
        for obs in fixture[scan_name]:
            key = (str(obs["category"]).strip().upper(), normalize_title(str(obs["title"])))
            if key not in by_key:
                by_key[key] = []
                order.append(key)
            by_key[key].append({**obs, "scan": scan_name})
    keys_a = {k for k, members in by_key.items() if any(m["scan"] == "scan_a" for m in members)}
    keys_b = {k for k, members in by_key.items() if any(m["scan"] == "scan_b" for m in members)}
    groups: list[dict[str, Any]] = []
    for key in order:
        members = by_key[key]
        in_a = key in keys_a
        in_b = key in keys_b
        if in_a and in_b:
            lifecycle = "PERSISTENT"
        elif in_b:
            lifecycle = "NEW"
        else:
            lifecycle = "RESOLVED" if fixture["scan_b"] else "NEW"
        severity = str(members[0]["severity"])
        groups.append(
            {
                "members": sorted(m["obs_id"] for m in members),
                "severity": severity,
                "category": key[0],
                "lifecycle": lifecycle,
                "priority_level": BASELINE_B_PRIORITY.get(severity),
                "scan": "scan_b" if in_b else "scan_a",
            }
        )
    return {"pipeline": "baseline-b", "groups": groups}


def run_sentinelgpt(fixture: dict[str, Any]) -> dict[str, Any]:
    """Full deterministic pipeline over fixture observations (real code)."""
    hostname = str(fixture["hostname"])
    groups, unidentified = _fingerprint_groups(hostname, fixture["scan_a"], fixture["scan_b"])
    history = _history_by_fingerprint(groups, dict(fixture["history"]))
    technologies = tuple(sorted(set(fixture["technologies"])))
    canonical: list[dict[str, Any]] = []
    for fingerprint in sorted(groups):
        members = groups[fingerprint]
        severities = [str(m["severity"]) for m in members]
        severity = max_severity(severities)
        category = str(members[0]["category"]).strip().upper()
        in_a = any(m["scan"] == "scan_a" for m in members)
        in_b = any(m["scan"] == "scan_b" for m in members) or not fixture["scan_b"]
        lifecycle = derive_lifecycle_status(
            fingerprint=fingerprint,
            in_current=in_b,
            in_previous=in_a and bool(fixture["scan_b"]),
            last_known_status=history.get(fingerprint),
        )
        cves = sorted({str(m["cve_id"]) for m in members if m.get("cve_id")})
        cvss_values = [float(m["cvss_score"]) for m in members if m.get("cvss_score") is not None]
        enrichment = [
            {
                "cve_id": m.get("cve_id"),
                "cvss_score": m.get("cvss_score"),
                "affected_technology": m.get("affected_technology"),
            }
            for m in members
            if m.get("cve_id") is not None or m.get("cvss_score") is not None
        ]
        matched = match_technologies(list(technologies), enrichment)
        priority = calculate_priority_v2(
            PriorityInputsV2(
                severity=severity,
                lifecycle_status=lifecycle,
                previous_severity=None,
                has_cve=bool(cves),
                cvss_score=max(cvss_values) if cvss_values else None,
                technologies=technologies,
                matched_technologies=matched,
            )
        )
        remediation = _remediation_for(members, dict(fixture["remediation"]))
        canonical.append(
            {
                "members": sorted(m["obs_id"] for m in members),
                "fingerprint": fingerprint,
                "severity": severity,
                "category": category,
                "lifecycle": lifecycle,
                "priority_level": priority.level,
                "priority_version": priority.version,
                "regressed": lifecycle == "REGRESSED",
                "resolved": lifecycle == "RESOLVED",
                "evidence_count": len(members),
                "cves": cves,
                "remediation_status": remediation,
                "compliance": _compliance_pairs(category),
            }
        )
    canonical.sort(key=lambda g: (g["category"], g["fingerprint"]))
    return {
        "pipeline": "sentinelgpt",
        "priority_version": PRIORITY_VERSION_V2,
        "groups": canonical,
        "unidentified": sorted(unidentified),
    }


def _fingerprint_groups(
    hostname: str, scan_a: list[dict[str, Any]], scan_b: list[dict[str, Any]]
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Group observations by real fingerprint (both scans, member-tagged).

    Observations without an extractable identifier mirror production
    (``ScanService._safe_fingerprint``): they persist fingerprint-less
    and join no group. Their ids return separately so evaluation can
    distinguish "unidentified" from "missing".
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    unidentified: list[str] = []
    for scan_name, observations in (("scan_a", scan_a), ("scan_b", scan_b)):
        for obs in observations:
            try:
                fingerprint = generate_fingerprint_from_finding(
                    hostname=hostname,
                    category_code=str(obs["category"]),
                    title=str(obs["title"]),
                    location=str(obs.get("location", "")),
                )
            except (UnsupportedFingerprintCategory, ValueError):
                unidentified.append(str(obs["obs_id"]))
                continue
            groups.setdefault(fingerprint, []).append({**obs, "scan": scan_name})
    return groups, sorted(unidentified)


def _history_by_fingerprint(
    groups: dict[str, list[dict[str, Any]]], history: dict[str, str]
) -> dict[str, str]:
    """Resolve fixture history (keyed by member obs) to fingerprints."""
    member_to_fp = {m["obs_id"]: fp for fp, members in groups.items() for m in members}
    resolved: dict[str, str] = {}
    for obs_id, status in history.items():
        fingerprint = member_to_fp.get(obs_id)
        if fingerprint is not None:
            resolved[fingerprint] = status
    return resolved


def _remediation_for(members: list[dict[str, Any]], remediation: dict[str, str]) -> str | None:
    """Informational remediation state (never influences lifecycle)."""
    for member in members:
        if member["obs_id"] in remediation:
            return remediation[member["obs_id"]]
    return None


def _compliance_pairs(category: str) -> list[list[str]]:
    """Curated (framework, control) pairs for one canonical category."""
    pairs: list[list[str]] = []
    for framework_id in FRAMEWORKS:
        framework = get_framework(framework_id)
        if framework is None:
            continue
        for control_id in controls_for_category(framework, category):
            pairs.append([framework_id, control_id])
    return sorted(pairs)


def assess_fixture_compliance(
    groups: list[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    """Assessment states per framework/control over pipeline groups.

    Builds minimal finding views (category + lifecycle only) and runs
    the REAL ``assess_control`` from the compliance domain, so the
    status semantics under test are the production semantics. Views
    carry no remediation state: unremediated-by-default is the honest
    baseline for assessment checks.
    """
    from src.domain.compliance.assessment import assess_control

    views = [
        {
            "finding_id": f"research-{i}",
            "fingerprint": f"research-{i}",
            "target_id": "research-target",
            "scan_id": "research-scan",
            "category": group.get("category"),
            "title": "",
            "severity": group.get("severity", ""),
            "lifecycle": group.get("lifecycle"),
            "remediation_status": None,
            "priority_level": None,
            "evidence": [],
            "observed_at": None,
        }
        for i, group in enumerate(groups)
    ]
    result: dict[str, dict[str, str]] = {}
    for framework_id in FRAMEWORKS:
        framework = get_framework(framework_id)
        if framework is None:
            continue
        states: dict[str, str] = {}
        for control in framework.controls:
            states[control.control_id] = str(
                assess_control(framework, control.control_id, views)["status"]
            )
        result[framework_id] = states
    return result


def fingerprint_of(hostname: str, category: str, title: str, location: str = "") -> str:
    """Test helper: fingerprint one synthetic observation (real code)."""
    try:
        return generate_fingerprint_from_finding(
            hostname=hostname, category_code=category, title=title, location=location
        )
    except UnsupportedFingerprintCategory:
        raise


__all__ = [
    "BASELINE_B_PRIORITY",
    "FRAMEWORKS",
    "assess_fixture_compliance",
    "fingerprint_of",
    "max_severity",
    "normalize_title",
    "run_baseline_a",
    "run_baseline_b",
    "run_sentinelgpt",
]
