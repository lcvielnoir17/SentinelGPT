"""Live-collection evidence views (M19, DB-free deterministic subset).

Production M12 evidence needs a database session and an owner; live
research collection must stay offline-capable and free of production
data. This module rebuilds the EQUIVALENT bounded view from fixture
pipeline output: same fingerprint-as-finding-id convention as
transcript replay, same registries, same prompt renderer, same
validator. Differences from the production path (no scan metadata,
no per-evidence ids, remediation untracked) are documented here, not
hidden — validator semantics are identical.
"""

from __future__ import annotations

from typing import Any


def views_for_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic finding views with fingerprints as finding IDs."""
    views = []
    for group in groups:
        fingerprint = str(group.get("fingerprint", ""))
        views.append(
            {
                "finding_id": fingerprint,
                "fingerprint": fingerprint,
                "target_id": "research-target",
                "scan_id": "research-scan",
                "category": group.get("category"),
                "title": "",
                "severity": group.get("severity", ""),
                "lifecycle": group.get("lifecycle"),
                "remediation_status": None,
                "priority_level": group.get("priority_level"),
                "evidence": [],
                "observed_at": None,
            }
        )
    views.sort(key=lambda v: str(v["fingerprint"]))
    return views


def registries_for_views(views: list[dict[str, Any]]) -> dict[str, frozenset[str]]:
    """Citation allow-lists matching the transcript-replay convention."""
    finding_ids = frozenset(str(v.get("finding_id", "")) for v in views if v.get("finding_id"))
    return {"finding_ids": finding_ids, "cves": frozenset(), "control_ids": frozenset()}


def build_live_evidence(groups: list[dict[str, Any]]) -> Any:
    """A real InvestigationEvidence over research views (for prompts/replay)."""
    from src.domain.investigation.evidence import InvestigationEvidence

    views = views_for_groups(groups)
    registries = registries_for_views(views)
    cves: set[str] = set()
    for group in groups:
        for cve in group.get("cves", []):
            cves.add(str(cve))
    return InvestigationEvidence(
        target_id="research-target",
        scan_id="research-scan",
        scan_status="REPORT_READY",
        generated_at="1970-01-01T00:00:00+00:00",
        finding_ids=registries["finding_ids"],
        evidence_ids=frozenset(),
        control_ids=_control_ids(groups),
        cve_set=frozenset(cves),
    )


def _control_ids(groups: list[dict[str, Any]]) -> frozenset[str]:
    controls: set[str] = set()
    for group in groups:
        for pair in group.get("compliance", []):
            if isinstance(pair, list) and len(pair) == 2:
                controls.add(str(pair[1]))
    return frozenset(controls)


__all__ = ["build_live_evidence", "registries_for_views", "views_for_groups"]
