"""Deterministic compliance assessment (pure, no I/O).

Assessment is a pure function of (mapping version, finding views):
same inputs always yield the same output, so results are reproducible
for a scan and the mapping version stamped on every result explains
which mapping produced it (STEP 11/12). No AI is involved anywhere —
finding titles and evidence travel strictly as data (STEP 16).

Status semantics (STEP 9):

* ``GAP_INDICATOR`` — at least one mapped finding is in an open
  lifecycle (NEW/PERSISTENT/REGRESSED/unknown). An observed finding
  without a resolution row is evidence of a gap, not of a fix.
* ``EVIDENCE_AVAILABLE`` — mapped findings exist but every one is
  RESOLVED: evidence of detection and remediation, not a verdict.
* ``NO_RELEVANT_FINDINGS`` — findings exist in scope but none fall in
  a mapped category. This is absence of evidence, NEVER evidence of
  compliance.
* ``INSUFFICIENT_EVIDENCE`` — no finding rows at all in scope (no
  completed scan evidence to evaluate).
"""

from __future__ import annotations

from typing import Any

from src.domain.compliance.catalog import (
    EVIDENCE_AVAILABLE,
    GAP_INDICATOR,
    INSUFFICIENT_EVIDENCE,
    MAPPING_VERSION,
    NO_RELEVANT_FINDINGS,
    OPEN_LIFECYCLES,
    ComplianceFramework,
    controls_for_category,
)

DISCLAIMER = (
    "Evidence mapping for control relevance only — not a compliance "
    "certification, attestation, or verdict. Absence of mapped findings "
    "does not mean a control is satisfied."
)

LIMITATION_NO_COMPLETED_SCANS = "No completed scan evidence in scope; controls cannot be evaluated."
LIMITATION_NO_MAPPED_FINDINGS = (
    "Findings exist in scope but none fall in categories mapped to this control."
)
LIMITATION_CURRENT_STATE = (
    "Lifecycle and remediation reflect current stored state; "
    "findings and evidence reflect the referenced scans."
)
LIMITATION_CURATED_SUBSET = "Curated control subset only — not a complete framework implementation."


def assess_framework(
    framework: ComplianceFramework,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assess every control of one framework over finding views.

    Each view carries: finding_id, fingerprint, target_id, scan_id,
    category, severity, title, lifecycle (may be None/unknown),
    remediation_status (may be None), priority_level (may be None),
    evidence (list of {id, type}), observed_at. Views are treated as
    data throughout — titles are never interpreted.
    """
    controls: list[dict[str, Any]] = []
    for control in sorted(framework.controls, key=lambda c: c.control_id):
        controls.append(assess_control(framework, control.control_id, findings))
    return {
        "framework": framework.framework_id,
        "framework_name": framework.name,
        "framework_version": framework.version,
        "mapping_version": MAPPING_VERSION,
        "controls": controls,
        "limitations": [LIMITATION_CURRENT_STATE, LIMITATION_CURATED_SUBSET, DISCLAIMER],
    }


def assess_control(
    framework: ComplianceFramework,
    control_id: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assess one control (shared by full assessments and report sections)."""
    relevant = [
        view
        for view in findings
        if control_id in controls_for_category(framework, _category_of(view))
    ]
    title = next((c.title for c in framework.controls if c.control_id == control_id), "")
    relevant.sort(
        key=lambda v: (
            str(v.get("target_id", "")),
            str(v.get("fingerprint", "")),
            str(v.get("scan_id", "")),
        )
    )
    if not findings:
        status = INSUFFICIENT_EVIDENCE
        limitations = [LIMITATION_NO_COMPLETED_SCANS]
    elif not relevant:
        status = NO_RELEVANT_FINDINGS
        limitations = [LIMITATION_NO_MAPPED_FINDINGS]
    elif any(
        _lifecycle_of(view) in OPEN_LIFECYCLES or _lifecycle_of(view) is None for view in relevant
    ):
        status = GAP_INDICATOR
        limitations = []
    else:
        status = EVIDENCE_AVAILABLE
        limitations = []
    return {
        "control_id": control_id,
        "title": title,
        "status": status,
        "rationale": framework.rationales.get(control_id, ""),
        "finding_count": len(relevant),
        "severity_summary": _tally(relevant, "severity"),
        "priority_summary": _tally(relevant, "priority_level"),
        "lifecycle_summary": _tally(relevant, "lifecycle", unknown_label="UNKNOWN"),
        "remediation_summary": _tally(relevant, "remediation_status", unknown_label="UNTRACKED"),
        "findings": [_finding_ref(view) for view in relevant],
        "limitations": limitations,
    }


def _category_of(view: dict[str, Any]) -> str | None:
    category = view.get("category")
    return str(category) if isinstance(category, str) and category else None


def _lifecycle_of(view: dict[str, Any]) -> str | None:
    lifecycle = view.get("lifecycle")
    return str(lifecycle) if isinstance(lifecycle, str) and lifecycle else None


def _tally(
    views: list[dict[str, Any]], key: str, *, unknown_label: str | None = None
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for view in views:
        raw = view.get(key)
        label = str(raw) if isinstance(raw, str) and raw else unknown_label
        if label is None:
            continue
        counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items()))


def _finding_ref(view: dict[str, Any]) -> dict[str, Any]:
    """Traceable reference: identifiers and states, never raw evidence."""
    evidence = view.get("evidence")
    items = evidence if isinstance(evidence, list) else []
    evidence_refs = [
        {"id": str(item.get("id", "")), "type": str(item.get("type", ""))}
        for item in items
        if isinstance(item, dict)
    ]
    return {
        "finding_id": str(view.get("finding_id", "")),
        "fingerprint": str(view.get("fingerprint", "")),
        "target_id": str(view.get("target_id", "")),
        "scan_id": str(view.get("scan_id", "")),
        "category": str(view.get("category", "") or ""),
        "title": str(view.get("title", "")),
        "severity": str(view.get("severity", "") or ""),
        "priority_level": view.get("priority_level"),
        "lifecycle": view.get("lifecycle"),
        "remediation_status": view.get("remediation_status"),
        "observed_at": view.get("observed_at"),
        "evidence": evidence_refs,
    }


def assessment_to_csv(assessment: dict[str, Any]) -> str:
    """Control-level CSV export (auditor-suitable, secrets-free).

    Free-text cells (titles live only in JSON detail; control titles
    here are curated seed text) still pass through formula
    neutralization — finding-derived content must never become a
    spreadsheet formula.
    """
    import csv
    import io

    from src.reporting.export_formatters.csv_formatter import _neutralize_formula

    columns = (
        "framework",
        "framework_version",
        "mapping_version",
        "control_id",
        "control_title",
        "status",
        "finding_count",
        "severities",
        "lifecycles",
        "fingerprints",
        "scan_ids",
    )
    controls = assessment.get("controls")
    rows = controls if isinstance(controls, list) else []
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(columns), dialect="excel")
    writer.writeheader()
    for control in rows:
        if not isinstance(control, dict):
            continue
        findings = control.get("findings")
        finding_list = findings if isinstance(findings, list) else []
        fingerprints = sorted(
            {
                str(item.get("fingerprint", ""))
                for item in finding_list
                if isinstance(item, dict) and item.get("fingerprint")
            }
        )
        scan_ids = sorted(
            {
                str(item.get("scan_id", ""))
                for item in finding_list
                if isinstance(item, dict) and item.get("scan_id")
            }
        )
        severities = control.get("severity_summary")
        lifecycles = control.get("lifecycle_summary")
        writer.writerow(
            {
                "framework": assessment.get("framework", ""),
                "framework_version": assessment.get("framework_version", ""),
                "mapping_version": assessment.get("mapping_version", ""),
                "control_id": control.get("control_id", ""),
                "control_title": _neutralize_formula(str(control.get("title", "") or "")),
                "status": control.get("status", ""),
                "finding_count": control.get("finding_count", 0),
                "severities": _format_counts(severities),
                "lifecycles": _format_counts(lifecycles),
                "fingerprints": ";".join(fingerprints),
                "scan_ids": ";".join(scan_ids),
            }
        )
    return buffer.getvalue()


def _format_counts(raw: object) -> str:
    if not isinstance(raw, dict):
        return ""
    return ";".join(f"{key}={value}" for key, value in sorted(raw.items()))


__all__ = [
    "DISCLAIMER",
    "assess_control",
    "assess_framework",
    "assessment_to_csv",
]
