"""Deterministic comparison evidence for AI narration (no network, no AI).

Builds the bounded, canonical input the comparison analyst consumes:
the summary plus per-finding change records from
``ScanService.compare_scans_detailed``. Records are already ordered
(bucket, fingerprint); beyond ``MAX_COMPARISON_RECORDS`` the tail is cut
deterministically with an explicit omission count — never silently.

The evidence carries a stable ``comparison_evidence_id`` (SHA-256 over the
canonical subset) that anchors validator reference checks and assessment
identity. Citation registries (finding IDs, fingerprints) are derived
from the same records, so the validator and the prompt can never
disagree about what exists.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from src.domain.scanning.findings import dumps_stable

MAX_COMPARISON_RECORDS = 64
MAX_EVIDENCE_HASHES = 16
MAX_ENRICHMENT_ROWS = 8
MAX_CVES = 10

_RECORD_FIELDS: tuple[str, ...] = (
    "id",
    "previous_finding_id",
    "title",
    "category",
    "fingerprint",
    "lifecycle_status",
    "previous_lifecycle_status",
    "severity",
    "previous_severity",
    "severity_changed",
    "priority",
    "previous_priority",
    "priority_changed",
    "priority_versions_match",
    "remediation_status",
    "previous_remediation_status",
    "remediation_changed",
    "evidence_count",
    "previous_evidence_count",
    "evidence_changed",
    "evidence_hashes",
    "enrichment_changed",
    "cves",
    "cvss_max",
    "enrichment",
    "first_seen_at",
    "last_seen_at",
    "scan_id",
    "previous_scan_id",
)


@dataclass(frozen=True)
class ComparisonEvidence:
    """Bounded deterministic comparison snapshot for one scan pair."""

    comparison_evidence_id: str
    scan_a_id: str
    scan_b_id: str
    target_id: str
    summary: dict[str, int]
    records: tuple[dict[str, Any], ...]
    omitted_record_count: int = 0
    finding_ids: frozenset[str] = frozenset()
    fingerprints: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        return {
            "comparison_evidence_id": self.comparison_evidence_id,
            "scan_a_id": self.scan_a_id,
            "scan_b_id": self.scan_b_id,
            "target_id": self.target_id,
            "summary": dict(self.summary),
            "records": [dict(r) for r in self.records],
            "omitted_record_count": self.omitted_record_count,
        }


def _bounded_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Project one detailed record to the AI-relevant, bounded subset."""
    record: dict[str, Any] = {key: raw.get(key) for key in _RECORD_FIELDS}
    hashes = record.get("evidence_hashes")
    if isinstance(hashes, list):
        record["evidence_hashes"] = [str(h) for h in hashes[:MAX_EVIDENCE_HASHES]]
    cves = record.get("cves")
    if isinstance(cves, list):
        record["cves"] = [str(c) for c in cves[:MAX_CVES]]
    enrichment = record.get("enrichment")
    if isinstance(enrichment, list):
        record["enrichment"] = [
            {
                key: item.get(key)
                for key in (
                    "source",
                    "external_ref",
                    "cve_id",
                    "cwe_id",
                    "cvss_score",
                )
            }
            for item in enrichment[:MAX_ENRICHMENT_ROWS]
            if isinstance(item, dict)
        ]
    priority = record.get("priority")
    if isinstance(priority, dict):
        record["priority"] = {
            key: priority.get(key) for key in ("score", "level", "version", "factors")
        }
    previous_priority = record.get("previous_priority")
    if isinstance(previous_priority, dict):
        record["previous_priority"] = {
            key: previous_priority.get(key) for key in ("score", "level", "version", "factors")
        }
    elif previous_priority is not None:
        record["previous_priority"] = None
    return record


def build_comparison_evidence(
    comparison: dict[str, Any],
    *,
    scan_a_id: str,
    scan_b_id: str,
    target_id: str,
) -> ComparisonEvidence:
    """Assemble bounded evidence from a detailed comparison result."""
    raw_records = comparison.get("records")
    records_in = list(raw_records) if isinstance(raw_records, list) else []
    bounded = [_bounded_record(r) for r in records_in if isinstance(r, dict)]
    omitted = max(0, len(bounded) - MAX_COMPARISON_RECORDS)
    kept = bounded[:MAX_COMPARISON_RECORDS]

    summary_raw = comparison.get("summary")
    summary = (
        {str(k): int(v) for k, v in summary_raw.items()} if isinstance(summary_raw, dict) else {}
    )
    finding_ids: set[str] = set()
    fingerprints: set[str] = set()
    for record in kept:
        for key in ("id", "previous_finding_id"):
            value = record.get(key)
            if isinstance(value, str) and value:
                finding_ids.add(value)
        fingerprint = record.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            fingerprints.add(fingerprint)

    canonical = dumps_stable(
        {
            "scan_a_id": scan_a_id,
            "scan_b_id": scan_b_id,
            "target_id": target_id,
            "summary": summary,
            "records": kept,
        }
    )
    evidence_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return ComparisonEvidence(
        comparison_evidence_id=evidence_id,
        scan_a_id=scan_a_id,
        scan_b_id=scan_b_id,
        target_id=target_id,
        summary=summary,
        records=tuple(kept),
        omitted_record_count=omitted,
        finding_ids=frozenset(finding_ids),
        fingerprints=frozenset(fingerprints),
    )
