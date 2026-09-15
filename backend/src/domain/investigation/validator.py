"""Investigation output validator: the narrator integrity boundary.

Fail-closed, mirroring the comparison validator: oversized, non-JSON,
or schema-invalid replies are rejected outright, and every grounded
reference is checked against the evidence registries — unknown
finding/evidence/control IDs, invented CVEs, certification claims,
and canonical restatements (severity/priority/resolution verdicts)
are rejected, never repaired. The validator never mutates evidence
and the output schema contains no finding/lifecycle/priority write
path, so canonical truth cannot be altered by construction.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.domain.investigation.evidence import InvestigationEvidence

MAX_OUTPUT_JSON_BYTES = 131_072
MAX_SUMMARY_CHARS = 4_000
MAX_POINT_CHARS = 500
MAX_POINTS = 20
MAX_ACTIONS = 10
MAX_CITATIONS = 25

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")

# Certification verdicts the narrator must never utter.
_FORBIDDEN_CERTIFICATION = (
    re.compile(r"\bcompliant\b", re.IGNORECASE),
    re.compile(r"\bcertified\b", re.IGNORECASE),
    re.compile(r"\bcertification\b", re.IGNORECASE),
)

# Canonical restatements: severity/priority levels and resolution
# verdicts belong to deterministic systems, never to narration.
# Both verbose ("Severity is now low") and terse report-style
# ("Severity: HIGH", "Status: RESOLVED") forms are rejected.
_FORBIDDEN_RESTATEMENT = (
    re.compile(r"severity\s+(is|are|was|were|changed?\s+to|now)\b", re.IGNORECASE),
    re.compile(r"priority\s+(is|are|was|were|changed?\s+to|now)\b", re.IGNORECASE),
    re.compile(r"\bseverity\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"\bpriority\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"\bmark\w*\s+(it\s+)?as\s+(resolved|fixed|done|closed)\b", re.IGNORECASE),
    re.compile(r"\b(status|verdict)\s*:\s*(resolved|fixed|done|closed)\b", re.IGNORECASE),
    re.compile(r"\bremediation\s+(is\s+)?(complete|completed|done|finished)\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class InvestigationValidationResult:
    """Outcome of validating one raw provider reply."""

    accepted: bool
    answer: dict[str, Any] | None
    errors: tuple[str, ...] = field(default_factory=tuple)


def validate_investigation_response(
    raw: str | bytes | dict[str, Any], evidence: InvestigationEvidence
) -> InvestigationValidationResult:
    """Validate a provider reply against the evidence registries."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_OUTPUT_JSON_BYTES:
            return _reject("response exceeds size cap")
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_OUTPUT_JSON_BYTES:
            return _reject("response exceeds size cap")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return _reject("response is not valid JSON")
    elif isinstance(raw, dict):
        parsed = raw
    else:
        return _reject("response has an unsupported shape")
    if not isinstance(parsed, dict):
        return _reject("response must be a JSON object")

    errors: list[str] = []
    summary = parsed.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        errors.append("summary is required")
    elif len(summary) > MAX_SUMMARY_CHARS:
        errors.append("summary exceeds size cap")

    key_points = _bounded_text_list(parsed.get("key_points"), MAX_POINTS, "key_points", errors)
    actions = _bounded_text_list(
        parsed.get("recommended_actions"), MAX_ACTIONS, "recommended_actions", errors
    )

    citations = parsed.get("citations")
    if not isinstance(citations, list) or len(citations) > MAX_CITATIONS:
        errors.append("citations must be a list within bounds")
        citations = []
    for citation in citations:
        if not isinstance(citation, dict):
            errors.append("citation must be an object")
            continue
        finding_id = citation.get("finding_id")
        if finding_id not in evidence.finding_ids:
            errors.append(f"unknown finding_id cited: {finding_id!r}")
        note = citation.get("note", "")
        if not isinstance(note, str) or len(note) > MAX_POINT_CHARS:
            errors.append("citation note out of bounds")

    notes = parsed.get("compliance_notes")
    if not isinstance(notes, list):
        errors.append("compliance_notes must be a list")
        notes = []
    for note in notes:
        if not isinstance(note, dict):
            errors.append("compliance note must be an object")
            continue
        if note.get("control_id") not in evidence.control_ids:
            errors.append(f"unknown control_id cited: {note.get('control_id')!r}")
        text = note.get("note", "")
        if not isinstance(text, str) or len(text) > MAX_POINT_CHARS:
            errors.append("compliance note out of bounds")

    if errors:
        return InvestigationValidationResult(accepted=False, answer=None, errors=tuple(errors))

    blob = json.dumps(parsed, default=str)
    for pattern in _FORBIDDEN_CERTIFICATION:
        if pattern.search(blob):
            return _reject("response claims compliance certification")
    for pattern in _FORBIDDEN_RESTATEMENT:
        if pattern.search(blob):
            return _reject("response restates canonical severity/priority/resolution")
    observed = set(_CVE_RE.findall(blob))
    invented = sorted(observed - set(evidence.cve_set))
    if invented:
        return _reject(f"response cites unobserved CVEs: {invented}")

    return InvestigationValidationResult(
        accepted=True,
        answer={
            "summary": summary,
            "key_points": key_points,
            "citations": [
                {"finding_id": c["finding_id"], "note": str(c.get("note", ""))}
                for c in citations
                if isinstance(c, dict)
            ],
            "recommended_actions": actions,
            "compliance_notes": [
                {"control_id": n["control_id"], "note": str(n.get("note", ""))}
                for n in notes
                if isinstance(n, dict)
            ],
        },
    )


def _bounded_text_list(raw: object, limit: int, name: str, errors: list[str]) -> list[str]:
    if not isinstance(raw, list) or len(raw) > limit:
        errors.append(f"{name} must be a list within bounds")
        return []
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or len(item) > MAX_POINT_CHARS:
            errors.append(f"{name} item out of bounds")
            continue
        out.append(item)
    return out


def _reject(reason: str) -> InvestigationValidationResult:
    return InvestigationValidationResult(accepted=False, answer=None, errors=(reason,))


__all__ = ["InvestigationValidationResult", "validate_investigation_response"]
