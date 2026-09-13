"""Finding enrichment validation (advisory metadata, never canonical).

Pure, network-free validation for vulnerability identifiers attached to a
finding fingerprint. Enrichment rows are display/analysis aids only:
validating here must never mutate fingerprints, evidence, lifecycle,
severity, or authorization — those live on the canonical finding path.

Accepted identifiers:
* CVE: ``CVE-YYYY-NNNN+`` (4+ digit sequence part).
* CWE: ``CWE-N+``.
* CVSS: numeric score in [0.0, 10.0] with an optional vector string.
* references: HTTP(S) URLs or recognized ``source:id`` handles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_PATTERN = re.compile(r"^CWE-\d+$")
_REFERENCE_URL = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
_REFERENCE_HANDLE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*:[^\s]+$")
# Handles are shape-validated, but active schemes must never reach a UI
# that renders references as links.
_BLOCKED_SCHEMES = re.compile(r"^(javascript|data|vbscript):", re.IGNORECASE)

MAX_REFERENCES = 20
MAX_REFERENCE_CHARS = 2_000


class EnrichmentValidationError(ValueError):
    """An enrichment payload field failed deterministic validation."""


def normalize_cve(value: str) -> str:
    """Uppercase, trimmed CVE id or raise."""
    candidate = value.strip().upper()
    if not CVE_PATTERN.match(candidate):
        raise EnrichmentValidationError(f"invalid CVE identifier: {value!r}")
    return candidate


def normalize_cwe(value: str) -> str:
    """Uppercase, trimmed CWE id or raise."""
    candidate = value.strip().upper()
    if not CWE_PATTERN.match(candidate):
        raise EnrichmentValidationError(f"invalid CWE identifier: {value!r}")
    return candidate


def validate_cvss_score(value: float | int | None) -> float | None:
    """CVSS score in [0.0, 10.0]; None stays None (signal absent)."""
    if value is None:
        return None
    score = float(value)
    if not 0.0 <= score <= 10.0:
        raise EnrichmentValidationError(f"CVSS score out of range: {value!r}")
    return score


def normalize_references(values: list[str] | tuple[str, ...] | None) -> list[str]:
    """Trimmed URL/handle references, bounded; anything else raises."""
    if not values:
        return []
    cleaned: list[str] = []
    for raw in values:
        item = str(raw).strip()
        if len(item) > MAX_REFERENCE_CHARS:
            raise EnrichmentValidationError("reference exceeds maximum length")
        if _BLOCKED_SCHEMES.match(item):
            raise EnrichmentValidationError(f"blocked reference scheme: {raw!r}")
        if not (_REFERENCE_URL.match(item) or _REFERENCE_HANDLE.match(item)):
            raise EnrichmentValidationError(f"invalid reference: {raw!r}")
        cleaned.append(item)
    if len(cleaned) > MAX_REFERENCES:
        raise EnrichmentValidationError("too many references")
    return cleaned


@dataclass(frozen=True)
class EnrichmentInput:
    """Validated enrichment payload for one (fingerprint, target) identity."""

    source: str = "manual"
    external_ref: str = "manual"
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[str] = field(default_factory=list)
    affected_technology: str | None = None
    remediation: str | None = None

    @classmethod
    def parse(cls, payload: dict[str, object]) -> EnrichmentInput:
        """Validate a raw request payload (raises EnrichmentValidationError)."""
        raw_cve = payload.get("cve_id", payload.get("cveId"))
        raw_cwe = payload.get("cwe_id", payload.get("cweId"))
        raw_score = payload.get("cvss_score", payload.get("cvssScore"))
        raw_refs = payload.get("references", [])
        raw_vector = payload.get("cvss_vector", payload.get("cvssVector"))
        raw_tech = payload.get("affected_technology", payload.get("affectedTechnology"))

        if raw_score is not None and not isinstance(raw_score, (int, float)):
            raise EnrichmentValidationError("CVSS score must be numeric")
        if raw_refs is not None and not isinstance(raw_refs, (list, tuple)):
            raise EnrichmentValidationError("references must be a list")
        remediation = payload.get("remediation")
        if remediation is not None and not isinstance(remediation, str):
            raise EnrichmentValidationError("remediation must be text")

        source = str(payload.get("source", "manual")).strip() or "manual"
        if len(source) > 30:
            raise EnrichmentValidationError("source exceeds maximum length")
        external_ref = str(payload.get("external_ref", payload.get("externalRef", ""))).strip()
        cve = normalize_cve(str(raw_cve)) if raw_cve else None
        if not external_ref:
            external_ref = cve or (normalize_cwe(str(raw_cwe)) if raw_cwe else None) or "manual"
        if len(external_ref) > 40:
            raise EnrichmentValidationError("external_ref exceeds maximum length")
        return cls(
            source=source,
            external_ref=external_ref,
            cve_id=cve,
            cwe_id=normalize_cwe(str(raw_cwe)) if raw_cwe else None,
            cvss_score=validate_cvss_score(raw_score),
            cvss_vector=str(raw_vector).strip()[:100] if raw_vector else None,
            references=normalize_references(list(raw_refs) if raw_refs else []),
            affected_technology=str(raw_tech).strip()[:200] if raw_tech else None,
            remediation=remediation.strip()
            if isinstance(remediation, str) and remediation
            else None,
        )
