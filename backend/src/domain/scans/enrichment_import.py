"""Offline vulnerability-intelligence importer (Milestone E).

Loads a versioned, curated JSON dataset of advisory metadata and binds
entries to finding fingerprints for ONE target. No network calls, no
scanner involvement: the importer only writes advisory rows that the
deterministic validators accept, and the repository deduplicates by the
(fingerprint, target, source, external_ref) identity — reruns are safe.

Dataset schema (``sgpt.enrichment-dataset.v1``)::

    {
      "schema_version": "sgpt.enrichment-dataset.v1",
      "source": "sentinelgpt-curated",
      "dataset_version": "2026.09.0",
      "entries": [
        {
          "category_code": "MISSING_SECURITY_HEADER",
          "identifier": "strict-transport-security",
          "cve_id": null,
          "cwe_id": "CWE-319",
          "cvss_score": null,
          "cvss_vector": null,
          "references": ["https://..."],
          "affected_technology": "HTTP servers",
          "remediation": "..."
        }
      ]
    }

Fingerprints resolve through the SAME
:func:`generate_fingerprint` the scan pipeline uses, so imported
advisories attach to exactly the findings the scanner produces — the
importer never invents finding identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.domain.scans.enrichment import EnrichmentInput, EnrichmentValidationError
from src.domain.scans.fingerprinting import (
    UnsupportedFingerprintCategory,
    generate_fingerprint,
)

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

DATASET_SCHEMA_VERSION = "sgpt.enrichment-dataset.v1"
MAX_ENTRIES = 5_000


class EnrichmentDatasetError(ValueError):
    """The dataset document failed schema validation."""


@dataclass(frozen=True)
class EnrichmentImportSummary:
    """Idempotent import outcome (safe to log; no advisory content)."""

    dataset_version: str
    source: str
    total_entries: int
    attached: int
    skipped_duplicates: int
    errors: tuple[str, ...] = field(default_factory=tuple)


def _require_mapping(document: object) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise EnrichmentDatasetError("dataset must be a JSON object")
    return dict(document)


def parse_dataset(document: object) -> dict[str, Any]:
    """Validate the dataset envelope; returns the normalized document."""
    data = _require_mapping(document)
    if data.get("schema_version") != DATASET_SCHEMA_VERSION:
        raise EnrichmentDatasetError(f"unsupported schema_version: {data.get('schema_version')!r}")
    source = data.get("source")
    if not isinstance(source, str) or not source.strip() or len(source) > 30:
        raise EnrichmentDatasetError("source must be a non-empty string (<=30 chars)")
    version = data.get("dataset_version")
    if not isinstance(version, str) or not version.strip() or len(version) > 30:
        raise EnrichmentDatasetError("dataset_version must be a non-empty string (<=30 chars)")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        raise EnrichmentDatasetError("entries must be a non-empty list")
    if len(entries) > MAX_ENTRIES:
        raise EnrichmentDatasetError(f"too many entries (max {MAX_ENTRIES})")
    return {
        "source": source.strip(),
        "dataset_version": version.strip(),
        "entries": entries,
    }


def _entry_fingerprint(hostname: str, entry: object, index: int) -> str:
    if not isinstance(entry, dict):
        raise EnrichmentDatasetError(f"entry {index}: must be an object")
    category = entry.get("category_code")
    identifier = entry.get("identifier")
    if not isinstance(category, str) or not category.strip():
        raise EnrichmentDatasetError(f"entry {index}: category_code is required")
    if not isinstance(identifier, str) or not identifier.strip():
        raise EnrichmentDatasetError(f"entry {index}: identifier is required")
    try:
        return generate_fingerprint(
            hostname=hostname,
            category_code=category.strip(),
            identifier=identifier.strip(),
        )
    except (UnsupportedFingerprintCategory, ValueError) as exc:
        raise EnrichmentDatasetError(f"entry {index}: unresolvable identity ({exc})") from exc


async def import_dataset(
    session: AsyncSession,
    target_id: uuid.UUID,
    document: object,
) -> EnrichmentImportSummary:
    """Import one dataset for one target (operator action, idempotent).

    Unknown targets raise ``EnrichmentDatasetError`` before anything is
    written. Malformed entries are collected into the summary (not raised)
    so one bad record cannot abort the batch; per-entry advisory
    validation still rejects bad identifiers individually.
    """
    from src.infrastructure.database.models import Target
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    parsed = parse_dataset(document)
    target = await session.get(Target, target_id)
    if target is None:
        raise EnrichmentDatasetError("unknown target")
    hostname = str(getattr(target, "hostname", "") or "")
    if not hostname:
        raise EnrichmentDatasetError("target has no hostname")

    repository = ScanEngineExecutionRepository(session)
    attached = 0
    skipped = 0
    errors: list[str] = []
    entries: list[object] = parsed["entries"]
    for index, raw in enumerate(entries):
        try:
            fingerprint = _entry_fingerprint(hostname, raw, index)
            payload = dict(raw) if isinstance(raw, dict) else {}
            payload["source"] = parsed["source"]
            validated = EnrichmentInput.parse(payload)
        except (EnrichmentDatasetError, EnrichmentValidationError) as exc:
            errors.append(f"entry {index}: {exc}")
            continue
        before = await repository.list_enrichment(fingerprint=fingerprint, target_id=target_id)
        before_keys = {(r.get("source"), r.get("external_ref")) for r in before}
        await repository.add_enrichment(
            fingerprint=fingerprint,
            target_id=target_id,
            source=validated.source,
            external_ref=validated.external_ref,
            cve_id=validated.cve_id,
            cwe_id=validated.cwe_id,
            cvss_score=validated.cvss_score,
            cvss_vector=validated.cvss_vector,
            references=validated.references,
            affected_technology=validated.affected_technology,
            remediation=validated.remediation,
        )
        if (validated.source, validated.external_ref) in before_keys:
            skipped += 1
        else:
            attached += 1
    return EnrichmentImportSummary(
        dataset_version=str(parsed["dataset_version"]),
        source=str(parsed["source"]),
        total_entries=len(entries),
        attached=attached,
        skipped_duplicates=skipped,
        errors=tuple(errors),
    )
