"""Offline enrichment importer (Milestone E).

Proves: schema validation, malformed records collected (not fatal),
fingerprint resolution through the canonical function, idempotent
reruns, unknown targets rejected, and priority activation from
imported enrichment.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from src.domain.scans.enrichment_import import (
    DATASET_SCHEMA_VERSION,
    EnrichmentDatasetError,
    import_dataset,
    parse_dataset,
)

TARGET = uuid.uuid4()
HOSTNAME = "seeded.example"


def _document(**overrides: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "schema_version": DATASET_SCHEMA_VERSION,
        "source": "test-seed",
        "dataset_version": "2026.09.0-test",
        "entries": [
            {
                "category_code": "MISSING_SECURITY_HEADER",
                "identifier": "strict-transport-security",
                "cwe_id": "CWE-319",
                "references": ["https://example.test/hsts"],
                "remediation": "Add HSTS.",
            }
        ],
    }
    doc.update(overrides)
    return doc


def test_parse_accepts_valid_dataset() -> None:
    parsed = parse_dataset(_document())
    assert parsed["dataset_version"] == "2026.09.0-test"
    assert len(parsed["entries"]) == 1  # type: ignore[arg-type]


def test_parse_rejects_schema_mismatch() -> None:
    with pytest.raises(EnrichmentDatasetError):
        parse_dataset(_document(schema_version="v0"))
    with pytest.raises(EnrichmentDatasetError):
        parse_dataset(_document(entries=[]))
    with pytest.raises(EnrichmentDatasetError):
        parse_dataset({"nope": True})
    with pytest.raises(EnrichmentDatasetError):
        parse_dataset(_document(entries=[{"category_code": "X"}] * 5001))


class _Store:
    """Repository double with real deduplication semantics."""

    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def list_enrichment(self, **kwargs: object) -> list[dict[str, object]]:
        return [
            r
            for r in self.rows
            if r["fingerprint"] == kwargs["fingerprint"] and r["target_id"] == kwargs["target_id"]
        ]

    async def add_enrichment(self, **kwargs: object) -> dict[str, object]:
        for row in self.rows:
            if (row["fingerprint"], row["target_id"], row["source"], row["external_ref"]) == (
                kwargs["fingerprint"],
                kwargs["target_id"],
                "test-seed",
                kwargs["external_ref"],
            ):
                return dict(row)
        row = {
            "id": str(uuid.uuid4()),
            "fingerprint": kwargs["fingerprint"],
            "target_id": kwargs["target_id"],
            "source": "test-seed",
            "external_ref": kwargs["external_ref"],
            "cve_id": kwargs["cve_id"],
            "cwe_id": kwargs["cwe_id"],
            "cvss_score": kwargs["cvss_score"],
            "cvss_vector": kwargs["cvss_vector"],
            "references": list(kwargs["references"]),  # type: ignore[arg-type]
            "affected_technology": kwargs["affected_technology"],
            "remediation": kwargs["remediation"],
        }
        self.rows.append(row)
        return dict(row)


class _Session:
    def __init__(self, hostname: str = HOSTNAME) -> None:
        self._hostname = hostname

    async def get(self, _model: object, key: uuid.UUID) -> object | None:
        if key != TARGET:
            return None
        return type("T", (), {"id": TARGET, "hostname": self._hostname})()


def _patch_repo(monkeypatch: pytest.MonkeyPatch, store: _Store) -> None:
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    monkeypatch.setattr(ScanEngineExecutionRepository, "list_enrichment", store.list_enrichment)
    monkeypatch.setattr(ScanEngineExecutionRepository, "add_enrichment", store.add_enrichment)


async def test_import_attaches_and_rerun_dedupes(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store()
    _patch_repo(monkeypatch, store)
    first = await import_dataset(_Session(), TARGET, _document())
    assert (first.total_entries, first.attached, first.skipped_duplicates) == (1, 1, 0)
    assert first.errors == ()
    # Fingerprint resolved through the canonical function.
    from src.domain.scans.fingerprinting import generate_fingerprint

    expected = generate_fingerprint(
        hostname=HOSTNAME,
        category_code="MISSING_SECURITY_HEADER",
        identifier="strict-transport-security",
    )
    assert store.rows[0]["fingerprint"] == expected

    second = await import_dataset(_Session(), TARGET, _document())
    assert (second.total_entries, second.attached, second.skipped_duplicates) == (1, 0, 1)
    assert len(store.rows) == 1


async def test_malformed_entries_collected_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store()
    _patch_repo(monkeypatch, store)
    doc = _document(
        entries=[
            {"category_code": "MISSING_SECURITY_HEADER"},
            {"category_code": "MISSING_SECURITY_HEADER", "identifier": "x-frame-options"},
            {
                "category_code": "MISSING_SECURITY_HEADER",
                "identifier": "content-security-policy",
                "cve_id": "bogus",
            },
        ]
    )
    summary = await import_dataset(_Session(), TARGET, doc)
    assert summary.total_entries == 3
    assert summary.attached == 1
    assert len(summary.errors) == 2
    assert len(store.rows) == 1


async def test_unknown_target_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_repo(monkeypatch, _Store())
    with pytest.raises(EnrichmentDatasetError):
        await import_dataset(_Session(), uuid.uuid4(), _document())


async def test_priority_activates_from_imported_enrichment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CVE/CVSS rows present → priority gains the enrichment signals."""
    from src.domain.scans.priority import PriorityInputs, calculate_priority

    store = _Store()
    _patch_repo(monkeypatch, store)
    await import_dataset(
        _Session(),
        TARGET,
        _document(
            entries=[
                {
                    "category_code": "KNOWN_CVE",
                    "identifier": "cve-2021-44228",
                    "cve_id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                }
            ]
        ),
    )
    rows = await store.list_enrichment(fingerprint="fp", target_id=TARGET)
    assert rows == []  # unknown fingerprint: nothing attached there
    assert len(store.rows) == 1
    row = store.rows[0]
    result = calculate_priority(
        PriorityInputs(
            severity="HIGH",
            has_cve=row["cve_id"] is not None,
            cvss_score=row["cvss_score"],  # type: ignore[arg-type]
        )
    )
    assert result.score == 60 + 5 + 10
    assert "known-cve=+5" in result.factors
    assert "cvss>=9=+10" in result.factors


def test_seed_dataset_is_valid() -> None:
    """The shipped development seed parses and every entry resolves."""
    from src.domain.scans.fingerprinting import generate_fingerprint

    path = (
        Path(__file__).resolve().parent.parent.parent
        / "backend"
        / "src"
        / "domain"
        / "scans"
        / "enrichment_seed.v1.json"
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    parsed = parse_dataset(document)
    assert parsed["source"] == "sentinelgpt-curated"
    entries = parsed["entries"]
    assert isinstance(entries, list) and 1 <= len(entries) <= 10
    for entry in entries:
        assert isinstance(entry, dict)
        fingerprint = generate_fingerprint(
            hostname=HOSTNAME,
            category_code=str(entry["category_code"]),
            identifier=str(entry["identifier"]),
        )
        assert len(fingerprint) == 64
        assert entry.get("cve_id") is None  # seed carries no invented CVEs
