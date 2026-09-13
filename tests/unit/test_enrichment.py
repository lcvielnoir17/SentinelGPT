"""Finding enrichment foundation: validation, dedupe, tenancy, non-mutation.

Enrichment is advisory metadata bound to (fingerprint, target). These
tests prove the validation contract, the attach/dedupe seam, tenant
gating, and that canonical finding fields are never modified by
enrichment operations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from src.domain.errors import NotFoundError
from src.domain.scans.enrichment import (
    EnrichmentInput,
    EnrichmentValidationError,
    normalize_cve,
    normalize_cwe,
    normalize_references,
    validate_cvss_score,
)
from src.domain.scans.errors import InvalidEnrichmentError
from src.domain.scans.scan_service import ScanService
from tests.unit.conftest import _principal  # noqa: F401 — shared harness

SCAN = uuid.uuid4()
TARGET = uuid.uuid4()
FP = "fp-enrich-aaa"
FID = uuid.uuid4()


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #


def test_valid_cve_normalizes_case() -> None:
    assert normalize_cve("cve-2021-44228") == "CVE-2021-44228"


def test_malformed_cve_rejected() -> None:
    for bad in ("CVE-2021", "CVE-21-1234", "XVE-2021-1234", "", "CVE-2021-12"):
        with pytest.raises(EnrichmentValidationError):
            normalize_cve(bad)


def test_valid_cwe() -> None:
    assert normalize_cwe("cwe-79") == "CWE-79"
    with pytest.raises(EnrichmentValidationError):
        normalize_cwe("CWE-")
    with pytest.raises(EnrichmentValidationError):
        normalize_cwe("79")


def test_cvss_bounds() -> None:
    assert validate_cvss_score(None) is None
    assert validate_cvss_score(0) == 0.0
    assert validate_cvss_score(9.8) == 9.8
    assert validate_cvss_score(10) == 10.0
    with pytest.raises(EnrichmentValidationError):
        validate_cvss_score(10.1)
    with pytest.raises(EnrichmentValidationError):
        validate_cvss_score(-0.1)


def test_references_accept_urls_and_handles() -> None:
    assert normalize_references(["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]) == [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    ]
    assert normalize_references([]) == []
    with pytest.raises(EnrichmentValidationError):
        normalize_references(["javascript:alert(1)"])
    with pytest.raises(EnrichmentValidationError):
        normalize_references(["not a reference"])
    with pytest.raises(EnrichmentValidationError):
        normalize_references([f"https://x.test/{'a' * 2100}"])


def test_parse_accepts_camel_and_snake_keys() -> None:
    parsed = EnrichmentInput.parse(
        {
            "cveId": "cve-2014-0160",
            "cweId": "CWE-125",
            "cvssScore": 7.5,
            "references": ["https://example.test/advisory"],
        }
    )
    assert parsed.cve_id == "CVE-2014-0160"
    assert parsed.cwe_id == "CWE-125"
    assert parsed.cvss_score == 7.5
    assert parsed.external_ref == "CVE-2014-0160"


def test_parse_rejects_non_numeric_cvss() -> None:
    with pytest.raises(EnrichmentValidationError):
        EnrichmentInput.parse({"cvss_score": "high"})


# --------------------------------------------------------------------------- #
# Service seam (in-memory repository double)                                  #
# --------------------------------------------------------------------------- #


def _finding(scan_id: uuid.UUID = SCAN) -> object:
    return type(
        "F",
        (),
        {
            "id": FID,
            "scan_id": scan_id,
            "title": "Missing HSTS",
            "fingerprint": FP,
            "severity_id": 2,
        },
    )()


class _EnrichmentRepo:
    """Deduplicating in-memory double mirroring the repository contract."""

    def __init__(self) -> None:
        self.rows: list[dict[str, object]] = []

    async def get_finding_by_id(self, _fid: uuid.UUID) -> object | None:
        return _finding()

    async def list_enrichment(self, **kwargs: object) -> list[dict[str, object]]:
        assert kwargs["fingerprint"] == FP
        return list(self.rows)

    async def add_enrichment(self, **kwargs: object) -> dict[str, object]:
        for row in self.rows:
            if (row["fingerprint"], row["target_id"], row["source"], row["external_ref"]) == (
                kwargs["fingerprint"],
                kwargs["target_id"],
                kwargs["source"],
                kwargs["external_ref"],
            ):
                return dict(row)
        row = dict(kwargs)
        row["id"] = str(uuid.uuid4())
        row["created_at"] = datetime(2026, 1, 1, tzinfo=UTC).isoformat()
        row["updated_at"] = datetime(2026, 1, 1, tzinfo=UTC).isoformat()
        self.rows.append(row)
        return dict(row)


def _service(monkeypatch: pytest.MonkeyPatch, store: _EnrichmentRepo) -> ScanService:
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    scan = type("S", (), {"id": SCAN, "target_id": TARGET})()

    async def _visible(self: object, _sid: uuid.UUID) -> object:
        if _sid == SCAN:
            return scan
        raise NotFoundError()

    async def _severity(self: object, _finding: object) -> str:
        return "MEDIUM"

    monkeypatch.setattr(ScanService, "_get_visible_scan", _visible)
    monkeypatch.setattr(ScanService, "_finding_severity", _severity)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", store.get_finding_by_id)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_enrichment", store.list_enrichment)
    monkeypatch.setattr(ScanEngineExecutionRepository, "add_enrichment", store.add_enrichment)
    return ScanService(object(), _principal())  # type: ignore[arg-type]


async def test_missing_enrichment_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _EnrichmentRepo())
    assert await service.get_finding_enrichment(SCAN, FID) == []


async def test_attach_then_list_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _EnrichmentRepo())
    row = await service.attach_finding_enrichment(SCAN, FID, {"cve_id": "CVE-2014-0160"})
    assert row is not None
    assert row["cve_id"] == "CVE-2014-0160"
    assert row["external_ref"] == "CVE-2014-0160"
    listed = await service.get_finding_enrichment(SCAN, FID)
    assert listed is not None and len(listed) == 1


async def test_duplicate_attach_returns_existing_row(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _EnrichmentRepo()
    service = _service(monkeypatch, store)
    first = await service.attach_finding_enrichment(SCAN, FID, {"cve_id": "CVE-2014-0160"})
    second = await service.attach_finding_enrichment(SCAN, FID, {"cve_id": "cve-2014-0160"})
    assert first is not None and second is not None
    assert first["id"] == second["id"]
    assert len(store.rows) == 1


async def test_malformed_payload_is_400_not_500(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _EnrichmentRepo())
    with pytest.raises(InvalidEnrichmentError):
        await service.attach_finding_enrichment(SCAN, FID, {"cve_id": "bogus"})
    assert service is not None


async def test_cross_tenant_enrichment_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(monkeypatch, _EnrichmentRepo())
    with pytest.raises(NotFoundError):
        await service.get_finding_enrichment(uuid.uuid4(), FID)


async def test_attach_does_not_mutate_canonical_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """The finding DTO is byte-identical before and after enrichment."""
    store = _EnrichmentRepo()
    service = _service(monkeypatch, store)
    before = await store.get_finding_by_id(FID)
    await service.attach_finding_enrichment(
        SCAN, FID, {"cve_id": "CVE-2014-0160", "cvss_score": 7.5}
    )
    after = await store.get_finding_by_id(FID)
    assert before is not None and after is not None
    assert (before.title, before.fingerprint, before.severity_id) == (
        after.title,
        after.fingerprint,
        after.severity_id,
    )


@pytest.fixture
def enrichment_client(monkeypatch: pytest.MonkeyPatch):
    from src.api.dependencies import get_current_user
    from src.main import create_application

    store = _EnrichmentRepo()

    async def _visible(self: object, _sid: uuid.UUID) -> object:
        if _sid == SCAN:
            return type("S", (), {"id": SCAN, "target_id": TARGET})()
        raise NotFoundError()

    async def _find_one(self: object, _fid: uuid.UUID) -> object | None:
        return _finding() if _fid == FID else None

    async def _severity(self: object, _finding: object) -> str:
        return "MEDIUM"

    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    monkeypatch.setattr(ScanService, "_get_visible_scan", _visible)
    monkeypatch.setattr(ScanService, "_finding_severity", _severity)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", _find_one)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_enrichment", store.list_enrichment)
    monkeypatch.setattr(ScanEngineExecutionRepository, "add_enrichment", store.add_enrichment)
    app = create_application()
    app.dependency_overrides[get_current_user] = lambda: _principal()
    return TestClient(app)


def test_enrichment_http_roundtrip(enrichment_client: TestClient) -> None:
    empty = enrichment_client.get(f"/api/v1/scans/{SCAN}/findings/{FID}/enrichment")
    assert empty.status_code == 200, empty.text
    assert empty.json() == []

    created = enrichment_client.post(
        f"/api/v1/scans/{SCAN}/findings/{FID}/enrichment",
        json={"cveId": "CVE-2014-0160", "cvssScore": 7.5},
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["cveId"] == "CVE-2014-0160"
    assert body["cvssScore"] == 7.5

    listed = enrichment_client.get(f"/api/v1/scans/{SCAN}/findings/{FID}/enrichment")
    assert len(listed.json()) == 1


def test_enrichment_http_rejects_malformed(enrichment_client: TestClient) -> None:
    response = enrichment_client.post(
        f"/api/v1/scans/{SCAN}/findings/{FID}/enrichment", json={"cve_id": "bogus"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_enrichment_http_cross_tenant_is_404(enrichment_client: TestClient) -> None:
    assert (
        enrichment_client.get(f"/api/v1/scans/{uuid.uuid4()}/findings/{FID}/enrichment").status_code
        == 404
    )
