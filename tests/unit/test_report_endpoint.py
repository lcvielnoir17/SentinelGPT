"""Unit tests for the report API endpoint (SRS Ch10 §4).

The endpoint renders one scan's canonical report as JSON or CSV.
Tenant isolation must be enforced through the existing ``get_scan``
gate, the format parameter must be validated, and the response must
never be a 404 when the scan exists.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from src.reporting.assembler import (
    REPORT_SCHEMA_VERSION,
    ReportDocument,
    ReportFinding,
    ReportScanMetadata,
)


def _patch_assembler(
    monkeypatch: pytest.MonkeyPatch, document: ReportDocument | None
) -> None:
    async def _fake_assemble(self: object, _scan_id: uuid.UUID) -> ReportDocument | None:
        return document

    monkeypatch.setattr(
        "src.reporting.assembler.ReportAssembler.assemble",
        _fake_assemble,
    )


def _patch_get_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_get_scan(self: object, _scan_id: uuid.UUID) -> object:
        return object()

    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _fake_get_scan,
    )


def _document() -> ReportDocument:
    return ReportDocument(
        schema_version=REPORT_SCHEMA_VERSION,
        generated_at=__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").UTC),
        scan=ReportScanMetadata(
            target_hostname="example.test",
            target_normalized_url="https://example.test/",
            scan_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            scan_profile="standard",
            scan_status="REPORT_READY",
            initiated_by_user_id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
            queued_at=None,
            started_at=None,
            completed_at=None,
        ),
        engines=(),
        findings=(
            ReportFinding(
                id=uuid.UUID("00000000-0000-0000-0000-000000000003"),
                severity="HIGH",
                category="MISSING_SECURITY_HEADER",
                title="Missing HSTS",
                description="",
                evidence="",
                location="",
                recommendation="",
                fingerprint=None,
                affected_asset=None,
                source_engine_code=None,
                evidence_rows=(),
                explanation=None,
            ),
        ),
        assessment=None,
        severity_counts={"HIGH": 1},
        lifecycle_counts={},
    )


@pytest.fixture
def client_with_user(monkeypatch: pytest.MonkeyPatch):
    """Spin up the FastAPI app with a stable principal for auth."""
    from src.api.dependencies import get_current_user
    from src.api.routes import scan_routes
    from src.main import create_application

    monkeypatch.setattr(scan_routes, "_maybe_gemini", lambda: None)
    app = create_application()

    user = type(
        "U",
        (),
        {
            "id": uuid.uuid4(),
            "email": "tester@example.test",
            "is_active": True,
            "mfa_enabled": False,
        },
    )()
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_report_endpoint_returns_json_by_default(
    client_with_user: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_assembler(monkeypatch, _document())
    _patch_get_scan(monkeypatch)
    scan_id = uuid.uuid4()
    response = client_with_user.get(f"/api/v1/scans/{scan_id}/report")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == REPORT_SCHEMA_VERSION
    assert body["scan"]["target_hostname"] == "example.test"
    assert len(body["findings"]) == 1


def test_report_endpoint_returns_csv_when_requested(
    client_with_user: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_assembler(monkeypatch, _document())
    _patch_get_scan(monkeypatch)
    scan_id = uuid.uuid4()
    response = client_with_user.get(f"/api/v1/scans/{scan_id}/report?format=csv")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    body = response.text
    assert body.splitlines()[0].startswith("scan_id,scan_status")
    assert "MISSING_SECURITY_HEADER" in body


def test_report_endpoint_returns_404_when_assembler_returns_none(
    client_with_user: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_assembler(monkeypatch, None)
    _patch_get_scan(monkeypatch)
    scan_id = uuid.uuid4()
    response = client_with_user.get(f"/api/v1/scans/{scan_id}/report")
    assert response.status_code == 404


def test_report_endpoint_rejects_unknown_format(
    client_with_user: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_assembler(monkeypatch, _document())
    _patch_get_scan(monkeypatch)
    scan_id = uuid.uuid4()
    response = client_with_user.get(f"/api/v1/scans/{scan_id}/report?format=pdf")
    # FastAPI returns 422 (default) or 400 depending on path; either
    # way, the request MUST be rejected before the assembler runs.
    assert response.status_code in (400, 422)
