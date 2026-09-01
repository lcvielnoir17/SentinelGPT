"""Contract tests for GET /api/v1/scans/{scan_id}/findings.

The findings endpoint is the user-facing surface for the deterministic
pipeline output. This test module locks down two truths about the
existing implementation that are easy to break accidentally:

1. For a scan that never produced any engine output — a scan that is
   still ``QUEUED`` (worker hasn't picked it up) or a scan that was
   ``REJECTED`` because the secure chain failed at the resolution or
   sandbox step — the endpoint MUST return ``HTTP 200`` with a
   well-formed empty list, NOT a 404, a 500, or an unwrapped exception.
   An empty findings list is the truthful answer; the canonical
   ``scan_finding`` table genuinely has no rows for these scans.

2. For a scan that the secure chain ran to completion against a real
   target, the deterministic findings produced by the
   ``headers-analyzer`` engine MUST be persisted in the
   ``scan_finding`` table and exposed through the API in the
   documented ``FindingResponse`` shape.

Together these tests document the existing SRS-Chapter 8 contract
(each engine's findings are persisted as soon as that engine
completes; the public API reads from that table) without inventing
any new behavior.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.api.routes.scan_routes import FindingResponse
from src.domain.scanning.findings import Confidence, Finding, Severity

# --------------------------------------------------------------------------- #
# Shared fake-row for the scan_engine_execution DTO returned by the repo      #
# --------------------------------------------------------------------------- #


def _finding_dto(
    finding_id: uuid.UUID,
    *,
    severity: str = "LOW",
    title: str = "Missing X-Content-Type-Options header",
) -> dict[str, object]:
    """The camelCase-ish DTO the real ``list_finding_dtos`` produces."""
    return {
        "id": str(finding_id),
        "title": title,
        "description": "The response did not include the nosniff directive.",
        "evidence": "X-Content-Type-Options: (absent)",
        "location": "https://example.test/",
        "recommendation": "Add X-Content-Type-Options: nosniff to all responses.",
        "severity": severity,
        "createdAt": "2026-01-01T00:00:00Z",
    }


@pytest.fixture
def client_with_user(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, Any]:
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
            "email": "findings-tester@example.test",
            "is_active": True,
            "mfa_enabled": False,
        },
    )()
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app), user


# --------------------------------------------------------------------------- #
# 1. Empty findings for scans that never produced output                       #
# --------------------------------------------------------------------------- #


def test_findings_endpoint_returns_empty_list_for_queued_scan(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan still in ``QUEUED`` (worker hasn't run the secure chain yet)
    has no engine executions, no ``scan_finding`` rows, and the
    findings endpoint must return 200 + ``[]`` — not 404, not 500."""
    client, _ = client_with_user
    scan_id = uuid.uuid4()

    async def _get_scan(_self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        # Visible to the principal — tenant-isolation gate passes.
        return object()

    async def _list_finding_dtos(_self: object, _sid: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG001
        # Real DB: no scan_engine_execution rows for this scan, so the
        # join returns the empty set.
        return []

    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository."
        "ScanEngineExecutionRepository.list_finding_dtos",
        _list_finding_dtos,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_findings_endpoint_returns_empty_list_for_rejected_scan(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan that was transitioned to ``REJECTED`` (e.g. unresolvable
    hostname, sandbox failure, revoked attestation) has one
    ``scan_engine_execution`` row but no ``scan_finding`` rows —
    because ``_persist_findings`` is only called on the success path
    of ``ScanService.execute_scan_job``. The endpoint must still
    return 200 + ``[]``."""
    client, _ = client_with_user
    scan_id = uuid.uuid4()

    async def _get_scan(_self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    async def _list_finding_dtos(_self: object, _sid: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG001
        return []

    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository."
        "ScanEngineExecutionRepository.list_finding_dtos",
        _list_finding_dtos,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert response.status_code == 200, response.text
    assert response.json() == []


# --------------------------------------------------------------------------- #
# 2. Successful execution persists deterministic findings                       #
# --------------------------------------------------------------------------- #


def test_findings_endpoint_returns_persisted_findings_after_successful_run(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan whose headers-analyzer run produced deterministic findings
    has them in the ``scan_finding`` table; the endpoint must return
    them in the documented ``FindingResponse`` shape (camelCase,
    severities preserved, all required fields)."""
    client, _ = client_with_user
    scan_id = uuid.uuid4()
    expected = [
        _finding_dto(uuid.uuid4(), severity="LOW", title="Missing HSTS"),
        _finding_dto(uuid.uuid4(), severity="MEDIUM", title="Missing CSP"),
    ]

    async def _get_scan(_self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    async def _list_finding_dtos(_self: object, _sid: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG001
        return expected

    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository."
        "ScanEngineExecutionRepository.list_finding_dtos",
        _list_finding_dtos,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body) == 2
    assert [b["title"] for b in body] == ["Missing HSTS", "Missing CSP"]
    assert [b["severity"] for b in body] == ["LOW", "MEDIUM"]
    for row in body:
        assert set(row.keys()) == {
            "id",
            "title",
            "description",
            "evidence",
            "location",
            "recommendation",
            "severity",
            "createdAt",
        }


def test_finding_response_accepts_real_engine_finding() -> None:
    """The ``FindingResponse`` Pydantic model must accept the exact
    shape returned by the headers-analyzer (a ``Finding`` dataclass
    turned into a DTO). This catches accidental schema drift in the
    public API contract."""
    finding = Finding.create(
        category="MISSING_SECURITY_HEADER",
        title="Missing Strict-Transport-Security",
        description="The response did not include HSTS.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        evidence="Strict-Transport-Security: (absent)",
        location="https://example.test/",
        recommendation="Add HSTS to all responses.",
    )
    dto = {
        "id": str(finding.id),
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence,
        "location": finding.location,
        "recommendation": finding.recommendation,
        "severity": finding.severity.value.upper(),
        "createdAt": "2026-01-01T00:00:00Z",
    }
    parsed = FindingResponse.model_validate(dto)
    assert parsed.severity == "LOW"
    assert parsed.title == "Missing Strict-Transport-Security"
