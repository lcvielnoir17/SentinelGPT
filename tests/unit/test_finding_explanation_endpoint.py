"""Unit tests for the per-finding AI explanation API endpoint (SRS Ch5 §9).

The endpoint must always return a readable explanation: a finding without
AI output gets the deterministic fallback template (NEVER a 404). The
``validationStatus`` field is the UI's only signal of provenance.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.domain.scanning.analysis.fallback_templates import build_fallback_explanation
from src.domain.scanning.analysis.finding_explanation import (
    Claim,
    EvidenceReference,
    ExplanationStatus,
    FindingExplanation,
    Remediation,
)


def _build_finding_payload(
    finding_id: uuid.UUID,
    *,
    category: str = "MISSING_SECURITY_HEADER",
    severity: str = "HIGH",
    include_in_scan: bool = True,
) -> dict[str, object]:
    return {
        "id": str(finding_id),
        "title": "Missing Strict-Transport-Security security header",
        "description": "The response did not include HSTS.",
        "evidence": "Strict-Transport-Security: (absent)",
        "location": "https://example.test/",
        "recommendation": "Add HSTS to all responses.",
        "severity": severity,
        "category": category,
        "evidence_rows": [
            {
                "id": str(uuid.uuid4()),
                "type": "RAW_HEADER",
                "content": "Strict-Transport-Security: (absent)",
            }
        ],
        "_include_in_scan": include_in_scan,
    }


def test_finding_explanation_falls_back_when_ai_unavailable(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No AI assessment exists → a deterministic fallback is returned."""
    client, _ = client_with_user
    finding_id = uuid.uuid4()
    scan_id = uuid.uuid4()

    async def _get_finding_with_evidence(self: object, _fid: uuid.UUID) -> dict[str, object]:  # noqa: ARG001
        return _build_finding_payload(finding_id, include_in_scan=True)

    async def _list_dtos(self: object, _sid: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG001
        return [_build_finding_payload(finding_id, include_in_scan=True)]

    async def _get_assessment(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return None

    async def _get_scan(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()  # existence-only check passes

    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_finding_with_evidence",
        _get_finding_with_evidence,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.list_finding_dtos",
        _list_dtos,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_assessment",
        _get_assessment,
    )
    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explanation")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["available"] is True
    assert body["validationStatus"] == ExplanationStatus.FALLBACK_USED.value
    assert body["explanation"]["finding_id"] == str(finding_id)
    assert body["explanation"]["claims"]  # non-empty


def test_finding_explanation_returns_validated_when_ai_payload_has_finding(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AI payload contains the finding's narrative → return VALIDATED."""
    client, _ = client_with_user
    finding_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    ai_explanation = FindingExplanation(
        finding_id=str(finding_id),
        claims=(
            Claim(
                text="HSTS header is absent on every response.",
                references=(EvidenceReference("ev-1", snippet="Strict-Transport-Security"),),
            ),
        ),
        explanation_text="HSTS header is absent on every response.",
        severity_rationale="Missing HSTS weakens TLS enforcement.",
        remediation=Remediation(summary="Add HSTS.", steps=("Configure header.",)),
        validation_status=ExplanationStatus.VALIDATED,
        prompt_template_version="v1",
        model_name="gemini-test",
        model_version="1",
        provider="test",
    )

    async def _get_finding_with_evidence(self: object, _fid: uuid.UUID) -> dict[str, object]:  # noqa: ARG001
        return _build_finding_payload(finding_id)

    async def _list_dtos(self: object, _sid: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG001
        return [_build_finding_payload(finding_id)]

    fake_assessment = type(
        "A",
        (),
        {
            "is_available": True,
            "payload": {"findings": {str(finding_id): ai_explanation.to_dict()}},
        },
    )()

    async def _get_assessment(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return fake_assessment

    async def _get_scan(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_finding_with_evidence",
        _get_finding_with_evidence,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.list_finding_dtos",
        _list_dtos,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_assessment",
        _get_assessment,
    )
    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explanation")
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is True
    assert body["validationStatus"] == "validated"
    assert body["explanation"]["finding_id"] == str(finding_id)
    assert body["explanation"]["model"]["provider"] == "test"


def test_finding_explanation_returns_fallback_when_finding_not_in_scan(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cross-tenant probes: finding exists but not in this scan → fallback."""
    client, _ = client_with_user
    finding_id = uuid.uuid4()
    scan_id = uuid.uuid4()

    async def _get_finding_with_evidence(self: object, _fid: uuid.UUID) -> dict[str, object]:  # noqa: ARG001
        return _build_finding_payload(finding_id)

    async def _list_dtos(self: object, _sid: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG001
        return []  # finding is not in this scan's findings list

    async def _get_scan(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_finding_with_evidence",
        _get_finding_with_evidence,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.list_finding_dtos",
        _list_dtos,
    )
    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explanation")
    assert response.status_code == 200
    body = response.json()
    assert body["validationStatus"] == "FALLBACK_USED"
    assert body["fallbackReason"] == "finding_not_in_scan"


def test_finding_explanation_returns_fallback_when_finding_missing(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown finding ID → a structured fallback, never a 404."""
    client, _ = client_with_user
    finding_id = uuid.uuid4()
    scan_id = uuid.uuid4()

    async def _get_finding_with_evidence(self: object, _fid: uuid.UUID) -> dict[str, object] | None:  # noqa: ARG001
        return None

    async def _get_scan(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_finding_with_evidence",
        _get_finding_with_evidence,
    )
    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explanation")
    assert response.status_code == 200
    body = response.json()
    assert body["fallbackReason"] == "finding_not_found"


def test_finding_explanation_does_not_silently_emit_ai_text_for_known_cve(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A known-CVE finding with no AI payload gets the CVE fallback template."""
    client, _ = client_with_user
    finding_id = uuid.uuid4()
    scan_id = uuid.uuid4()

    async def _get_finding_with_evidence(self: object, _fid: uuid.UUID) -> dict[str, object]:  # noqa: ARG001
        return _build_finding_payload(finding_id, category="KNOWN_CVE")

    async def _list_dtos(self: object, _sid: uuid.UUID) -> list[dict[str, object]]:  # noqa: ARG001
        return [_build_finding_payload(finding_id, category="KNOWN_CVE")]

    async def _get_assessment(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return None

    async def _get_scan(self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_finding_with_evidence",
        _get_finding_with_evidence,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.list_finding_dtos",
        _list_dtos,
    )
    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository.ScanEngineExecutionRepository.get_assessment",
        _get_assessment,
    )
    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/findings/{finding_id}/explanation")
    body = response.json()
    expected = build_fallback_explanation(finding_id=str(finding_id), category_code="KNOWN_CVE")
    assert body["explanation"]["explanation_text"] == expected.explanation_text
    assert body["explanation"]["validation_status"] == "fallback_used"


# --------------------------------------------------------------------------- #
# TestClient harness: FastAPI app with an injected principal                   #
# --------------------------------------------------------------------------- #


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
    return TestClient(app), user
