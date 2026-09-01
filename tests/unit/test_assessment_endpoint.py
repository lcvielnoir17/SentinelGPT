"""Regression tests for GET /api/v1/scans/{scan_id}/assessment.

The unavailable path of the assessment endpoint returns a fixed
"controlled unavailability" payload (no AI run yet, no assessment
record). FastAPI's response_model validation MUST accept this payload
without raising — previously a missing validation_alias on
``AssessmentResponse`` caused the response validator to reject the
camelCase keys, surfacing as an HTTP 500 in production.

These tests assert:
  * HTTP 200 on the unavailable path (no 500).
  * The documented JSON shape: every field present, snake_case-free,
    ``available``/``provider``/``model``/``failureKind`` etc. correctly set.
  * The available-ai path also round-trips correctly through the model.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.api.routes.scan_routes import AssessmentResponse


def _build_assessment_dto() -> dict[str, object]:
    """The camelCase shape ScanEngineExecutionRepository.get_assessment_dto
    is contractually required to return."""
    return {
        "available": True,
        "provider": "gemini",
        "model": "gemini-1.5-flash",
        "promptSchemaVersion": "v1",
        "outputSchemaVersion": "v1",
        "failureKind": None,
        "unsupportedClaimCount": 2,
        "payload": {
            "findings": {"f-1": {"summary": "n/a"}},
            "executive_summary": "n/a",
        },
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
            "email": "assessment-tester@example.test",
            "is_active": True,
            "mfa_enabled": False,
        },
    )()
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app), user


def test_assessment_unavailable_returns_200_with_documented_shape(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No assessment row exists → endpoint returns the controlled
    unavailability envelope, NOT a 500."""
    client, _ = client_with_user
    scan_id = uuid.uuid4()

    async def _get_assessment_dto(_self: object, _sid: uuid.UUID) -> None:  # noqa: ARG001
        return None

    async def _get_scan(_self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository."
        "ScanEngineExecutionRepository.get_assessment_dto",
        _get_assessment_dto,
    )
    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/assessment")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {
        "available": False,
        "provider": "none",
        "model": "none",
        "promptSchemaVersion": "v1",
        "outputSchemaVersion": "v1",
        "failureKind": "not_ready",
        "unsupportedClaimCount": 0,
        "payload": {},
        "createdAt": body["createdAt"],
    }
    assert isinstance(body["createdAt"], str) and body["createdAt"]


def test_assessment_available_round_trips_through_response_model(
    client_with_user: tuple[TestClient, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the repo returns a real assessment DTO, the endpoint
    passes it through AssessmentResponse without breaking the public
    JSON contract (camelCase keys, types preserved)."""
    client, _ = client_with_user
    scan_id = uuid.uuid4()
    dto = _build_assessment_dto()

    async def _get_assessment_dto(_self: object, _sid: uuid.UUID) -> dict[str, object]:  # noqa: ARG001
        return dto

    async def _get_scan(_self: object, _sid: uuid.UUID) -> object:  # noqa: ARG001
        return object()

    monkeypatch.setattr(
        "src.infrastructure.database.repositories.scan_repository."
        "ScanEngineExecutionRepository.get_assessment_dto",
        _get_assessment_dto,
    )
    monkeypatch.setattr(
        "src.domain.scans.scan_service.ScanService.get_scan",
        _get_scan,
    )

    response = client.get(f"/api/v1/scans/{scan_id}/assessment")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {
        "available": True,
        "provider": "gemini",
        "model": "gemini-1.5-flash",
        "promptSchemaVersion": "v1",
        "outputSchemaVersion": "v1",
        "failureKind": None,
        "unsupportedClaimCount": 2,
        "payload": {
            "findings": {"f-1": {"summary": "n/a"}},
            "executive_summary": "n/a",
        },
        "createdAt": "2026-01-01T00:00:00Z",
    }


def test_assessment_response_accepts_camelcase_payload_directly() -> None:
    """The Pydantic model must accept the camelCase dict FastAPI passes
    it during response_model validation. This is the precise failure
    mode that previously produced the HTTP 500."""
    camel = {
        "available": False,
        "provider": "none",
        "model": "none",
        "promptSchemaVersion": "v1",
        "outputSchemaVersion": "v1",
        "failureKind": "not_ready",
        "unsupportedClaimCount": 0,
        "payload": {},
        "createdAt": "2026-01-01T00:00:00Z",
    }
    parsed = AssessmentResponse.model_validate(camel)
    assert parsed.failure_kind == "not_ready"
    assert parsed.unsupported_claim_count == 0
    # Serialization must keep the camelCase public contract.
    assert parsed.model_dump(by_alias=True) == camel
