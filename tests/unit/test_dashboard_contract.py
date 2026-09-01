"""Contract test: the dashboard's typed API client matches the backend.

The SentinelGPT MVP dashboard (frontend/src/features/{targets,scans,reports}/)
talks to a fixed set of FastAPI endpoints. The Pydantic response models in
``backend/src/api/routes/`` are the source of truth for the JSON shape.
This test asserts every field the dashboard reads off each response is
present in the corresponding Pydantic model — so a backend rename or
removal breaks the test instead of silently breaking the UI.

Concretely: the dashboard reads
  TargetResponse.{id, hostname, url, ownerOrganizationId, ownerUserId,
                  isArchived, createdAt, status}
  ScanResponse.{id, targetId, scanProfile, status, initiatedBy,
                authorizationAttestationId, queuedAt, startedAt,
                completedAt, createdAt}
  FindingResponse.{id, title, description, severity, evidence, location,
                   recommendation, createdAt}
  AssessmentResponse.{available, provider, model, promptSchemaVersion,
                      outputSchemaVersion, failureKind,
                      unsupportedClaimCount, payload, createdAt}
  AttestationResponse.{id, targetId, method, status, expiresAt,
                       evidenceFileRef, revokedAt, revokedReason, createdAt}
  PageInfo.{nextCursor, hasNextPage}

If any of these fields are renamed or dropped, this test fails with a
descriptive diff so the frontend can be updated in the same change.
"""

from __future__ import annotations

from src.api.routes.attestation_routes import AttestationResponse
from src.api.routes.scan_routes import (
    AssessmentResponse,
    FindingResponse,
    ScanResponse,
)
from src.api.routes.target_routes import PageInfo, TargetResponse

REQUIRED_TARGET_FIELDS = {
    "id",
    "hostname",
    "url",
    "ownerOrganizationId",
    "ownerUserId",
    "isArchived",
    "createdAt",
    "status",
}

REQUIRED_SCAN_FIELDS = {
    "id",
    "targetId",
    "scanProfile",
    "status",
    "initiatedBy",
    "authorizationAttestationId",
    "queuedAt",
    "startedAt",
    "completedAt",
    "createdAt",
}

REQUIRED_FINDING_FIELDS = {
    "id",
    "title",
    "description",
    "severity",
    "evidence",
    "location",
    "recommendation",
    "createdAt",
}

REQUIRED_ASSESSMENT_FIELDS = {
    "available",
    "provider",
    "model",
    "promptSchemaVersion",
    "outputSchemaVersion",
    "failureKind",
    "unsupportedClaimCount",
    "payload",
    "createdAt",
}

REQUIRED_ATTESTATION_FIELDS = {
    "id",
    "targetId",
    "method",
    "status",
    "expiresAt",
    "evidenceFileRef",
    "revokedAt",
    "revokedReason",
    "createdAt",
}

REQUIRED_PAGE_INFO_FIELDS = {"nextCursor", "hasNextPage"}


def _pydantic_fields(model: type[object]) -> set[str]:
    """All fields the model serializes, including aliased names.

    The dashboard reads camelCase keys, so any field with
    ``serialization_alias`` or ``validation_alias`` is exposed under its
    alias rather than the snake-case Python name.
    """
    names: set[str] = set()
    for name, field in model.model_fields.items():  # type: ignore[attr-defined]
        alias = field.serialization_alias or field.validation_alias or name
        names.add(alias)
    return names


def test_target_response_shape_matches_dashboard() -> None:
    actual = _pydantic_fields(TargetResponse)
    missing = REQUIRED_TARGET_FIELDS - actual
    assert not missing, f"TargetResponse missing fields the dashboard reads: {sorted(missing)}"


def test_scan_response_shape_matches_dashboard() -> None:
    actual = _pydantic_fields(ScanResponse)
    missing = REQUIRED_SCAN_FIELDS - actual
    assert not missing, f"ScanResponse missing fields the dashboard reads: {sorted(missing)}"


def test_finding_response_shape_matches_dashboard() -> None:
    actual = _pydantic_fields(FindingResponse)
    missing = REQUIRED_FINDING_FIELDS - actual
    assert not missing, f"FindingResponse missing fields the dashboard reads: {sorted(missing)}"


def test_assessment_response_shape_matches_dashboard() -> None:
    actual = _pydantic_fields(AssessmentResponse)
    missing = REQUIRED_ASSESSMENT_FIELDS - actual
    assert not missing, f"AssessmentResponse missing fields the dashboard reads: {sorted(missing)}"


def test_attestation_response_shape_matches_dashboard() -> None:
    actual = _pydantic_fields(AttestationResponse)
    missing = REQUIRED_ATTESTATION_FIELDS - actual
    assert not missing, f"AttestationResponse missing fields the dashboard reads: {sorted(missing)}"


def test_page_info_shape_matches_dashboard() -> None:
    actual = _pydantic_fields(PageInfo)
    missing = REQUIRED_PAGE_INFO_FIELDS - actual
    assert not missing, f"PageInfo missing fields the dashboard reads: {sorted(missing)}"


def test_dashboard_endpoints_registered_in_router() -> None:
    """Every URL the dashboard calls must exist in the v1 router."""
    from src.api.routes import api_router

    # The api_router composes several sub-routers, each mounted under
    # /api/v1. Walk the tree to collect the fully-qualified (method, path)
    # pairs the dashboard actually fetches.
    expected_paths = {
        ("GET", "/api/v1/targets"),
        ("POST", "/api/v1/targets"),
        ("GET", "/api/v1/targets/{target_id}"),
        ("PATCH", "/api/v1/targets/{target_id}"),
        ("DELETE", "/api/v1/targets/{target_id}"),
        ("GET", "/api/v1/targets/{target_id}/attestations"),
        ("POST", "/api/v1/targets/{target_id}/attestations"),
        ("POST", "/api/v1/scans"),
        ("GET", "/api/v1/scans"),
        ("GET", "/api/v1/scans/{scan_id}"),
        ("POST", "/api/v1/scans/{scan_id}/cancel"),
        ("GET", "/api/v1/scans/{scan_id}/findings"),
        ("GET", "/api/v1/scans/{scan_id}/findings/{finding_id}/explanation"),
        ("GET", "/api/v1/scans/{scan_id}/assessment"),
        ("GET", "/api/v1/scans/{scan_id}/report"),
    }

    def _walk(router: object, prefix: str) -> set[tuple[str, str]]:
        found: set[tuple[str, str]] = set()
        for route in getattr(router, "routes", []):
            if hasattr(route, "methods") and hasattr(route, "path"):
                full = prefix.rstrip("/") + route.path
                for method in route.methods:
                    found.add((method, full))
            else:
                # Sub-router include: pick up the include-context prefix
                # (FastAPI stores the mount prefix on `_IncludedRouter`).
                inc = getattr(route, "include_context", None)
                sub_prefix = prefix + (
                    inc.prefix
                    if inc is not None
                    else getattr(route, "prefix", "")
                )
                found |= _walk(route.original_router, sub_prefix)
        return found

    actual = _walk(api_router, "")
    missing = expected_paths - actual
    assert not missing, f"API routes used by the dashboard are not registered: {sorted(missing)}"
