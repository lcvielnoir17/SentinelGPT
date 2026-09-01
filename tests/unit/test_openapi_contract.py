"""OpenAPI contract tests.

Two complementary surfaces are pinned:

1. The **live** schema served by the running FastAPI app at
   ``/api/v1/openapi.json`` must declare every currently registered
   ``/api/v1`` route, and must declare ``X-Refresh-Request`` as
   ``required: true`` on both ``/auth/refresh`` and ``/auth/logout``.
2. The regenerated ``openapi.json`` snapshot at the repository root must
   agree with the live schema, so consumers (CI, clients) pinning against
   the static file are not silently out of sync.

The snapshot check is the regression proof for the previous
"stale openapi.json" defect (P0-1) and the "header declared optional"
defect (P0-2). The live-schema check ensures the runtime and the
snapshot are derived from the same source.

Both checks consult the *actual* FastAPI application via
``create_application()`` — no manual inventory of routes is hard-coded
beyond the high-level grouping assertions (P0-1 wants every currently
registered route, so the live app is the source of truth).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from scripts.generate_openapi import _enforce_csrf_header_required

from src.main import create_application

if TYPE_CHECKING:
    from fastapi import FastAPI
    from httpx import AsyncClient


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _live_schema() -> dict[str, Any]:
    """Build the live OpenAPI schema from the FastAPI app and apply the
    same CSRF-header-required post-processing that the committed
    artifact uses."""
    app: FastAPI = create_application()
    schema: dict[str, Any] = copy.deepcopy(app.openapi())
    _enforce_csrf_header_required(schema)
    return schema


def _live_paths(schema: dict[str, Any] | None = None) -> dict[str, Any]:
    paths: dict[str, Any] = (schema or _live_schema())["paths"]
    return paths


def _live_v1_paths(schema: dict[str, Any] | None = None) -> set[str]:
    return {p for p in _live_paths(schema) if p.startswith("/api/v1/")}


def _csrf_param(op: dict[str, Any]) -> dict[str, Any]:
    for p in op.get("parameters", []):
        if p.get("name") == "x-refresh-request" and p.get("in") == "header":
            typed: dict[str, Any] = p
            return typed
    raise AssertionError("x-refresh-request parameter missing from operation")


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
COMMITTED_OPENAPI = REPO_ROOT / "openapi.json"


# --------------------------------------------------------------------------- #
# Live-schema contract                                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_openapi_schema_endpoint(async_client: AsyncClient) -> None:
    """The runtime OpenAPI endpoint is reachable and self-describes."""
    response = await async_client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "SentinelGPT API"
    assert "/healthz" in schema["paths"]
    assert "/readyz" in schema["paths"]


def _live_v1_paths_set() -> set[str]:
    """Return the /api/v1/* paths the live FastAPI app would expose in its
    generated OpenAPI schema. ``FastAPI.openapi()`` correctly traverses
    included routers via the private ``api_router.routes`` member;
    ``app.router.routes`` only exposes the top-level wrappers.
    """
    meta_routes = {
        "/api/v1/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"
    }
    app = create_application()
    schema_paths = set(app.openapi().get("paths", {}).keys())
    return {p for p in schema_paths if p.startswith("/api/v1/") and p not in meta_routes}


def test_live_openapi_contains_every_registered_v1_route() -> None:
    """P0-1: no registered /api/v1 route may be missing from the schema.

    FastAPI's ``app.openapi()`` is the canonical enumeration of routes
    the application advertises — it traverses every included router. We
    compare it against the live schema's path set to prove every
    registered route is represented.
    """
    live_paths = _live_v1_paths_set()
    assert live_paths, "Live FastAPI app has no /api/v1 routes"

    schema = _live_schema()
    schema_paths = {p for p in schema["paths"] if p.startswith("/api/v1/")}
    missing = live_paths - schema_paths
    assert not missing, (
        f"Live /api/v1 routes missing from OpenAPI schema: {sorted(missing)}"
    )


def test_live_openapi_route_groups_have_expected_density() -> None:
    """Sanity check: each route group declared by the SRS is represented.

    The exact operation counts are pinned by the route files themselves;
    this assertion guards against a router accidentally being excluded.
    """
    paths = _live_paths()
    by_first_segment: dict[str, int] = {}
    for p in paths:
        if not p.startswith("/api/v1/"):
            continue
        # /api/v1/<group>/...
        parts = p[len("/api/v1/"):].split("/")
        group = parts[0]
        by_first_segment[group] = by_first_segment.get(group, 0) + 1

    for group in ("healthz", "auth", "targets", "scans", "audit-log"):
        assert group in by_first_segment, (
            f"Route group /api/v1/{group}/ missing from the schema"
        )


def test_live_openapi_declares_refresh_csrf_header_required() -> None:
    """P0-2: X-Refresh-Request is required on /auth/refresh."""
    paths = _live_paths()
    op = paths["/api/v1/auth/refresh"]["post"]
    param = _csrf_param(op)
    assert param.get("required") is True, (
        "OpenAPI must declare X-Refresh-Request as required on /auth/refresh"
    )


def test_live_openapi_declares_logout_csrf_header_required() -> None:
    """P0-2: X-Refresh-Request is required on /auth/logout."""
    paths = _live_paths()
    op = paths["/api/v1/auth/logout"]["post"]
    param = _csrf_param(op)
    assert param.get("required") is True, (
        "OpenAPI must declare X-Refresh-Request as required on /auth/logout"
    )


def test_live_openapi_csrf_header_schema_constrains_value_to_1() -> None:
    """The CSRF-mitigation header value is constrained to the literal '1'."""
    paths = _live_paths()
    for path in ("/api/v1/auth/refresh", "/api/v1/auth/logout"):
        op = paths[path]["post"]
        param = _csrf_param(op)
        schema = param.get("schema", {})
        assert schema.get("type") == "string"
        assert schema.get("enum") == ["1"]


# --------------------------------------------------------------------------- #
# Committed-artifact contract                                                 #
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def committed_schema() -> dict[str, Any]:
    """Load the committed openapi.json artifact."""
    assert COMMITTED_OPENAPI.exists(), (
        f"Missing committed artifact: {COMMITTED_OPENAPI}"
    )
    loaded: dict[str, Any] = json.loads(COMMITTED_OPENAPI.read_text())
    return loaded


def test_committed_artifact_matches_live_schema(
    committed_schema: dict[str, Any],
) -> None:
    """The committed openapi.json must equal the live FastAPI schema.

    This is the regression proof for the previous "stale openapi.json"
    defect (P0-1). If the live schema changes without regenerating the
    committed artifact, this test fails.

    FastAPI's runtime injects a ``servers`` entry pointing at the host
    that served the schema — that field is environment-dependent and not
    part of the contract, so it is stripped from both sides before the
    equality check.
    """
    live = _live_schema()
    committed = copy.deepcopy(committed_schema)

    # Strip environment-specific noise.
    for s in (live, committed):
        s.pop("servers", None)

    assert live == committed, (
        "Committed openapi.json is out of sync with the live FastAPI app. "
        "Re-run scripts/generate_openapi.py."
    )


def test_committed_artifact_contains_every_registered_v1_route(
    committed_schema: dict[str, Any],
) -> None:
    """P0-1 (committed side): every live /api/v1 route is in the artifact."""
    committed_paths = {
        p for p in committed_schema["paths"] if p.startswith("/api/v1/")
    }
    live_paths = _live_v1_paths()
    missing = live_paths - committed_paths
    assert not missing, (
        f"Live routes missing from committed artifact: {sorted(missing)}"
    )


def test_committed_artifact_declares_refresh_csrf_header_required(
    committed_schema: dict[str, Any],
) -> None:
    """P0-2 (committed side): /auth/refresh declares X-Refresh-Request required."""
    op = committed_schema["paths"]["/api/v1/auth/refresh"]["post"]
    param = _csrf_param(op)
    assert param.get("required") is True


def test_committed_artifact_declares_logout_csrf_header_required(
    committed_schema: dict[str, Any],
) -> None:
    """P0-2 (committed side): /auth/logout declares X-Refresh-Request required."""
    op = committed_schema["paths"]["/api/v1/auth/logout"]["post"]
    param = _csrf_param(op)
    assert param.get("required") is True
