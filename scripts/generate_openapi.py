"""Generate the committed ``openapi.json`` from the live FastAPI app.

The committed OpenAPI artifact is built directly from ``create_application()``
so it cannot drift from the running code. A small post-processing step marks
the CSRF-mitigation header (``X-Refresh-Request``) as ``required`` on
``/auth/refresh`` and ``/auth/logout`` — the runtime still rejects a missing
header with the existing ``RefreshCsrfHeaderMissingError`` (403 FORBIDDEN,
not a 422 validation error), so the schema declaration aligns with the
SRS Ch2 §9 contract that the actual API enforces.

Run from the repository root::

    .venv/Scripts/python scripts/generate_openapi.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from src.main import create_application  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "openapi.json"

# Operations on which X-Refresh-Request MUST be declared required.
_CSRF_REQUIRED_OPS: dict[str, set[str]] = {
    "/api/v1/auth/refresh": {"post"},
    "/api/v1/auth/logout": {"post"},
}

_CSRF_PARAM_DESCRIPTION = (
    "CSRF mitigation per SRS Ch2 §9. Same-origin JS sets this custom header; "
    "cross-site form posts cannot. Must be the literal string '1'."
)


def _enforce_csrf_header_required(schema: dict[str, Any]) -> None:
    """Mark ``X-Refresh-Request`` as required on the protected auth ops.

    FastAPI auto-generates the parameter as ``required: false`` because the
    route declares ``Annotated[str | None, Header()] = None`` — that lets the
    runtime raise the project's own 403 envelope (``RefreshCsrfHeaderMissingError``)
    instead of a generic 422 validation error. We flip the schema field to
    ``required: true`` so the public contract matches the enforced runtime.
    """
    paths: dict[str, Any] = schema["paths"]
    for path, methods in _CSRF_REQUIRED_OPS.items():
        path_item = paths.get(path)
        if path_item is None:
            raise RuntimeError(f"Expected {path} in OpenAPI schema")
        for method in methods:
            op = path_item.get(method)
            if op is None:
                raise RuntimeError(f"Expected {method.upper()} {path} in OpenAPI schema")
            params: list[dict[str, Any]] = op.setdefault("parameters", [])
            for p in params:
                if p.get("name") == "x-refresh-request" and p.get("in") == "header":
                    p["required"] = True
                    p["description"] = _CSRF_PARAM_DESCRIPTION
                    p["schema"] = {"type": "string", "enum": ["1"]}
            if not any(
                p.get("name") == "x-refresh-request" and p.get("in") == "header" for p in params
            ):
                raise RuntimeError(f"x-refresh-request parameter missing from {method} {path}")


def main() -> None:
    # These defaults make the script runnable from a fresh checkout
    # where the operator hasn't yet provisioned a database / JWT secret.
    # ``setdefault`` ensures we don't clobber a configured environment
    # (CI, staging, production).
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-must-be-at-least-32-chars-long")
    os.environ.setdefault(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/sentinelgpt_test",
    )
    os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")

    app = create_application()
    schema: dict[str, Any] = app.openapi()
    _enforce_csrf_header_required(schema)
    OUTPUT_PATH.write_text(json.dumps(schema, indent=2))
    paths = sorted(schema["paths"].keys())
    print(f"Wrote {OUTPUT_PATH.relative_to(REPO_ROOT)}")
    print(f"Total paths: {len(paths)}")


if __name__ == "__main__":
    main()
