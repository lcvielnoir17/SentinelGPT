"""Static architectural guard: the scanner boundary stays network-inert.

The packages below define the security boundary that future engines must pass
through. They must contain NO network/subprocess capability of their own —
this phase cannot accidentally become a scanner. If a future phase needs to
relax this guard (e.g. a sandboxed runner), that change must be explicit and
reviewed against ADR-0001/0002.
"""

from __future__ import annotations

import pathlib

BOUNDARY_ROOTS = (
    pathlib.Path("backend/src/domain/scanning"),
    pathlib.Path("backend/src/scanning"),
)

FORBIDDEN_TOKENS = (
    "import requests",
    "from requests",
    "import httpx",
    "from httpx",
    "import aiohttp",
    "from aiohttp",
    "urllib.request",
    "urlopen(",
    "socket.",
    "create_connection",
    "subprocess",
    "create_subprocess",
    "asyncio.open_connection",
    "getaddrinfo",
)


def test_boundary_contains_no_network_or_process_capability() -> None:
    violations: list[str] = []
    for root in BOUNDARY_ROOTS:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for token in FORBIDDEN_TOKENS:
                if token in text:
                    violations.append(f"{path}: contains {token!r}")
    assert not violations, "Scanner boundary gained network/process capability:\n" + "\n".join(
        violations
    )


def test_boundary_package_exists_and_is_imported_by_guard() -> None:
    for root in BOUNDARY_ROOTS:
        assert root.is_dir(), f"missing boundary package: {root}"
