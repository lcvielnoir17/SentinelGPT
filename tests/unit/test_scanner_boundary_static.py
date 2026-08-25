"""Static architectural guard for the scanner security boundary.

Zone model (ADR-0002/0003):

* DEFAULT (everything under ``backend/src``): NO network clients, NO raw
  network primitives, NO process-spawning capability.
* ``backend/src/infrastructure/network``: the designated DNS zone — may use
  socket-level DNS primitives; still no HTTP clients and no subprocesses.
* ``backend/src/scanning/sandbox``: the designated runtime-enforcement
  zone — may spawn controlled processes (container lifecycle); still no
  HTTP clients and no direct sockets of its own.

Any other placement of these capabilities fails this guard, so neither the
domain services nor engine abstractions can quietly grow network or process
power. Relaxing a zone requires an explicit, reviewed change here plus the
matching ADR.
"""

from __future__ import annotations

import pathlib

SRC_ROOT = pathlib.Path("backend/src")

# Zones are matched as POSIX-style prefixes of files under SRC_ROOT.
DNS_ZONE_PREFIXES = ("infrastructure/network",)
SANDBOX_ZONE_PREFIXES = ("scanning/sandbox",)

HTTP_CLIENT_TOKENS: tuple[str, ...] = (
    "import requests",
    "from requests",
    "import httpx",
    "from httpx",
    "import aiohttp",
    "from aiohttp",
    "urllib.request",
    "urlopen(",
    "http.client",
)

NETWORK_PRIMITIVE_TOKENS: tuple[str, ...] = (
    "import socket",
    "from socket",
    "socket.",
    "create_connection",
    "getaddrinfo",
    "gethostbyname",
    "asyncio.open_connection",
    "asyncio.start_server",
)

PROCESS_TOKENS: tuple[str, ...] = (
    "subprocess",
    "create_subprocess",
    "os.system",
    "os.popen",
)

DEFAULT_FORBIDDEN = HTTP_CLIENT_TOKENS + NETWORK_PRIMITIVE_TOKENS + PROCESS_TOKENS
# DNS zone: real resolver primitives are the point; nothing else is allowed.
DNS_ZONE_ALLOWED = frozenset(
    {"import socket", "from socket", "socket.", "getaddrinfo", "gethostbyname"}
)
# Sandbox zone: container/process lifecycle only; it must never open its own
# sockets so all traffic stays inside the isolated runtime it creates.
SANDBOX_ZONE_ALLOWED = frozenset(PROCESS_TOKENS)


def _zone_for(relative_posix: str) -> str:
    if relative_posix.startswith(DNS_ZONE_PREFIXES):
        return "dns"
    if relative_posix.startswith(SANDBOX_ZONE_PREFIXES):
        return "sandbox"
    return "default"


def _violations_for(text: str, zone: str) -> list[str]:
    if zone == "dns":
        return [t for t in DEFAULT_FORBIDDEN if t in text and t not in DNS_ZONE_ALLOWED]
    if zone == "sandbox":
        return [t for t in DEFAULT_FORBIDDEN if t in text and t not in SANDBOX_ZONE_ALLOWED]
    return [t for t in DEFAULT_FORBIDDEN if t in text]


def _iter_source_files() -> list[pathlib.Path]:
    return sorted(SRC_ROOT.rglob("*.py"))


def test_default_zone_is_network_and_process_inert() -> None:
    violations: list[str] = []
    for path in _iter_source_files():
        zone = _zone_for(path.as_posix().replace("backend/src/", "", 1))
        if zone != "default":
            continue
        text = path.read_text(encoding="utf-8")
        violations.extend(f"{path}: contains {token!r}" for token in _violations_for(text, zone))
    assert not violations, "Default zone gained network/process capability:\n" + "\n".join(
        violations
    )


def test_dns_zone_has_no_http_clients_or_process_capability() -> None:
    """The DNS adapter may resolve names but never fetch URLs or spawn."""
    dns_files = [
        path
        for path in _iter_source_files()
        if _zone_for(path.as_posix().replace("backend/src/", "", 1)) == "dns"
    ]
    assert dns_files, "DNS infrastructure zone went missing; guard covers nothing"
    forbidden_here = [t for t in DEFAULT_FORBIDDEN if t not in DNS_ZONE_ALLOWED]
    violations: list[str] = []
    for path in dns_files:
        text = path.read_text(encoding="utf-8")
        violations.extend(
            f"{path}: contains {token!r}" for token in forbidden_here if token in text
        )
    assert not violations, "DNS zone gained forbidden capability:\n" + "\n".join(violations)


def test_sandbox_zone_has_no_direct_network_capability() -> None:
    """The sandbox drives runtimes via processes; it opens no sockets itself."""
    sandbox_files = [
        path
        for path in _iter_source_files()
        if _zone_for(path.as_posix().replace("backend/src/", "", 1)) == "sandbox"
    ]
    assert sandbox_files, "Sandbox infrastructure zone went missing; guard covers nothing"
    forbidden_here = [t for t in DEFAULT_FORBIDDEN if t not in SANDBOX_ZONE_ALLOWED]
    violations: list[str] = []
    for path in sandbox_files:
        text = path.read_text(encoding="utf-8")
        violations.extend(
            f"{path}: contains {token!r}" for token in forbidden_here if token in text
        )
    assert not violations, "Sandbox zone gained forbidden capability:\n" + "\n".join(violations)


def test_boundary_packages_exist_and_remain_guarded() -> None:
    for required in (
        SRC_ROOT / "domain" / "scanning",
        SRC_ROOT / "scanning" / "engines",
        SRC_ROOT / "scanning" / "sandbox",
        SRC_ROOT / "infrastructure" / "network",
    ):
        assert required.is_dir(), f"missing guarded boundary package: {required}"
