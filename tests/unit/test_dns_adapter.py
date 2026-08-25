"""Unit tests for the platform DNS adapter (hermetic; no real lookups).

The adapter's underlying ``getaddrinfo`` is injectable, so every behavior —
multi-record handling, dedup, failure taxonomy, freshness — is exercised
against scripted responses. One integration-marked test exercises the real
OS resolver against ``localhost`` only.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from src.domain.scanning.resolver import (
    ResolutionFailure,
    ResolutionFailureKind,
    ResolutionSuccess,
)
from src.infrastructure.network.dns_resolver import (
    GetAddrInfoRecord,
    PlatformDnsResolver,
)

PUBLIC_A = "93.184.216.34"
PUBLIC_B = "8.8.8.8"
PUBLIC_C = "151.101.1.140"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
PUBLIC_V6B = "2620:fe::fe"


def v4(address: str) -> GetAddrInfoRecord:
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))


def v6(address: str) -> GetAddrInfoRecord:
    return (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, 0, 0, 0))


class ScriptedGetAddrInfo:
    """Callable standing in for ``socket.getaddrinfo`` in tests."""

    def __init__(self, *records: GetAddrInfoRecord) -> None:
        self.records = list(records)
        self._pending: list[GetAddrInfoRecord] | None = None
        self.calls: list[str] = []

    def queue_next(self, *records: GetAddrInfoRecord) -> None:
        """Change the script so the NEXT call observes different answers."""
        self._pending = list(records)

    def __call__(self, host: str, *_args: object, **_kwargs: object) -> list[GetAddrInfoRecord]:
        self.calls.append(host)
        if isinstance(self.records, Exception):
            raise self.records
        if self._pending is not None:
            self.records = self._pending
            self._pending = None
        return list(self.records)


def _addresses(outcome: object) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    assert isinstance(outcome, ResolutionSuccess)
    return outcome.addresses


def test_multiple_a_records_all_returned_never_first_only() -> None:
    resolver = PlatformDnsResolver(ScriptedGetAddrInfo(v4(PUBLIC_A), v4(PUBLIC_B), v4(PUBLIC_C)))
    outcome = resolver.resolve_all("multi.example")
    got = _addresses(outcome)
    assert len(got) == 3
    assert {str(a) for a in got} == {PUBLIC_A, PUBLIC_B, PUBLIC_C}


def test_multiple_aaaa_records_all_returned() -> None:
    resolver = PlatformDnsResolver(ScriptedGetAddrInfo(v6(PUBLIC_V6), v6(PUBLIC_V6B)))
    got = _addresses(resolver.resolve_all("v6.example"))
    assert len(got) == 2
    assert all(a.version == 6 for a in got)


def test_mixed_a_and_aaaa_records_both_preserved() -> None:
    resolver = PlatformDnsResolver(ScriptedGetAddrInfo(v4(PUBLIC_A), v6(PUBLIC_V6), v4(PUBLIC_B)))
    got = _addresses(resolver.resolve_all("dual.example"))
    assert {a.version for a in got} == {4, 6}
    assert len(got) == 3


def test_duplicate_records_are_deduplicated() -> None:
    resolver = PlatformDnsResolver(
        ScriptedGetAddrInfo(v4(PUBLIC_A), v4(PUBLIC_A), v6(PUBLIC_V6), v6(PUBLIC_V6))
    )
    got = _addresses(resolver.resolve_all("dup.example"))
    assert [str(a) for a in got] == [PUBLIC_A, PUBLIC_V6]  # v4 first: version-ordered


def test_result_order_is_deterministic_v4_before_v6() -> None:
    resolver = PlatformDnsResolver(ScriptedGetAddrInfo(v6(PUBLIC_V6), v4(PUBLIC_A)))
    got = _addresses(resolver.resolve_all("order.example"))
    assert [a.version for a in got] == [4, 6]


def test_non_inet_families_are_ignored() -> None:
    bogus: GetAddrInfoRecord = (999, socket.SOCK_STREAM, 0, "", ("/tmp/sock",))
    resolver = PlatformDnsResolver(ScriptedGetAddrInfo(bogus, v4(PUBLIC_A)))
    got = _addresses(resolver.resolve_all("weird.example"))
    assert [str(a) for a in got] == [PUBLIC_A]


def test_zero_usable_records_is_explicit_no_records_failure() -> None:
    resolver = PlatformDnsResolver(ScriptedGetAddrInfo())
    outcome = resolver.resolve_all("empty.example")
    assert isinstance(outcome, ResolutionFailure)
    assert outcome.kind is ResolutionFailureKind.NO_RECORDS


def _name_not_found_errnos() -> frozenset[int]:
    from src.infrastructure.network.dns_resolver import _NAME_NOT_FOUND_ERRNOS

    return _NAME_NOT_FOUND_ERRNOS  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    "errno_attr",
    [
        "EAI_NONAME",
        "WSAHOST_NOT_FOUND",
    ],
)
def test_name_not_found_classification(errno_attr: str) -> None:
    errno = getattr(socket, errno_attr, None)
    if errno is None:  # platform does not expose this constant
        pytest.skip(f"{errno_attr} not available on this platform")

    class Raising(ScriptedGetAddrInfo):
        def __call__(self, host: str, *_a: object, **_k: object) -> list[GetAddrInfoRecord]:
            self.calls.append(host)
            raise socket.gaierror(errno, "name or service not known")

    outcome = PlatformDnsResolver(Raising()).resolve_all("missing.example")
    assert isinstance(outcome, ResolutionFailure)
    assert outcome.kind is ResolutionFailureKind.NAME_NOT_FOUND


@pytest.mark.parametrize(
    "errno_attr",
    [
        "EAI_NODATA",
        "WSANO_DATA",
    ],
)
def test_no_data_classification(errno_attr: str) -> None:
    errno = getattr(socket, errno_attr, None)
    if errno is None:
        pytest.skip(f"{errno_attr} not available on this platform")
    if errno in _name_not_found_errnos():
        # Windows collapses EAI_NODATA onto the EAI_NONAME code; the platform
        # cannot distinguish the two, so this case is untestable there.
        pytest.skip(f"{errno_attr} shares a code with name-not-found on this platform")

    class Raising(ScriptedGetAddrInfo):
        def __call__(self, host: str, *_a: object, **_k: object) -> list[GetAddrInfoRecord]:
            self.calls.append(host)
            raise socket.gaierror(errno, "no address associated with name")

    outcome = PlatformDnsResolver(Raising()).resolve_all("nodata.example")
    assert isinstance(outcome, ResolutionFailure)
    assert outcome.kind is ResolutionFailureKind.NO_RECORDS


@pytest.mark.parametrize(
    ("errno_attr", "fallback"),
    [("EAI_AGAIN", 11002), ("WSATRY_AGAIN", 11002)],
)
def test_transient_classification(errno_attr: str, fallback: int) -> None:
    errno = getattr(socket, errno_attr, fallback)

    class Raising(ScriptedGetAddrInfo):
        def __call__(self, host: str, *_a: object, **_k: object) -> list[GetAddrInfoRecord]:
            self.calls.append(host)
            raise socket.gaierror(errno, "temporary failure")

    outcome = PlatformDnsResolver(Raising()).resolve_all("again.example")
    assert isinstance(outcome, ResolutionFailure)
    assert outcome.kind is ResolutionFailureKind.TRANSIENT_ERROR


def test_non_gai_os_error_is_transient() -> None:
    class Raising(ScriptedGetAddrInfo):
        def __call__(self, host: str, *_a: object, **_k: object) -> list[GetAddrInfoRecord]:
            self.calls.append(host)
            raise OSError("resolver exploded")

    outcome = PlatformDnsResolver(Raising()).resolve_all("boom.example")
    assert isinstance(outcome, ResolutionFailure)
    assert outcome.kind is ResolutionFailureKind.TRANSIENT_ERROR


def test_empty_hostname_fails_without_invoking_resolver() -> None:
    script = ScriptedGetAddrInfo(v4(PUBLIC_A))
    outcome = PlatformDnsResolver(script).resolve_all("   ")
    assert isinstance(outcome, ResolutionFailure)
    assert outcome.kind is ResolutionFailureKind.NAME_NOT_FOUND
    assert script.calls == []


def test_resolution_is_fresh_on_every_call_no_caching() -> None:
    script = ScriptedGetAddrInfo(v4(PUBLIC_A))
    resolver = PlatformDnsResolver(script)

    first = _addresses(resolver.resolve_all("shifty.example"))
    assert [str(a) for a in first] == [PUBLIC_A]

    script.queue_next(v4(PUBLIC_B))
    second = _addresses(resolver.resolve_all("shifty.example"))
    assert [str(a) for a in second] == [PUBLIC_B]
    assert script.calls == ["shifty.example", "shifty.example"]


def test_whitespace_hostname_is_normalized() -> None:
    script = ScriptedGetAddrInfo(v4(PUBLIC_A))
    outcome = PlatformDnsResolver(script).resolve_all("  padded.example ")
    assert isinstance(outcome, ResolutionSuccess)
    assert outcome.hostname == "padded.example"
    assert script.calls == ["padded.example"]


@pytest.mark.integration
def test_real_localhost_resolution_contains_loopback() -> None:
    """Smoke test against the OS resolver; contacts loopback names only."""
    outcome = PlatformDnsResolver().resolve_all("localhost")
    assert isinstance(outcome, ResolutionSuccess)
    assert any(
        ipaddress.ip_address("127.0.0.1") in (a,) or str(a) == "::1" for a in outcome.addresses
    )
