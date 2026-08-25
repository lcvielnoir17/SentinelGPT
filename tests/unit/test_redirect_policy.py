"""Redirect revalidation policy tests â€” synthetic destinations only (offline)."""

from datetime import UTC, datetime

import pytest

from src.domain.errors import RedirectDestinationBlockedError, TargetUnresolvedError
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.redirects import RedirectValidationService
from src.domain.scanning.resolution import ScanTargetResolutionService
from src.domain.scanning.resolver import (
    ResolutionFailure,
    ResolutionFailureKind,
)
from tests.unit.test_resolution_binding import FakeResolver

NOW = datetime.now(UTC)


def _service(resolver: FakeResolver) -> RedirectValidationService:
    return RedirectValidationService(ScanTargetResolutionService(resolver))


def _origin_context(resolver: FakeResolver, hostname: str = "public.example") -> ScanNetworkContext:
    origin_binding = ScanTargetResolutionService(resolver).resolve(hostname, now=NOW)
    return ScanNetworkContext.create(origin_binding)


def test_same_host_relative_redirect_inherits_validated_context() -> None:
    resolver = FakeResolver({"public.example": FakeResolver.records("93.184.216.34")})
    origin = _origin_context(resolver)

    result = _service(resolver).evaluate(origin, "/login?next=/", now=NOW)

    assert result is origin  # identity unchanged; no re-resolution occurred
    assert resolver.calls == ["public.example"]


def test_public_absolute_redirect_revalidates_into_new_context() -> None:
    resolver = FakeResolver(
        {
            "public.example": FakeResolver.records("93.184.216.34"),
            "cdn.other.example": FakeResolver.records("8.8.8.8"),
        }
    )
    origin = _origin_context(resolver)

    result = _service(resolver).evaluate(origin, "https://Cdn.Other.Example/login", now=NOW)

    assert result is not origin
    assert result.binding.hostname == "cdn.other.example"
    assert resolver.calls[-1] == "cdn.other.example"


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1/",  # loopback IP literal
        "http://169.254.169.254/latest/meta-data/",  # metadata IP literal
        "http://metadata.google.internal/",  # metadata name
        "http://internal.host.local/",  # mDNS/private suffix
        "http://fd00::1/",  # private IPv6 literal
        "ftp://public.example/file",  # unsupported scheme
        "javascript:alert(1)",  # non-network scheme
        "http://",  # malformed (no host)
    ],
)
def test_dangerous_redirect_destinations_are_blocked(location: str) -> None:
    resolver = FakeResolver({"public.example": FakeResolver.records("93.184.216.34")})
    origin = _origin_context(resolver)

    with pytest.raises(RedirectDestinationBlockedError):
        _service(resolver).evaluate(origin, location, now=NOW)


def test_redirect_to_unresolvable_host_is_blocked_not_leaked() -> None:
    resolver = FakeResolver(
        {
            "public.example": FakeResolver.records("93.184.216.34"),
            "gone.example": ResolutionFailure("gone.example", ResolutionFailureKind.NAME_NOT_FOUND),
        }
    )
    origin = _origin_context(resolver)

    with pytest.raises(RedirectDestinationBlockedError) as err:
        _service(resolver).evaluate(origin, "https://gone.example/", now=NOW)

    # The underlying resolution failure is folded into the blocked envelope;
    # no DNS detail escapes to the caller.
    assert not isinstance(err.value, TargetUnresolvedError)


def test_redirect_to_private_resolving_hostname_is_blocked() -> None:
    resolver = FakeResolver(
        {
            "public.example": FakeResolver.records("93.184.216.34"),
            "bait.example": FakeResolver.records("10.0.0.77"),
        }
    )
    origin = _origin_context(resolver)

    with pytest.raises(RedirectDestinationBlockedError):
        _service(resolver).evaluate(origin, "http://bait.example/", now=NOW)
