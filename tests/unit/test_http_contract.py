"""Tests for the HTTP scanner contract (offline; fake adapters only)."""

from __future__ import annotations

import ipaddress

import pytest

from src.domain.errors import (
    EgressDeniedError,
    RedirectDestinationBlockedError,
)
from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.http_contract import (
    ConnectionTarget,
    ControlledTransportError,
    HttpLimits,
    HttpRequestSpec,
    HttpResponseData,
    HttpScanRequest,
    RedirectChain,
    ScanCancellation,
    ScanCancelledError,
    TransportFailureKind,
)
from src.domain.scanning.redirects import RedirectValidationService
from src.domain.scanning.resolution import ScanTargetResolutionService
from tests.unit.test_resolution_binding import FakeResolver

PUBLIC = "93.184.216.34"
OTHER_PUBLIC = "8.8.8.8"
PRIVATE = "10.0.0.9"


def _context(hostname: str, *addresses: str) -> ScanNetworkContext:
    binding = ValidatedTargetBinding.create(
        hostname=hostname,
        addresses=tuple(ipaddress.ip_address(a) for a in addresses),
        validate=lambda _a: None,
    )
    return ScanNetworkContext.create(binding)


# --------------------------------------------------------------------- #
# Destination binding                                                    #
# --------------------------------------------------------------------- #


def test_connection_target_comes_only_from_pinned_context() -> None:
    context = _context("target.example", PUBLIC)
    pinned = context.binding.with_pinned(context.binding.addresses[0])
    target = ConnectionTarget.for_context(ScanNetworkContext.create(pinned), port=8443)
    assert str(target.address) == PUBLIC
    assert target.port == 8443
    assert target.scheme == "https"
    assert target.hostname == "target.example"


def test_unpinned_context_cannot_produce_a_connection_target() -> None:
    context = _context("target.example", PUBLIC)
    with pytest.raises(EgressDeniedError):
        ConnectionTarget.for_context(context)


def test_disallowed_schemes_are_rejected_before_any_target_exists() -> None:
    context = _context("target.example", PUBLIC)
    pinned = ScanNetworkContext.create(context.binding.with_pinned(context.binding.addresses[0]))
    with pytest.raises(ValueError, match="not scannable"):
        ConnectionTarget.for_context(pinned, scheme="ftp")


def test_default_ports_follow_scheme() -> None:
    ctx = ScanNetworkContext.create(
        _context("t.example", PUBLIC).binding.with_pinned(ipaddress.ip_address(PUBLIC))
    )
    https = ConnectionTarget.for_context(ctx)
    http = ConnectionTarget.for_context(ctx, scheme="http")
    assert https.port == 443 and http.port == 80


# --------------------------------------------------------------------- #
# Request authorization envelope                                         #
# --------------------------------------------------------------------- #


def test_request_envelope_requires_validated_pinned_context() -> None:
    context = _context("target.example", PUBLIC)
    with pytest.raises(EgressDeniedError):
        HttpScanRequest.authorize(
            context,
            HttpRequestSpec(path="/login"),
            scheme="https",
        )

    pinned = ScanNetworkContext.create(context.binding.with_pinned(ipaddress.ip_address(PUBLIC)))
    request = HttpScanRequest.authorize(pinned, HttpRequestSpec(path="/login"))
    assert request.target.address == ipaddress.ip_address(PUBLIC)


def test_transport_owned_headers_are_rejected() -> None:
    with pytest.raises(ValueError, match="transport-owned"):
        HttpRequestSpec(headers=(("Host", "evil.example"),))
    with pytest.raises(ValueError, match="transport-owned"):
        HttpRequestSpec(headers=(("content-length", "0"),))


def test_non_relative_paths_are_rejected() -> None:
    with pytest.raises(ValueError, match="origin-relative"):
        HttpRequestSpec(path="https://elsewhere.example/")


def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError):
        HttpLimits(max_redirects=0)
    with pytest.raises(ValueError):
        HttpLimits(connect_timeout_s=-1)
    assert HttpLimits().max_redirects == 10


# --------------------------------------------------------------------- #
# Fake client: cannot bypass the scan context                            #
# --------------------------------------------------------------------- #


class ContractEnforcingFakeClient:
    """Stands in for the future real transport; enforces the contract."""

    def __init__(self, body: bytes = b"ok") -> None:
        self.body = body
        self.seen_targets: list[ConnectionTarget] = []
        self.host_headers: list[str] = []

    def execute(
        self, request: HttpScanRequest, *, limits: HttpLimits, cancellation: ScanCancellation
    ) -> HttpResponseData:
        if cancellation.cancelled:
            raise ScanCancelledError()
        # The destination MUST be the validated pin; nothing else is legal.
        if not request.context.egress.authorize(request.target.address):
            raise EgressDeniedError()
        self.seen_targets.append(request.target)
        self.host_headers.append(request.target.hostname)
        return HttpResponseData(
            status=200,
            headers=(("content-type", "text/plain"),),
            body=self.body[: limits.max_response_bytes],
            elapsed_ms=1.0,
            final_target=request.target,
        )


def test_fake_client_connects_nowhere_but_the_pin() -> None:
    context = _context("target.example", PUBLIC)
    pinned_ctx = ScanNetworkContext.create(
        context.binding.with_pinned(ipaddress.ip_address(PUBLIC))
    )
    request = HttpScanRequest.authorize(pinned_ctx, HttpRequestSpec())
    client = ContractEnforcingFakeClient()

    response = client.execute(request, limits=HttpLimits(), cancellation=ScanCancellation.create())

    assert [str(t.address) for t in client.seen_targets] == [PUBLIC]
    assert client.host_headers == ["target.example"]
    assert response.status == 200


def test_client_refuses_destination_outside_the_binding() -> None:
    context = _context("target.example", PUBLIC)
    pinned_ctx = ScanNetworkContext.create(
        context.binding.with_pinned(ipaddress.ip_address(PUBLIC))
    )
    forged_target = ConnectionTarget.for_context(pinned_ctx)
    object.__setattr__(forged_target, "address", ipaddress.ip_address(PRIVATE))
    forged = HttpScanRequest(context=pinned_ctx, spec=HttpRequestSpec(), target=forged_target)

    with pytest.raises(EgressDeniedError):
        ContractEnforcingFakeClient().execute(
            forged, limits=HttpLimits(), cancellation=ScanCancellation.create()
        )


def test_cancellation_fires_inside_the_client() -> None:
    token = ScanCancellation.create()
    token.cancel()
    context = _context("target.example", PUBLIC)
    pinned_ctx = ScanNetworkContext.create(
        context.binding.with_pinned(ipaddress.ip_address(PUBLIC))
    )
    request = HttpScanRequest.authorize(pinned_ctx, HttpRequestSpec())
    with pytest.raises(ScanCancelledError):
        ContractEnforcingFakeClient().execute(request, limits=HttpLimits(), cancellation=token)


def test_controlled_transport_error_carries_kind() -> None:
    err = ControlledTransportError(TransportFailureKind.RESPONSE_TOO_LARGE, "2MB cap")
    assert err.kind is TransportFailureKind.RESPONSE_TOO_LARGE


# --------------------------------------------------------------------- #
# Redirect chain: revalidation, loops, budget                            #
# --------------------------------------------------------------------- #


def _redirect_service(resolver: FakeResolver) -> RedirectValidationService:
    return RedirectValidationService(ScanTargetResolutionService(resolver))


def test_redirect_chain_relative_stays_and_absolute_revalidates() -> None:
    resolver = FakeResolver(
        {
            "origin.example": FakeResolver.records(PUBLIC),
            "cdn.other.example": FakeResolver.records(OTHER_PUBLIC),
        }
    )
    service = _redirect_service(resolver)
    origin_binding = ValidatedTargetBinding.create(
        hostname="origin.example",
        addresses=(ipaddress.ip_address(PUBLIC),),
        validate=lambda _a: None,
    )
    origin = ScanNetworkContext.create(origin_binding)
    chain = RedirectChain(service.evaluate, HttpLimits())

    same = chain.follow(origin, "/next?x=1")
    assert same is origin

    moved = chain.follow(same, "https://cdn.other.example/a")
    assert moved is not same
    assert moved.binding.hostname == "cdn.other.example"


def test_redirect_chain_detects_loops_fail_closed() -> None:
    resolver = FakeResolver({"origin.example": FakeResolver.records(PUBLIC)})
    service = _redirect_service(resolver)
    origin = ScanNetworkContext.create(
        ValidatedTargetBinding.create(
            hostname="origin.example",
            addresses=(ipaddress.ip_address(PUBLIC),),
            validate=lambda _a: None,
        )
    )
    chain = RedirectChain(service.evaluate, HttpLimits())

    chain.follow(origin, "/a")
    with pytest.raises(RedirectDestinationBlockedError):
        chain.follow(origin, "/a")  # same location again => loop


def test_redirect_budget_exhaustion_is_blocked() -> None:
    resolver = FakeResolver({"origin.example": FakeResolver.records(PUBLIC)})
    service = _redirect_service(resolver)
    origin = ScanNetworkContext.create(
        ValidatedTargetBinding.create(
            hostname="origin.example",
            addresses=(ipaddress.ip_address(PUBLIC),),
            validate=lambda _a: None,
        )
    )
    chain = RedirectChain(service.evaluate, HttpLimits(max_redirects=2))

    chain.follow(origin, "/one")
    chain.follow(origin, "/two")
    with pytest.raises(RedirectDestinationBlockedError):
        chain.follow(origin, "/three")


def test_redirect_to_private_resolving_host_never_yields_a_context() -> None:
    resolver = FakeResolver(
        {
            "origin.example": FakeResolver.records(PUBLIC),
            "bait.example": FakeResolver.records(PRIVATE),
        }
    )
    service = _redirect_service(resolver)
    origin = ScanNetworkContext.create(
        ValidatedTargetBinding.create(
            hostname="origin.example",
            addresses=(ipaddress.ip_address(PUBLIC),),
            validate=lambda _a: None,
        )
    )
    chain = RedirectChain(service.evaluate, HttpLimits())

    with pytest.raises(RedirectDestinationBlockedError):
        chain.follow(origin, "http://bait.example/")
