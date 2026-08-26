"""Unit tests for the passive HTTP security-analysis engine (offline).

A scripted fake client stands in for the sandbox-aware transport so header/
cookie/transport assessments are exercised deterministically without any
network or daemon.
"""

from __future__ import annotations

import ipaddress
import json

import pytest

from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.findings import Severity
from src.domain.scanning.http_contract import (
    ConnectionTarget,
    ControlledTransportError,
    HttpLimits,
    HttpResponseData,
    HttpScanRequest,
    ScanCancellation,
    TransportFailureKind,
)
from src.scanning.engines.http_analysis import (
    HttpAnalysisResult,
    HttpSecurityAnalysisEngine,
)
from src.scanning.engines.services import EngineServices, OriginSpec

PIN = "93.184.216.34"
ENGINE = HttpSecurityAnalysisEngine()


class ScriptedClient:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[HttpScanRequest] = []

    def execute(self, request, *, limits, cancellation):  # noqa: ARG002 - protocol shape
        del limits
        cancellation.check()
        self.calls.append(request)
        assert isinstance(self.response, object)
        return self.response  # type: ignore[no-any-return]


def _response(
    *,
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"ok",
    truncated: bool = False,
) -> HttpResponseData:
    target = ConnectionTarget(
        address=ipaddress.ip_address(PIN),
        port=443,
        scheme="https",
        hostname="target.example",
    )
    return HttpResponseData(
        status=status,
        headers=tuple(headers or []),
        body=body,
        elapsed_ms=3.2,
        final_target=target,
        via_redirects=(),
        truncated=truncated,
    )


def _services(
    response: object,
    *,
    limits: HttpLimits | None = None,
    cancelled: bool = False,
):
    binding = ValidatedTargetBinding.create(
        hostname="target.example",
        addresses=(ipaddress.ip_address(PIN),),
        validate=lambda _a: None,
    ).with_pinned(ipaddress.ip_address(PIN))
    context = ScanNetworkContext.create(binding)
    client = ScriptedClient(response)
    token = ScanCancellation.create()
    if cancelled:
        token.cancel()
    services = EngineServices(
        http_client_factory=lambda: client,  # type: ignore[arg-type,return-value]
        cancellation=token,
        limits=limits or HttpLimits(),
        origin=OriginSpec(scheme="https", path="/"),
        _context=context,
    )
    return services, client, context


def _run(response: object, **kwargs: object) -> tuple[HttpAnalysisResult, ScriptedClient]:
    services, client, context = _services(response, **kwargs)
    result = ENGINE.execute(context, services)
    return result, client


# --------------------------------------------------------------------- #
# Basics                                                                 #
# --------------------------------------------------------------------- #


def test_engine_returns_structured_result_with_transport_observations() -> None:
    result, client = _run(_response(headers=[("Server", "unit"), ("Content-Type", "text/html")]))

    assert result.target_hostname == "target.example"
    assert result.status == 200
    assert result.engine_name == "http-security-analysis"
    titles = [o.title for o in result.observations]
    assert "Transport posture" in titles
    assert any("Server information exposed: server" in t for t in titles)
    assert len(client.calls) == 1  # exactly one logical request
    sent = client.calls[0]
    assert sent.spec.path == "/"
    assert sent.target.hostname == "target.example"


def test_request_budget_zero_is_rejected_by_contract_and_engine_guard() -> None:
    """The contract rejects non-positive budgets; the engine guard is the
    second, independent line of defense for exhausted budgets."""
    with pytest.raises(ValueError):
        HttpLimits(max_requests=0)

    services, client, context = _services(_response(), limits=HttpLimits(max_requests=1))
    ENGINE.execute(context, services)
    assert len(client.calls) == 1  # exactly the budgeted request


def test_precancelled_token_blocks_execution() -> None:
    from src.domain.scanning.http_contract import ScanCancelledError

    services, client, context = _services(_response(), cancelled=True)
    with pytest.raises(ScanCancelledError):
        ENGINE.execute(context, services)
    assert client.calls == []


def test_truncated_flag_flows_into_result() -> None:
    result, _ = _run(_response(truncated=True))
    assert result.truncated is True


def test_controlled_tls_failure_becomes_unreachable_result() -> None:
    class FailingClient(ScriptedClient):
        def execute(self, request, *, limits, cancellation):  # noqa: ARG002 - protocol shape
            del request, limits, cancellation
            raise ControlledTransportError(TransportFailureKind.TLS_ERROR, "cert")

    services, _, context = _services(None)
    failing = FailingClient(None)
    rebuilt = EngineServices(
        http_client_factory=lambda: failing,  # type: ignore[arg-type,return-value]
        cancellation=services.cancellation,
        limits=services.limits,
        origin=services.origin,
        _context=context,
    )
    result = ENGINE.execute(context, rebuilt)

    assert result.status is None
    assert result.error_kind == "tls_error"
    assert "No HTTP response obtained" in [f.title for f in result.findings]


# --------------------------------------------------------------------- #
# Security headers                                                       #
# --------------------------------------------------------------------- #

GOOD_HEADERS = [
    ("Content-Security-Policy", "default-src 'self'"),
    ("Strict-Transport-Security", "max-age=63072000"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "geolocation=()"),
]


def test_all_security_headers_present_yields_no_header_findings() -> None:
    result, _ = _run(_response(headers=list(GOOD_HEADERS)))
    header_findings = [f for f in result.findings if f.category == "http.security-headers"]
    assert header_findings == []
    present = [o.title for o in result.observations if "present" in o.title]
    assert len(present) == 6


def test_missing_security_headers_produce_low_or_info_findings() -> None:
    result, _ = _run(_response())
    missing = {
        f.title: f.severity for f in result.findings if f.category == "http.security-headers"
    }
    assert missing["Missing Content-Security-Policy security header"] is Severity.LOW
    assert missing["Missing X-Content-Type-Options security header"] is Severity.LOW
    assert missing["Missing Referrer-Policy security header"] is Severity.INFO
    assert missing["Missing Permissions-Policy security header"] is Severity.INFO


def test_nonstandard_xcto_value_is_flagged_instead_of_absence() -> None:
    result, _ = _run(_response(headers=[("X-Content-Type-Options", "sniff")]))
    titles = [f.title for f in result.findings]
    assert "Nonstandard X-Content-Type-Options value" in titles
    assert "Missing X-Content-Type-Options security header" not in titles


# --------------------------------------------------------------------- #
# Cookies                                                                #
# --------------------------------------------------------------------- #

COOKIE_ATTRS = {
    "good": "; Secure; HttpOnly; SameSite=Strict",
    "nossl": "; HttpOnly; SameSite=Lax",
    "nohttp": "; Secure; SameSite=Lax",
    "nosite": "; Secure; HttpOnly",
    "badsite": "; Secure; HttpOnly; SameSite=gibberish",
}


def _cookie_response(*names_and_values: tuple[str, str]) -> HttpResponseData:
    headers = [
        ("Set-Cookie", f"{name}={value}" + COOKIE_ATTRS.get(name.split("_")[0], ""))
        for name, value in names_and_values
    ]
    return _response(headers=headers)


def test_cookie_attribute_matrix_produces_expected_findings() -> None:
    result, _ = _run(_cookie_response(("good_s1", "v1"), ("nossl_s2", "v2"), ("nohttp_s3", "v3")))
    cookie_findings = [f for f in result.findings if f.category == "http.cookies"]
    titles = [f.title for f in cookie_findings]

    assert "Cookies without the Secure attribute" in titles
    assert "Cookies without the HttpOnly attribute" in titles

    secure_finding = next(f for f in cookie_findings if "Secure" in f.title)
    assert "nossl_s2" in secure_finding.evidence
    assert "good_s1" not in secure_finding.evidence


def test_malformed_and_unspecified_samesite_are_distinguished() -> None:
    result, _ = _run(_cookie_response(("nosite_a", "v1"), ("badsite_b", "v2")))
    samesite = next(f for f in result.findings if "SameSite" in f.title)
    assert "unspecified" in samesite.evidence
    assert "invalid 'gibberish'" in samesite.evidence
    assert samesite.severity is Severity.INFO


def test_cookie_values_never_appear_in_serialization() -> None:
    secret = "SUPERSECRETVALUE123"
    result, _ = _run(_cookie_response(("session", secret)))
    serialized = result.serialize()
    assert secret not in serialized
    assert "[<value-redacted>]" in serialized


def test_well_formed_cookies_yield_no_cookie_findings() -> None:
    result, _ = _run(_cookie_response(("good_a", "v"), ("good_b", "w")))
    assert [f for f in result.findings if f.category == "http.cookies"] == []


# --------------------------------------------------------------------- #
# Determinism / boundedness                                              #
# --------------------------------------------------------------------- #


def test_findings_have_deterministic_ids_across_runs() -> None:
    r1, _ = _run(_response(headers=[("Server", "s")]))
    r2, _ = _run(_response(headers=[("Server", "s")]))
    assert [o.id for o in r1.observations] == [o.id for o in r2.observations]
    assert [f.id for f in r1.findings] == [f.id for f in r2.findings]
    assert r1.serialize() == r2.serialize()


def test_serialization_round_trip_contains_summary() -> None:
    result, _ = _run(_response())
    parsed = json.loads(result.serialize())
    assert parsed["summary"]["finding_count"] == len(result.findings)
    assert parsed["summary"]["observation_count"] == len(result.observations)


def test_evidence_is_bounded_for_giant_headers() -> None:
    giant = "x" * 10_000
    result, _ = _run(_response(headers=[("Server", giant)]))
    server_obs = next(o for o in result.observations if "exposed: server" in o.title)
    assert len(server_obs.evidence) <= 513  # clamp limit + ellipsis
