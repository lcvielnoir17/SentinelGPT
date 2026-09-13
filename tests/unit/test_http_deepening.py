"""HTTP security deepening: cookies, CORS, cache, referrer, verbose output.

Passive assessments over the single already-fetched response — no new
requests, no crawling. Tests use synthetic responses through the same
scripted-client harness as the base engine suite.
"""

from __future__ import annotations

import ipaddress

from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.findings import Severity
from src.domain.scanning.http_contract import (
    ConnectionTarget,
    HttpLimits,
    HttpResponseData,
    HttpScanRequest,
    ScanCancellation,
)
from src.scanning.engines.http_analysis import HttpSecurityAnalysisEngine
from src.scanning.engines.services import EngineServices, OriginSpec

PIN = "93.184.216.34"
HOST = "target.example"
ENGINE = HttpSecurityAnalysisEngine()


class ScriptedClient:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[HttpScanRequest] = []

    def execute(self, request, *, limits, cancellation):  # noqa: ARG002 - protocol shape
        del limits
        cancellation.check()
        self.calls.append(request)
        return self.response  # type: ignore[no-any-return]


def _services(response: object) -> tuple[EngineServices, ScriptedClient, ScanNetworkContext]:
    binding = ValidatedTargetBinding.create(
        hostname=HOST,
        addresses=(ipaddress.ip_address(PIN),),
        validate=lambda _a: None,
    ).with_pinned(ipaddress.ip_address(PIN))
    context = ScanNetworkContext.create(binding)
    client = ScriptedClient(response)
    services = EngineServices(
        http_client_factory=lambda: client,  # type: ignore[arg-type,return-value]
        cancellation=ScanCancellation.create(),
        limits=HttpLimits(),
        origin=OriginSpec(scheme="https", path="/"),
        _context=context,
    )
    return services, client, context


def _response(headers: list[tuple[str, str]], body: bytes = b"ok") -> HttpResponseData:
    target = ConnectionTarget(
        address=ipaddress.ip_address(PIN),
        port=443,
        scheme="https",
        hostname=HOST,
    )
    return HttpResponseData(
        status=200,
        headers=tuple(headers),
        body=body,
        elapsed_ms=3.2,
        final_target=target,
        via_redirects=(),
        truncated=False,
    )


def _run(headers: list[tuple[str, str]], body: bytes = b"ok") -> object:
    services, _client, context = _services(_response(headers, body))
    return ENGINE.execute(context, services)


def _finding_titles(result: object) -> list[str]:
    return [f.title for f in result.findings]


def _finding(title: str, result: object) -> object:
    matches = [f for f in result.findings if f.title == title]
    assert len(matches) == 1, f"expected one {title!r} finding"
    return matches[0]


# --------------------------------------------------------------------------- #
# Cookie prefixes                                                             #
# --------------------------------------------------------------------------- #


def test_host_prefix_missing_secure_flagged() -> None:
    result = _run([("Set-Cookie", "__Host-sess=abc; Path=/")])
    finding = _finding("Cookie prefix violation", result)
    assert finding.severity == Severity.LOW
    assert "__Host-sess" in finding.evidence
    assert "abc" not in finding.evidence  # value redacted


def test_host_prefix_compliant_is_quiet() -> None:
    result = _run([("Set-Cookie", "__Host-sess=abc; Secure; Path=/")])
    assert "Cookie prefix violation" not in _finding_titles(result)


def test_host_prefix_with_domain_flagged() -> None:
    result = _run([("Set-Cookie", "__Host-sess=abc; Secure; Path=/; Domain=example.com")])
    assert "Cookie prefix violation" in _finding_titles(result)


def test_host_prefix_wrong_path_flagged() -> None:
    result = _run([("Set-Cookie", "__Host-sess=abc; Secure; Path=/app")])
    assert "Cookie prefix violation" in _finding_titles(result)


def test_secure_prefix_requires_secure() -> None:
    result = _run([("Set-Cookie", "__Secure-id=1; Path=/")])
    assert "Cookie prefix violation" in _finding_titles(result)
    quiet = _run([("Set-Cookie", "__Secure-id=1; Secure; Path=/")])
    assert "Cookie prefix violation" not in _finding_titles(quiet)


def test_ordinary_cookie_ignores_prefix_rules() -> None:
    result = _run([("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax")])
    assert "Cookie prefix violation" not in _finding_titles(result)


# --------------------------------------------------------------------------- #
# CORS                                                                        #
# --------------------------------------------------------------------------- #


def test_credentialed_wildcard_is_medium() -> None:
    result = _run(
        [
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ]
    )
    finding = _finding("Credentialed CORS wildcard", result)
    assert finding.severity == Severity.MEDIUM


def test_bare_wildcard_is_info() -> None:
    result = _run([("Access-Control-Allow-Origin", "*")])
    finding = _finding("Wildcard CORS origin", result)
    assert finding.severity == Severity.INFO


def test_explicit_origin_is_quiet() -> None:
    result = _run([("Access-Control-Allow-Origin", "https://app.example")])
    titles = _finding_titles(result)
    assert "Credentialed CORS wildcard" not in titles
    assert "Wildcard CORS origin" not in titles


# --------------------------------------------------------------------------- #
# Cache                                                                       #
# --------------------------------------------------------------------------- #


def test_shared_cacheable_session_response_flagged() -> None:
    result = _run(
        [
            ("Set-Cookie", "session=abc; Secure; HttpOnly"),
            ("Cache-Control", "public, max-age=60"),
        ]
    )
    finding = _finding("Cacheable sensitive response", result)
    assert finding.severity == Severity.LOW


def test_private_cache_directive_is_quiet() -> None:
    result = _run(
        [
            ("Set-Cookie", "session=abc; Secure; HttpOnly"),
            ("Cache-Control", "private, no-store"),
        ]
    )
    assert "Cacheable sensitive response" not in _finding_titles(result)


def test_public_without_cookies_is_quiet() -> None:
    result = _run([("Cache-Control", "public, max-age=60")])
    assert "Cacheable sensitive response" not in _finding_titles(result)


def test_s_maxage_counts_as_shared() -> None:
    result = _run(
        [
            ("Set-Cookie", "session=abc; Secure"),
            ("Cache-Control", "s-maxage=60"),
        ]
    )
    assert "Cacheable sensitive response" in _finding_titles(result)


# --------------------------------------------------------------------------- #
# Referrer / CSP / HSTS values                                                #
# --------------------------------------------------------------------------- #


def test_unsafe_referrer_policy_flagged() -> None:
    result = _run(
        [
            ("Referrer-Policy", "unsafe-url"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Permissions-Policy", "geolocation=()"),
        ]
    )
    finding = _finding("Permissive Referrer-Policy value", result)
    assert finding.severity == Severity.LOW


def test_strict_referrer_policy_is_quiet() -> None:
    result = _run([("Referrer-Policy", "strict-origin-when-cross-origin")])
    assert "Permissive Referrer-Policy value" not in _finding_titles(result)


def test_unsafe_inline_csp_flagged() -> None:
    result = _run([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")])
    finding = _finding("Permissive Content-Security-Policy value", result)
    assert finding.severity == Severity.LOW


def test_strict_csp_is_quiet() -> None:
    result = _run([("Content-Security-Policy", "default-src 'self'; object-src 'none'")])
    assert "Permissive Content-Security-Policy value" not in _finding_titles(result)


def test_short_hsts_max_age_flagged() -> None:
    result = _run([("Strict-Transport-Security", "max-age=60")])
    finding = _finding("Weak Strict-Transport-Security max-age", result)
    assert finding.severity == Severity.LOW


def test_strong_hsts_is_quiet() -> None:
    result = _run([("Strict-Transport-Security", "max-age=31536000; includeSubDomains")])
    titles = _finding_titles(result)
    assert "Weak Strict-Transport-Security max-age" not in titles
    assert "Missing Strict-Transport-Security security header" not in titles


# --------------------------------------------------------------------------- #
# Verbose server detail                                                       #
# --------------------------------------------------------------------------- #


def test_versioned_server_header_flagged_per_header() -> None:
    result = _run(
        [
            ("Server", "nginx/1.25.3"),
            ("X-Powered-By", "Express"),
        ]
    )
    finding = _finding("Server version disclosed: server", result)
    assert finding.severity == Severity.LOW
    assert "1.25.3" in finding.evidence
    # Express carries no version token: no finding for it.
    assert "Server version disclosed: x-powered-by" not in _finding_titles(result)


def test_debug_header_flagged() -> None:
    result = _run([("X-Debug-Token", "abc123")])
    finding = _finding("Debug header exposed", result)
    assert finding.severity == Severity.LOW
    assert "abc123" not in finding.evidence  # names only


def test_plain_server_banner_is_quiet() -> None:
    result = _run([("Server", "ExampleServer")])
    assert "Server version disclosed: server" not in _finding_titles(result)


# --------------------------------------------------------------------------- #
# Robustness                                                                  #
# --------------------------------------------------------------------------- #


def test_malicious_header_content_is_sanitized() -> None:
    result = _run(
        [
            ("Server", "nginx/1.0\x00<script>alert(1)</script>"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ]
    )
    for finding in result.findings:
        assert "\n" not in finding.evidence
        assert "\x00" not in finding.evidence
        assert len(finding.evidence) <= 512
    for observation in result.observations:
        assert len(observation.evidence) <= 512


def test_single_request_budget_preserved() -> None:
    services, client, context = _services(
        _response([("Server", "nginx/1.0"), ("Access-Control-Allow-Origin", "*")])
    )
    ENGINE.execute(context, services)
    assert len(client.calls) == 1


def test_hardening_fingerprints_stable_and_distinct() -> None:
    from src.domain.scans.fingerprinting import generate_fingerprint_from_finding

    def fp(title: str) -> str:
        return generate_fingerprint_from_finding(
            hostname=HOST,
            category_code="MISSING_SECURITY_HEADER",
            title=title,
            location="https://target.example/",
        )

    assert fp("Cookie prefix violation") == fp("Cookie prefix violation")
    assert fp("Credentialed CORS wildcard") != fp("Wildcard CORS origin")
    assert fp("Cacheable sensitive response") != fp("Cookie prefix violation")
    assert fp("Server version disclosed: server") != fp("Server version disclosed: x-powered-by")
    assert fp("Debug header exposed") != fp("Cacheable sensitive response")
