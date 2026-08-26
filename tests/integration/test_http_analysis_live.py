"""Live end-to-end proofs for the passive HTTP security-analysis engine.

The engine runs through the REAL chain: validated binding → established
Docker sandbox → sandbox-bound transport factory (with the real
ScanTargetResolutionService behind an injected name script) → seeded local
webapp. No external host is contacted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from tests.integration.conftest import WEBAPP_HTTP_PORT, WEBAPP_TLS_PORT
from tests.unit.test_resolution_binding import FakeResolver

from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.findings import Severity
from src.domain.scanning.http_contract import HttpLimits, ScanCancellation
from src.domain.scanning.resolution import ScanTargetResolutionService
from src.scanning.engines.http_analysis import (
    HttpAnalysisResult,
    HttpSecurityAnalysisEngine,
)
from src.scanning.sandbox.http_transport import SandboxHttpClient

if TYPE_CHECKING:
    import ipaddress

    from src.scanning.sandbox.docker_sandbox import DockerEgressSandbox

pytestmark = pytest.mark.integration

ENGINE = HttpSecurityAnalysisEngine()


def _binding(hostname: str, pin: ipaddress.IPv4Address) -> ValidatedTargetBinding:
    return ValidatedTargetBinding.create(
        hostname=hostname,
        addresses=(pin,),
        validate=lambda _a: None,
    ).with_pinned(pin)


def _run_engine(
    make_sandbox_for,  # type: ignore[no-untyped-def]
    webapp,  # type: ignore[no-untyped-def]
    hostname: str,
    *,
    scheme: str = "http",
    port: int = WEBAPP_HTTP_PORT,
    path: str = "/",
    ca_pem: str | None = None,
) -> tuple[HttpAnalysisResult, DockerEgressSandbox]:
    binding = _binding(hostname, webapp.ip)
    sandbox = make_sandbox_for(binding, (webapp.network,))
    sandbox.establish()

    resolver = FakeResolver({hostname: FakeResolver.records(str(webapp.ip))})
    resolution = ScanTargetResolutionService(resolver)
    client = SandboxHttpClient(sandbox, resolution, ca_pem=ca_pem)

    context = ScanNetworkContext.create(binding)

    from src.scanning.engines.services import EngineServices, OriginSpec

    services = EngineServices(
        http_client_factory=lambda: client,
        cancellation=ScanCancellation.create(),
        limits=HttpLimits(),
        origin=OriginSpec(scheme=scheme, port=port, path=path),
        _context=context,
    )
    return ENGINE.execute(context, services), sandbox


def test_full_chain_http_analysis_produces_expected_findings(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result, sandbox = _run_engine(make_sandbox_for, webapp, "webapp.test")

    assert result.status == 200
    header_findings = [f for f in result.findings if f.category == "http.security-headers"]
    # The seeded webapp sends none of the six security headers.
    assert len(header_findings) == 6
    missing_titles = {f.title for f in header_findings}
    assert "Missing Content-Security-Policy security header" in missing_titles
    assert "Missing Strict-Transport-Security security header" in missing_titles

    transport_obs = next(o for o in result.observations if o.title == "Transport posture")
    assert '"scheme":"http"' in transport_obs.evidence.replace(" ", "")


def test_https_analysis_marks_tls_enforced(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result, _ = _run_engine(
        make_sandbox_for,
        webapp,
        "secure.test",
        scheme="https",
        port=WEBAPP_TLS_PORT,
        ca_pem=webapp.ca_pem,
    )

    assert result.status == 200
    assert result.request_scheme == "https"
    posture = next(o for o in result.observations if o.title == "Transport posture")
    assert "certificate verification enforced" in posture.detail


def test_tls_failure_becomes_controlled_result_not_exception(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result, _ = _run_engine(
        make_sandbox_for,
        webapp,
        "wrong.test",
        scheme="https",
        port=WEBAPP_TLS_PORT,
        ca_pem=webapp.ca_pem,
    )

    assert result.status is None
    assert result.error_kind == "tls_error"
    unreachable = next(f for f in result.findings if f.title == "No HTTP response obtained")
    assert unreachable.severity is Severity.INFO


def test_cookie_hygiene_findings_and_redaction_live(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result, _ = _run_engine(make_sandbox_for, webapp, "webapp.test", path="/cookies")
    cookie_findings = [f for f in result.findings if f.category == "http.cookies"]
    titles = {f.title for f in cookie_findings}
    assert "Cookies without the Secure attribute" in titles
    assert "Cookies without the HttpOnly attribute" in titles
    assert "SameSite attribute missing or invalid" in titles

    secure_finding = next(f for f in cookie_findings if "Secure" in f.title)
    assert "nossl_ck" in secure_finding.evidence
    assert "good_ck" not in secure_finding.evidence

    serialized = result.serialize()
    for secret in ("SECRETVALUE2", "SECRETVALUE3", "SECRETVALUE4", "SECRETVALUE5"):
        assert secret not in serialized


def test_scan_isolation_between_two_contexts(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result_a, _ = _run_engine(make_sandbox_for, webapp, "webapp.test")
    result_b, _ = _run_engine(
        make_sandbox_for,
        webapp,
        "secure.test",
        scheme="https",
        port=WEBAPP_TLS_PORT,
        ca_pem=webapp.ca_pem,
    )

    serialized_a = result_a.serialize()
    serialized_b = result_b.serialize()
    assert "secure.test" not in serialized_a
    assert "webapp.test" not in serialized_b
