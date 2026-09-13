"""TLS posture engine: assessment, error taxonomy, fingerprint stability.

The engine is passive: it issues one logical request through the
sandbox-bound client factory and assesses the workload-reported TLS
handshake. Tests use synthetic ``TlsConnectionInfo`` blocks (no network)
plus controlled transport failures.
"""

from __future__ import annotations

import ipaddress

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
    TlsCertificateInfo,
    TlsConnectionInfo,
    TransportFailureKind,
)
from src.scanning.engines.services import EngineServices, OriginSpec
from src.scanning.engines.tls_posture import TlsPostureEngine

PIN = "93.184.216.34"
HOST = "target.example"
ENGINE = TlsPostureEngine()


class ScriptedClient:
    def __init__(self, response: object | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[HttpScanRequest] = []

    def execute(self, request, *, limits, cancellation):  # noqa: ARG002 - protocol shape
        del limits
        cancellation.check()
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        assert self.response is not None
        return self.response  # type: ignore[no-any-return]


def _services(
    response: object | None = None,
    error: Exception | None = None,
    *,
    scheme: str = "https",
) -> tuple[EngineServices, ScriptedClient, ScanNetworkContext]:
    binding = ValidatedTargetBinding.create(
        hostname=HOST,
        addresses=(ipaddress.ip_address(PIN),),
        validate=lambda _a: None,
    ).with_pinned(ipaddress.ip_address(PIN))
    context = ScanNetworkContext.create(binding)
    client = ScriptedClient(response, error)
    services = EngineServices(
        http_client_factory=lambda: client,  # type: ignore[arg-type,return-value]
        cancellation=ScanCancellation.create(),
        limits=HttpLimits(),
        origin=OriginSpec(scheme=scheme, path="/"),
        _context=context,
    )
    return services, client, context


def _tls_response(tls: TlsConnectionInfo | None) -> HttpResponseData:
    target = ConnectionTarget(
        address=ipaddress.ip_address(PIN),
        port=443,
        scheme="https",
        hostname=HOST,
    )
    return HttpResponseData(
        status=200,
        headers=(("content-type", "text/html"),),
        body=b"ok",
        elapsed_ms=3.2,
        final_target=target,
        via_redirects=(),
        truncated=False,
        tls=tls,
    )


def _cert(
    *,
    san: tuple[str, ...] = ("target.example",),
    subject: str = "CN=target.example,O=Example",
    issuer: str = "CN=Test CA,O=Example",
    not_before: str | None = "Jan  1 00:00:00 2020 GMT",
    not_after: str | None = "Jan  1 00:00:00 2030 GMT",
) -> TlsCertificateInfo:
    return TlsCertificateInfo(
        subject=subject, issuer=issuer, san=san, not_before=not_before, not_after=not_after
    )


def _tls(
    *,
    version: str | None = "TLSv1.3",
    cipher: str | None = "TLS_AES_128_GCM_SHA256",
    verified: bool = True,
    verify_error: str | None = None,
    certificate: TlsCertificateInfo | None = None,
) -> TlsConnectionInfo:
    return TlsConnectionInfo(
        version=version,
        cipher=cipher,
        cipher_bits=128,
        verified=verified,
        verify_error=verify_error,
        certificate=certificate if certificate is not None else _cert(),
    )


def _run_tls(tls: TlsConnectionInfo | None) -> object:
    services, _client, context = _services(_tls_response(tls))
    return ENGINE.execute(context, services)


def _titles(result: object) -> list[str]:
    return [f.title for f in result.findings]


# --------------------------------------------------------------------------- #
# Applicability & sound posture                                               #
# --------------------------------------------------------------------------- #


def test_http_origin_is_not_applicable_without_network() -> None:
    services, client, context = _services(_tls_response(None), scheme="http")
    result = ENGINE.execute(context, services)
    assert client.calls == []
    assert result.findings == ()
    assert any("not applicable" in o.title.lower() for o in result.observations)


def test_sound_posture_produces_no_findings() -> None:
    result = _run_tls(_tls(version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256"))
    assert result.findings == ()
    assert any("negotiated" in o.title for o in result.observations)
    assert result.tls_version == "TLSv1.3"
    assert result.certificate_valid is True


def test_tls12_strong_cipher_is_quiet() -> None:
    result = _run_tls(_tls(version="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    assert result.findings == ()


def test_missing_tls_report_yields_no_claims() -> None:
    result = _run_tls(None)
    assert result.findings == ()
    assert any("unavailable" in o.title for o in result.observations)


# --------------------------------------------------------------------------- #
# Certificate findings                                                        #
# --------------------------------------------------------------------------- #


def test_expired_certificate() -> None:
    tls = _tls(
        verified=False,
        verify_error="certificate has expired",
        certificate=_cert(not_after="Jan  1 00:00:00 2020 GMT"),
    )
    services, _client, context = _services(
        None, ControlledTransportError(TransportFailureKind.TLS_ERROR, "refused", tls=tls)
    )
    result = ENGINE.execute(context, services)
    assert _titles(result) == ["TLS certificate expired"]
    assert result.findings[0].severity == Severity.MEDIUM
    assert result.findings[0].category == "tls.certificate"


def test_not_yet_valid_certificate() -> None:
    tls = _tls(
        verified=False,
        certificate=_cert(
            not_before="Jan  1 00:00:00 2035 GMT", not_after="Jan  1 00:00:00 2040 GMT"
        ),
    )
    services, _client, context = _services(
        None, ControlledTransportError(TransportFailureKind.TLS_ERROR, "refused", tls=tls)
    )
    result = ENGINE.execute(context, services)
    assert _titles(result) == ["TLS certificate not yet valid"]


def test_hostname_mismatch() -> None:
    tls = _tls(
        verified=False,
        verify_error="hostname mismatch",
        certificate=_cert(san=("other.example",), subject="CN=other.example"),
    )
    services, _client, context = _services(
        None, ControlledTransportError(TransportFailureKind.TLS_ERROR, "refused", tls=tls)
    )
    result = ENGINE.execute(context, services)
    assert _titles(result) == ["TLS certificate hostname mismatch"]


def test_untrusted_self_signed() -> None:
    tls = _tls(
        verified=False,
        verify_error="self-signed certificate",
        certificate=_cert(),
    )
    services, _client, context = _services(
        None, ControlledTransportError(TransportFailureKind.TLS_ERROR, "refused", tls=tls)
    )
    result = ENGINE.execute(context, services)
    assert _titles(result) == ["TLS certificate not trusted"]


def test_cn_fallback_matches_without_san() -> None:
    result = _run_tls(_tls(certificate=_cert(san=(), subject="CN=target.example")))
    assert result.findings == ()


def test_wildcard_san_matches_single_label() -> None:
    result = _run_tls(_tls(certificate=_cert(san=("*.example.com",), subject="CN=*.example.com")))
    # Fixture hostname is target.example: the wildcard does NOT cover the
    # apex, so this must still mismatch.
    assert _titles(result) == ["TLS certificate hostname mismatch"]


def test_wildcard_matching_rules() -> None:
    from src.scanning.engines.tls_posture import _dns_name_matches

    assert _dns_name_matches("*.example.com", "www.example.com") is True
    assert _dns_name_matches("*.example.com", "example.com") is False
    assert _dns_name_matches("*.example.com", "a.b.example.com") is False
    assert _dns_name_matches("example.com", "example.com") is True
    assert _dns_name_matches("example.com", "www.example.com") is False
    assert _dns_name_matches("EXAMPLE.com", "example.COM") is True


def test_most_specific_cause_wins() -> None:
    """An expired cert that also mismatches reports expiry, not mismatch."""
    tls = _tls(
        verified=False,
        certificate=_cert(
            san=("other.example",),
            subject="CN=other.example",
            not_after="Jan  1 00:00:00 2020 GMT",
        ),
    )
    services, _client, context = _services(
        None, ControlledTransportError(TransportFailureKind.TLS_ERROR, "refused", tls=tls)
    )
    result = ENGINE.execute(context, services)
    assert _titles(result) == ["TLS certificate expired"]


# --------------------------------------------------------------------------- #
# Protocol & cipher                                                           #
# --------------------------------------------------------------------------- #


def test_deprecated_protocol_is_low() -> None:
    result = _run_tls(_tls(version="TLSv1.1", cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    assert _titles(result) == ["Deprecated TLS protocol negotiated"]
    assert result.findings[0].severity == Severity.LOW
    assert result.findings[0].category == "tls.protocol"


def test_weak_cipher_is_medium() -> None:
    result = _run_tls(_tls(version="TLSv1.2", cipher="DES-CBC3-SHA"))
    assert _titles(result) == ["Weak TLS cipher negotiated"]
    assert result.findings[0].severity == Severity.MEDIUM
    assert result.findings[0].category == "tls.cipher"


def test_rc4_cipher_flagged() -> None:
    result = _run_tls(_tls(version="TLSv1.2", cipher="RC4-SHA"))
    assert _titles(result) == ["Weak TLS cipher negotiated"]


# --------------------------------------------------------------------------- #
# Failure taxonomy: no vulnerability from transport conditions                #
# --------------------------------------------------------------------------- #


def test_handshake_failure_without_capture_is_info_only() -> None:
    services, _client, context = _services(
        None, ControlledTransportError(TransportFailureKind.TLS_ERROR, "handshake aborted")
    )
    result = ENGINE.execute(context, services)
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert result.error_kind == "tls_error"


def test_timeout_is_not_a_vulnerability() -> None:
    services, _client, context = _services(
        None, ControlledTransportError(TransportFailureKind.CONNECT_TIMEOUT, "slow")
    )
    result = ENGINE.execute(context, services)
    assert [f.severity for f in result.findings] == [Severity.INFO]
    assert result.error_kind == "connect_timeout"


# --------------------------------------------------------------------------- #
# Fingerprint stability & evidence bounds                                     #
# --------------------------------------------------------------------------- #


def test_finding_identity_stable_across_runs() -> None:
    from src.domain.scans.fingerprinting import generate_fingerprint_from_finding

    left = generate_fingerprint_from_finding(
        hostname="Target.Example.",
        category_code="OUTDATED_TLS",
        title="TLS certificate expired",
        location="tls://target.example:443",
    )
    right = generate_fingerprint_from_finding(
        hostname="target.example",
        category_code="OUTDATED_TLS",
        title="TLS certificate expired",
        location="tls://target.example:443",
    )
    assert left == right
    other = generate_fingerprint_from_finding(
        hostname="target.example",
        category_code="OUTDATED_TLS",
        title="TLS certificate hostname mismatch",
        location="tls://target.example:443",
    )
    assert other != left
    cipher_fp = generate_fingerprint_from_finding(
        hostname="target.example",
        category_code="WEAK_CIPHER",
        title="Weak TLS cipher negotiated",
        location="tls://target.example:443",
    )
    assert cipher_fp != left


def test_evidence_is_bounded() -> None:
    many_san = tuple(["target.example"] + [f"host{i}.example" for i in range(60)])
    result = _run_tls(_tls(certificate=_cert(san=many_san)))
    assert result.findings == ()
    assert all(len(o.evidence) <= 512 for o in result.observations)


def test_engine_result_serializes_deterministically() -> None:
    first = _run_tls(_tls(version="TLSv1.1", cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    second = _run_tls(_tls(version="TLSv1.1", cipher="ECDHE-RSA-AES128-GCM-SHA256"))
    assert first.serialize() == second.serialize()


def test_unpinned_context_is_refused_before_network() -> None:
    """No validated pin → EgressDeniedError, zero client calls."""
    from src.domain.errors import EgressDeniedError

    binding = ValidatedTargetBinding.create(
        hostname=HOST,
        addresses=(ipaddress.ip_address(PIN),),
        validate=lambda _a: None,
    )
    context = ScanNetworkContext.create(binding)
    services, client, _ = _services(_tls_response(_tls()))
    with pytest.raises(EgressDeniedError):
        ENGINE.execute(context, services)
    assert client.calls == []
