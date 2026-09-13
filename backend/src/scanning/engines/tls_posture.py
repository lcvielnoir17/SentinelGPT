"""TLS posture engine — passive assessment of the authorized endpoint.

Scope (deliberately narrow):

* The engine receives ONLY ``(context, services)`` like every engine: its
  sole network capability is the sandbox-bound HTTP client factory, and it
  issues exactly ONE logical request (https origins only; plain-http
  origins yield a not-applicable result without any network use).
* TLS parameters (protocol, cipher, certificate summary, verification
  verdict) are REPORTED by the sandbox workload from the handshake it
  already performed — the engine opens no sockets, resolves no names,
  and never disables verification itself.
* When verification REFUSES the chain, the transport surfaces a
  ``tls_error`` carrying a best-effort DESCRIPTIVE certificate capture
  (trust-nothing handshake, no HTTP bytes). The engine turns that
  description into precise expired / mismatch / untrusted findings
  instead of lumping every refusal together.
* Non-certificate failures (timeout, unreachable, handshake aborted with
  no capture) are transport conditions, not vulnerabilities: observation
  plus an INFO finding, never a severity-bearing posture claim.
* HSTS posture stays with the HTTP engine (single owner, no duplicates).

Findings map to the existing canonical categories (OUTDATED_TLS,
WEAK_CIPHER) with fixed titles so fingerprints stay stable across
rescans and wording never leaks into identity.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.domain.errors import EgressDeniedError
from src.domain.scanning.findings import (
    Confidence,
    Finding,
    Observation,
    Severity,
    bound_evidence,
    dumps_stable,
)
from src.domain.scanning.http_contract import (
    ConnectionTarget,
    ControlledTransportError,
    HttpRequestSpec,
    HttpScanRequest,
    TlsConnectionInfo,
    TransportFailureKind,
)

if TYPE_CHECKING:
    from src.domain.scanning.egress import ScanNetworkContext
    from src.domain.scanning.http_contract import (
        HttpClient,
        HttpLimits,
        HttpResponseData,
        ScanCancellation,
        TlsCertificateInfo,
        TlsConnectionInfo,
    )
    from src.scanning.engines.services import EngineServices, OriginSpec

_ENGINE_CATEGORY_CERTIFICATE = "tls.certificate"
_ENGINE_CATEGORY_PROTOCOL = "tls.protocol"
_ENGINE_CATEGORY_CIPHER = "tls.cipher"

# Anything below TLS 1.2 is deprecated for general use.
_DEPRECATED_PROTOCOLS = frozenset({"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"})
# Conservative weak-cipher markers (substring, upper-cased name).
_WEAK_CIPHER_TOKENS = ("RC4", "DES", "MD5", "NULL", "EXPORT", "ANON")


@dataclass(frozen=True)
class TlsPostureResult:
    """Deterministic structured output (mirrors the HTTP engine shape)."""

    engine_name: str
    target_hostname: str
    observations: tuple[Observation, ...]
    findings: tuple[Finding, ...]
    tls_version: str | None = None
    tls_cipher: str | None = None
    certificate_valid: bool | None = None
    error_kind: str | None = None
    error_detail: str = ""
    engine_version: str = "1"

    def to_dict(self) -> dict[str, object]:
        severity_counts: dict[str, int] = {}
        for finding in self.findings:
            key = finding.severity.value
            severity_counts[key] = severity_counts.get(key, 0) + 1
        return {
            "engine": self.engine_name,
            "target": self.target_hostname,
            "tls": {
                "version": self.tls_version,
                "cipher": self.tls_cipher,
                "certificate_valid": self.certificate_valid,
            },
            "observations": [o.to_dict() for o in self.observations],
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "observation_count": len(self.observations),
                "finding_count": len(self.findings),
                "severity_counts": dict(sorted(severity_counts.items())),
            },
            "error": (
                {"kind": self.error_kind, "detail": self.error_detail} if self.error_kind else None
            ),
        }

    def serialize(self) -> str:
        return dumps_stable(self.to_dict())


@dataclass(frozen=True)
class TlsPostureEngine:
    """Passive TLS assessment over the sandbox-bound transport."""

    name: str = "tls-posture"
    version: str = "1"

    def execute(
        self,
        context: ScanNetworkContext,
        services: EngineServices,
    ) -> TlsPostureResult:
        limits = services.limits
        cancellation = services.cancellation
        origin = services.origin
        hostname = context.binding.hostname

        if origin.scheme.lower() != "https":
            observation = Observation.create(
                category=_ENGINE_CATEGORY_PROTOCOL,
                title="TLS assessment not applicable",
                detail="The authorized origin uses plain HTTP; there is no TLS posture to assess.",
                evidence=f"scheme={origin.scheme.lower()}",
                location=f"tls://{hostname}",
            )
            return self._result(hostname, [observation], [])

        if limits.max_requests < 1:
            from src.scanning.engines.http_analysis import RequestBudgetExceededError

            raise RequestBudgetExceededError("request budget below minimum")

        client: HttpClient = services.http_client_factory()
        request = self._build_request(context, services)
        try:
            response = self._single_request(client, request, limits, cancellation)
        except ControlledTransportError as exc:
            return self._refused_result(context, origin, exc)

        return self._assess_response(context, response)

    # ------------------------------------------------------------------ #
    # Request plumbing (mirrors the HTTP engine; no new capability)       #
    # ------------------------------------------------------------------ #

    def _build_request(
        self, context: ScanNetworkContext, services: EngineServices
    ) -> HttpScanRequest:
        origin = services.origin
        spec = HttpRequestSpec(method="GET", path=origin.path)
        target = ConnectionTarget.for_context(context, scheme=origin.scheme, port=origin.port)
        if not context.egress.authorize(target.address):
            raise EgressDeniedError()
        return HttpScanRequest(context=context, spec=spec, target=target)

    def _single_request(
        self,
        client: HttpClient,
        request: HttpScanRequest,
        limits: HttpLimits,
        cancellation: ScanCancellation,
    ) -> HttpResponseData:
        cancellation.check()
        return client.execute(request, limits=limits, cancellation=cancellation)

    # ------------------------------------------------------------------ #
    # Refused / failed handshakes                                        #
    # ------------------------------------------------------------------ #

    def _refused_result(
        self,
        context: ScanNetworkContext,
        origin: OriginSpec,
        exc: ControlledTransportError,
    ) -> TlsPostureResult:
        hostname = context.binding.hostname
        location = f"tls://{hostname}:{origin.port or 443}"
        observations: list[Observation] = []
        findings: list[Finding] = []
        tls = exc.tls
        if exc.kind == TransportFailureKind.TLS_ERROR and tls is not None and tls.certificate:
            observations.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_CERTIFICATE,
                    title="TLS certificate refused by verification",
                    detail=(
                        "The transport's verification-ON handshake rejected the "
                        f"presented chain ({tls.verify_error or exc.detail})."
                    ),
                    evidence=_cert_evidence(tls, hostname),
                    location=location,
                )
            )
            findings.extend(_assess_certificate(tls, hostname, location, observations))
        else:
            observations.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_PROTOCOL,
                    title="TLS handshake did not complete",
                    detail=(
                        f"The attempt ended in a controlled transport failure "
                        f"({exc.kind.value}); no TLS posture could be observed, and "
                        f"no vulnerability is claimed from the failure itself."
                    ),
                    evidence=str(exc.kind.value),
                    location=location,
                )
            )
            findings.append(
                Finding.create(
                    category=_ENGINE_CATEGORY_PROTOCOL,
                    title="No TLS assessment possible",
                    description=(
                        "The handshake did not complete, so certificate, "
                        "protocol, and cipher posture are unknown."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence=str(exc.kind.value),
                    location=location,
                    recommendation="Verify availability out-of-band; retry later.",
                    observation_ids=(observations[-1].id,),
                )
            )
        return self._result(
            hostname,
            observations,
            findings,
            error_kind=exc.kind.value,
            error_detail=bound_evidence(exc.detail, 256),
        )

    # ------------------------------------------------------------------ #
    # Successful handshake assessment                                    #
    # ------------------------------------------------------------------ #

    def _assess_response(
        self,
        context: ScanNetworkContext,
        response: HttpResponseData,
    ) -> TlsPostureResult:
        hostname = context.binding.hostname
        location = f"tls://{hostname}:{response.final_target.port}"
        observations: list[Observation] = []
        findings: list[Finding] = []
        tls = response.tls
        if tls is None:
            observations.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_PROTOCOL,
                    title="TLS parameters unavailable",
                    detail=(
                        "The exchange completed but the workload did not report "
                        "handshake parameters; no posture claims are made."
                    ),
                    evidence="tls-report-absent",
                    location=location,
                )
            )
            return self._result(hostname, observations, findings)

        observations.append(
            Observation.create(
                category=_ENGINE_CATEGORY_PROTOCOL,
                title=f"TLS {tls.version or 'unknown version'} negotiated",
                detail=f"Cipher: {tls.cipher or 'unknown'}.",
                evidence=f"version={tls.version};cipher={tls.cipher}",
                location=location,
            )
        )
        if tls.certificate is not None:
            observations.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_CERTIFICATE,
                    title="TLS certificate presented and verified",
                    detail="The transport's verification-ON handshake accepted the chain.",
                    evidence=_cert_evidence(tls, hostname),
                    location=location,
                )
            )
            # Validity re-checked locally (cheap, clock-skew-robust); on the
            # success path this yields observations only in practice.
            findings.extend(_assess_certificate(tls, hostname, location, observations))

        protocol_finding = _assess_protocol(tls, location)
        if protocol_finding is not None:
            observations.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_PROTOCOL,
                    title="Deprecated TLS protocol observed",
                    detail=f"Negotiated version: {tls.version}.",
                    evidence=f"version={tls.version}",
                    location=location,
                )
            )
            findings.append(protocol_finding)
        cipher_finding = _assess_cipher(tls, location)
        if cipher_finding is not None:
            observations.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_CIPHER,
                    title="Weak TLS cipher observed",
                    detail=f"Negotiated cipher: {tls.cipher}.",
                    evidence=f"cipher={tls.cipher}",
                    location=location,
                )
            )
            findings.append(cipher_finding)

        return self._result(
            hostname,
            observations,
            findings,
            tls_version=tls.version,
            tls_cipher=tls.cipher,
            certificate_valid=tls.verified and tls.certificate is not None,
        )

    def _result(
        self,
        hostname: str,
        observations: list[Observation],
        findings: list[Finding],
        *,
        tls_version: str | None = None,
        tls_cipher: str | None = None,
        certificate_valid: bool | None = None,
        error_kind: str | None = None,
        error_detail: str = "",
    ) -> TlsPostureResult:
        return TlsPostureResult(
            engine_name=self.name,
            engine_version=self.version,
            target_hostname=hostname,
            observations=tuple(observations),
            findings=tuple(findings),
            tls_version=tls_version,
            tls_cipher=tls_cipher,
            certificate_valid=certificate_valid,
            error_kind=error_kind,
            error_detail=error_detail,
        )


# ---------------------------------------------------------------------- #
# Deterministic assessment helpers (pure; unit-testable)                  #
# ---------------------------------------------------------------------- #


def _cert_evidence(tls: TlsConnectionInfo, hostname: str) -> str:
    cert = tls.certificate
    if cert is None:
        return f"host={hostname};certificate=absent"
    san = ",".join(cert.san[:8])
    return bound_evidence(
        f"host={hostname};subject={cert.subject};issuer={cert.issuer};"
        f"san={san};valid={cert.not_before}..{cert.not_after};"
        f"version={tls.version};cipher={tls.cipher}"
    )


def _assess_certificate(
    tls: TlsConnectionInfo, hostname: str, location: str, observations_out: list[Observation]
) -> list[Finding]:
    """Expired / not-yet-valid / mismatch / untrusted, most specific first.

    Each finding carries its own observation (appended to
    ``observations_out``); at most one certificate finding fires per
    assessment so overlapping causes never double-count.
    """
    cert = tls.certificate
    if cert is None:
        return []
    findings: list[Finding] = []
    now = time.time()

    not_after: float | None = _parse_cert_time(cert.not_after)
    not_before: float | None = _parse_cert_time(cert.not_before)
    if not_after is not None and not_after < now:
        findings.append(
            _cert_finding(
                "TLS certificate expired",
                "The presented certificate is past its notAfter date; clients "
                "with correct clocks refuse the connection.",
                tls,
                hostname,
                location,
                observations_out,
            )
        )
        return findings
    if not_before is not None and not_before > now:
        findings.append(
            _cert_finding(
                "TLS certificate not yet valid",
                "The presented certificate is before its notBefore date; "
                "clients refuse the connection.",
                tls,
                hostname,
                location,
                observations_out,
            )
        )
        return findings
    if not _hostname_matches(cert, hostname):
        findings.append(
            _cert_finding(
                "TLS certificate hostname mismatch",
                "None of the certificate's SAN entries (or subject CN) "
                "identify the scanned hostname; clients refuse the connection.",
                tls,
                hostname,
                location,
                observations_out,
            )
        )
        return findings
    if not tls.verified:
        findings.append(
            _cert_finding(
                "TLS certificate not trusted",
                f"The chain failed verification ({tls.verify_error or 'unknown reason'}).",
                tls,
                hostname,
                location,
                observations_out,
            )
        )
    return findings


def _cert_finding(
    title: str,
    description: str,
    tls: TlsConnectionInfo,
    hostname: str,
    location: str,
    observations_out: list[Observation],
) -> Finding:
    observation = Observation.create(
        category=_ENGINE_CATEGORY_CERTIFICATE,
        title=title,
        detail=description,
        evidence=_cert_evidence(tls, hostname),
        location=location,
    )
    observations_out.append(observation)
    return Finding.create(
        category=_ENGINE_CATEGORY_CERTIFICATE,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        evidence=_cert_evidence(tls, hostname),
        location=location,
        recommendation=(
            "Serve a valid certificate chain for this hostname from a "
            "publicly trusted CA, and renew before expiry."
        ),
        observation_ids=(observation.id,),
    )


def _assess_protocol(tls: TlsConnectionInfo, location: str) -> Finding | None:
    version = (tls.version or "").strip()
    if not version or version.lower() not in _DEPRECATED_PROTOCOLS:
        return None
    return Finding.create(
        category=_ENGINE_CATEGORY_PROTOCOL,
        title="Deprecated TLS protocol negotiated",
        description=(
            f"The endpoint negotiated {version}, which is deprecated; "
            "modern clients may refuse it and its primitives are weaker."
        ),
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        evidence=f"version={version}",
        location=location,
        recommendation="Disable protocol versions below TLS 1.2.",
        observation_ids=(),
    )


def _assess_cipher(tls: TlsConnectionInfo, location: str) -> Finding | None:
    cipher = (tls.cipher or "").upper()
    if not cipher or not any(token in cipher for token in _WEAK_CIPHER_TOKENS):
        return None
    return Finding.create(
        category=_ENGINE_CATEGORY_CIPHER,
        title="Weak TLS cipher negotiated",
        description=(
            f"The endpoint negotiated {tls.cipher}, which uses deprecated "
            "primitives and weakens connection confidentiality."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        evidence=f"cipher={tls.cipher}",
        location=location,
        recommendation="Prefer AEAD suites (AES-GCM/ChaCha20-Poly1305); disable weak ciphers.",
        observation_ids=(),
    )


def _parse_cert_time(raw: str | None) -> float | None:
    """ASN.1 time (as reported) → epoch seconds, or None when unparseable."""
    if not raw:
        return None
    import ssl

    try:
        return float(ssl.cert_time_to_seconds(str(raw)))
    except (ValueError, TypeError):
        return None


def _hostname_matches(cert: TlsCertificateInfo, hostname: str) -> bool:
    """Local SAN/CN check mirroring verification semantics (RFC 6125).

    Implemented directly: ``ssl.match_hostname`` was removed in Python
    3.12, and shelling certificate identity out to a helper keeps the
    rule explicit and unit-testable. DNS SANs take precedence over the
    subject CN; a leading ``*.`` wildcard matches exactly one label.
    """
    import ipaddress

    wanted = hostname.strip().lower().rstrip(".")
    if not wanted:
        return False
    try:
        ipaddress.ip_address(wanted)
        wanted_is_ip = True
    except ValueError:
        wanted_is_ip = False

    dns_names: list[str] = []
    ip_names: list[str] = []
    for name in cert.san or ():
        cleaned = name.strip().lower().rstrip(".")
        if not cleaned:
            continue
        try:
            ipaddress.ip_address(cleaned)
            ip_names.append(cleaned)
        except ValueError:
            dns_names.append(cleaned)
    if wanted_is_ip:
        return wanted in ip_names
    if dns_names:
        return any(_dns_name_matches(pattern, wanted) for pattern in dns_names)
    cn = _subject_cn(cert.subject)
    return cn is not None and _dns_name_matches(cn, wanted)


def _subject_cn(subject: str) -> str | None:
    for chunk in subject.split(","):
        if "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        if key.strip().upper() == "CN":
            candidate = value.strip().strip('"').lower().rstrip(".")
            return candidate or None
    return None


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.strip().lower()
    hostname = hostname.strip().lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix or "." not in hostname:
            return False
        parent = hostname.split(".", 1)[1]
        return parent == suffix and "*" not in suffix
    return pattern == hostname and "*" not in pattern
