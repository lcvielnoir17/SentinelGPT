"""HTTP scanning CONTRACTS (ADR-0005) — transport semantics, zero transport.

This module defines WHAT a future HTTP scanning layer may do and receive:

    User URL -> registration normalization -> fresh DNS resolution ->
    validate EVERY A/AAAA -> ValidatedTargetBinding -> sandbox-derived
    egress policy -> sandbox establishment -> ENGINE GATE ->
    THIS contract -> pinned destination ONLY

Hard rules encoded here:

* A connection destination can come from nowhere except a validated,
  PINNED binding (:meth:`ConnectionTarget.for_context`).
* An :class:`HttpScanRequest` is born from a validated scan context; a
  future client implementation receives it already authorized and has NO
  API to resolve names or open arbitrary destinations.
* Response/redirect/cancellation constraints are explicit values, not
  folklore constants buried in a client.

No network client of any kind exists here or may be added to the scanner
domain (static boundary guard enforces the token lists). Real adapters live
in infrastructure and appear in Phase 4+ behind :class:`HttpClient`.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from src.domain.errors import (
    EgressDeniedError,
    RedirectDestinationBlockedError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.domain.scanning.binding import ValidatedTargetBinding
    from src.domain.scanning.egress import ScanNetworkContext
    from src.domain.scanning.ip_policy import IPAddress

ALLOWED_HTTP_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
DEFAULT_PORTS: dict[str, int] = dict(_DEFAULT_PORTS)

# Headers the transport owns; caller-supplied values would let a workload
# spoof host identity or framing and are rejected at contract level.
_TRANSPORT_OWNED_HEADERS = frozenset({"host", "content-length", "connection", "transfer-encoding"})


class TransportFailureKind(enum.StrEnum):
    """Coarse taxonomy of controlled transport failures."""

    CONNECT_TIMEOUT = "connect_timeout"
    READ_TIMEOUT = "read_timeout"
    TLS_ERROR = "tls_error"
    PROTOCOL_ERROR = "protocol_error"
    RESPONSE_TOO_LARGE = "response_too_large"
    CANCELLED = "cancelled"


class ControlledTransportError(Exception):
    """A transport failure with a bounded, loggable taxonomy.

    Deliberately NOT a DomainError yet: no API surface consumes it. When an
    HTTP-facing endpoint exists, mapping decisions belong there so client
    payloads stay generic.
    """

    def __init__(
        self, kind: TransportFailureKind, detail: str = "", tls: TlsConnectionInfo | None = None
    ) -> None:
        self.kind = kind
        self.detail = detail
        # Best-effort descriptive TLS state captured alongside the failure
        # (e.g. the offending certificate when verification refused it).
        # Advisory only: never trusted, never a bypass.
        self.tls = tls
        super().__init__(f"{kind.value}: {detail}".rstrip(": "))


class ScanCancelledError(Exception):
    """Raised by clients when the cancellation token fires."""


@dataclass(frozen=True)
class HttpLimits:
    """Explicit ceilings for one HTTP scan attempt."""

    connect_timeout_s: float = 5.0
    read_timeout_s: float = 15.0
    max_response_bytes: int = 2_000_000
    max_redirects: int = 10
    # Logical requests an engine may issue per attempt. Transport-managed
    # redirect hops count against max_redirects, not this budget.
    max_requests: int = 4

    def __post_init__(self) -> None:
        positive = (
            self.connect_timeout_s,
            self.read_timeout_s,
            self.max_response_bytes,
            self.max_redirects,
            self.max_requests,
        )
        if any(value <= 0 for value in positive):
            raise ValueError("HttpLimits values must be positive")


@dataclass(frozen=True)
class ScanCancellation:
    """Cooperative cancellation flag passed down the whole attempt."""

    _flagged: bool = field(default=False, repr=False)

    @classmethod
    def create(cls) -> ScanCancellation:
        return cls(_flagged=False)

    def cancel(self) -> None:
        object.__setattr__(self, "_flagged", True)

    @property
    def cancelled(self) -> bool:
        return self._flagged

    def check(self) -> None:
        if self._flagged:
            raise ScanCancelledError("scan was cancelled")


@dataclass(frozen=True)
class ConnectionTarget:
    """The ONLY representation of where an HTTP exchange may connect.

    Constructed exclusively through :meth:`for_context`: the address is the
    binding's pinned IP (never a freshly resolved name), and the hostname is
    carried purely for Host/SNI/TLS-identity purposes.
    """

    address: IPAddress
    port: int
    scheme: str
    hostname: str

    @classmethod
    def for_context(
        cls,
        context: ScanNetworkContext,
        *,
        scheme: str = "https",
        port: int | None = None,
    ) -> ConnectionTarget:
        normalized_scheme = scheme.lower()
        if normalized_scheme not in ALLOWED_HTTP_SCHEMES:
            raise ValueError(f"scheme {scheme!r} is not scannable")
        pinned = context.binding.pinned_address
        if pinned is None:
            raise EgressDeniedError()
        # Belt-and-braces: the pin must also pass the live egress policy.
        context.authorize_destination(pinned)
        return cls(
            address=pinned,
            port=port if port is not None else _DEFAULT_PORTS[normalized_scheme],
            scheme=normalized_scheme,
            hostname=context.binding.hostname,
        )


@dataclass(frozen=True)
class HttpRequestSpec:
    """Method/path/headers/body of ONE logical request (origin-relative)."""

    method: str = "GET"
    path: str = "/"
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None

    def __post_init__(self) -> None:
        if self.method.upper() not in {"GET", "HEAD", "POST", "OPTIONS"}:
            raise ValueError(f"method {self.method!r} is not permitted")
        if not self.path.startswith("/"):
            raise ValueError("request path must be origin-relative")
        lowered = {name.lower() for name, _value in self.headers}
        smuggled = lowered & _TRANSPORT_OWNED_HEADERS
        if smuggled:
            raise ValueError(f"transport-owned headers cannot be set: {sorted(smuggled)}")


@dataclass(frozen=True)
class HttpScanRequest:
    """An authorized envelope: validated context + spec + pinned target."""

    context: ScanNetworkContext
    spec: HttpRequestSpec
    target: ConnectionTarget

    @classmethod
    def authorize(
        cls,
        context: ScanNetworkContext,
        spec: HttpRequestSpec,
        *,
        scheme: str = "https",
        port: int | None = None,
    ) -> HttpScanRequest:
        """The only sanctioned way to obtain a request envelope."""
        target = ConnectionTarget.for_context(context, scheme=scheme, port=port)
        return cls(context=context, spec=spec, target=target)


@dataclass(frozen=True)
class TlsCertificateInfo:
    """Descriptive public-certificate summary (never private material).

    Captured by the sandbox workload from the handshake it already
    performed — no new network capability. Subject/issuer are bounded
    display strings; SANs are the validated name list.
    """

    subject: str = ""
    issuer: str = ""
    san: tuple[str, ...] = ()
    not_before: str | None = None
    not_after: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "san": list(self.san),
            "not_before": self.not_before,
            "not_after": self.not_after,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> TlsCertificateInfo:
        san = raw.get("san")
        return cls(
            subject=str(raw.get("subject") or ""),
            issuer=str(raw.get("issuer") or ""),
            san=tuple(str(s) for s in san) if isinstance(san, list) else (),
            not_before=str(raw["not_before"]) if raw.get("not_before") is not None else None,
            not_after=str(raw["not_after"]) if raw.get("not_after") is not None else None,
        )


@dataclass(frozen=True)
class TlsConnectionInfo:
    """Observed TLS handshake parameters for one https exchange.

    ``verified`` records whether the transport's verification-ON handshake
    accepted the chain. When False, ``verify_error`` carries the refusal
    reason and ``certificate`` (when captured via a descriptive,
    trust-nothing handshake) describes the offending certificate so the
    engine can distinguish expired / mismatch / untrusted precisely.
    """

    version: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    verified: bool = True
    verify_error: str | None = None
    certificate: TlsCertificateInfo | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "cipher": self.cipher,
            "cipher_bits": self.cipher_bits,
            "verified": self.verified,
            "verify_error": self.verify_error,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> TlsConnectionInfo:
        cert = raw.get("certificate")
        bits = raw.get("cipher_bits")
        return cls(
            version=str(raw["version"]) if raw.get("version") is not None else None,
            cipher=str(raw["cipher"]) if raw.get("cipher") is not None else None,
            cipher_bits=int(bits) if isinstance(bits, int) else None,
            verified=bool(raw.get("verified", True)),
            verify_error=str(raw["verify_error"]) if raw.get("verify_error") is not None else None,
            certificate=TlsCertificateInfo.from_dict(cert) if isinstance(cert, dict) else None,
        )


@dataclass(frozen=True)
class HttpResponseData:
    """Bounded response payload plus provenance for downstream analysis.

    ``truncated=True`` marks bodies clamped at ``HttpLimits.max_response_bytes``
    (stream-clamped, never held unbounded in memory).
    """

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed_ms: float
    final_target: ConnectionTarget
    via_redirects: tuple[str, ...] = ()
    truncated: bool = False
    # Observed TLS state for https exchanges (None for http, or when the
    # workload could not capture it — absence never fails the scan).
    tls: TlsConnectionInfo | None = None


@runtime_checkable
class HttpClient(Protocol):
    """The seam a REAL transport adapter will implement in Phase 4+.

    Implementations MUST: connect only to ``request.target``; send
    ``Host: <target.hostname>``; perform TLS (for https) with SNI set to
    ``target.hostname`` and certificate verification against that hostname;
    enforce ``limits``; honor ``cancellation`` between redirects and while
    streaming the body; clamp bodies at ``max_response_bytes`` (raising
    ``ControlledTransportError(RESPONSE_TOO_LARGE)``); and follow redirects
    exclusively through the orchestrator's redirect chain (ADR-0005).
    """

    def execute(
        self,
        request: HttpScanRequest,
        *,
        limits: HttpLimits,
        cancellation: ScanCancellation,
    ) -> HttpResponseData:  # pragma: no cover - interface only
        ...


class RedirectChain:
    """Revalidating redirect walker shared by the future HTTP layer.

    Every absolute destination re-enters the full validation pipeline and
    receives a NEW context; relative paths stay on the validated origin;
    loops and budget exhaustion fail closed inside the block-envelope family.
    """

    def __init__(
        self,
        evaluate: Callable[[ScanNetworkContext, str], ScanNetworkContext],
        limits: HttpLimits,
    ) -> None:
        self._evaluate = evaluate
        self._remaining = limits.max_redirects
        self._seen: set[str] = set()

    def follow(self, current: ScanNetworkContext, location: str) -> ScanNetworkContext:
        """Return the NEXT validated context for this redirect hop."""
        if location in self._seen:
            raise RedirectDestinationBlockedError()  # loop: same envelope, no leak
        self._seen.add(location)
        if self._remaining <= 0:
            raise RedirectDestinationBlockedError()
        self._remaining -= 1
        return self._evaluate(current, location)


def binding_of(context: ScanNetworkContext) -> ValidatedTargetBinding:
    """Convenience accessor keeping engine code off raw attribute chains."""
    return context.binding
