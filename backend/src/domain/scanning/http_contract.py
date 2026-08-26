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

    def __init__(self, kind: TransportFailureKind, detail: str = "") -> None:
        self.kind = kind
        self.detail = detail
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

    def __post_init__(self) -> None:
        positive = (
            self.connect_timeout_s,
            self.read_timeout_s,
            self.max_response_bytes,
            self.max_redirects,
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
class HttpResponseData:
    """Bounded response payload plus provenance for downstream analysis."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    elapsed_ms: float
    final_target: ConnectionTarget
    via_redirects: tuple[str, ...] = ()


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
