"""Sandbox-aware HTTP transport: the real :class:`HttpClient` (ADR-0006).

Security chain realized here:

    HttpScanRequest (validated context, pinned target)
      -> require_established(sandbox)
      -> destination re-checked against the live egress policy
      -> spec serialized to the container-side workload
      -> kernel-enforced OUTPUT chain governs every packet
      -> bounded, marker-framed response parsed back

The host process NEVER opens a scan socket itself and NEVER resolves names:
absolute redirect hops go through :class:`ScanTargetResolutionService`
(fresh resolution + full-record validation + NEW binding + NEW pin), and a
fresh exchange runs inside the same established sandbox for every hop.
Relative hops keep the current validated origin/pin and merge paths only.

Pinned-IP vs logical-identity mechanism: the URL host is the pinned IP
(IPv6 bracketed); the logical hostname rides in the ``Host`` header and in
the ``sni_hostname`` request extension, which httpcore passes as SSL
``server_hostname`` — driving SNI AND certificate verification against the
validated name while verification stays fully enabled.

Capability note (static guard): this zone may import httpx because all
traffic originates inside the established sandbox runtime; the host-side
module itself imports no network library at all.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from typing import TYPE_CHECKING

from src.domain.errors import (
    EgressDeniedError,
    RedirectDestinationBlockedError,
)
from src.domain.scanning.egress import ScanNetworkContext
from src.domain.scanning.http_contract import (
    ConnectionTarget,
    ControlledTransportError,
    HttpLimits,
    HttpRequestSpec,
    HttpResponseData,
    HttpScanRequest,
    ScanCancellation,
    TransportFailureKind,
)
from src.domain.scanning.redirects import RedirectValidationService
from src.scanning.sandbox.base import ExecResult, require_established
from src.scanning.sandbox.http_workload_loader import WORKLOAD_B64

if TYPE_CHECKING:
    from src.domain.scanning.resolution import ScanTargetResolutionService
    from src.scanning.sandbox.base import EgressSandbox

_SUCCESS_PREFIX = "SGPT/1 "
_ERROR_PREFIX = "SGPTERR/1 "
_MAX_SPEC_ARGV_BYTES = 65536
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HOP_BY_HOP_HEADERS = frozenset(
    {"connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-authorization"}
)
_KIND_MAP = {
    "connect_timeout": TransportFailureKind.CONNECT_TIMEOUT,
    "read_timeout": TransportFailureKind.READ_TIMEOUT,
    "tls_error": TransportFailureKind.TLS_ERROR,
    "protocol_error": TransportFailureKind.PROTOCOL_ERROR,
    "response_too_large": TransportFailureKind.RESPONSE_TOO_LARGE,
    "cancelled": TransportFailureKind.CANCELLED,
}
_DEFAULT_PORTS = {"http": 80, "https": 443}


class SandboxHttpClient:
    """Executes contract requests inside an established egress sandbox."""

    def __init__(
        self,
        sandbox: EgressSandbox,
        resolution: ScanTargetResolutionService,
    ) -> None:
        self._sandbox = sandbox
        self._resolution = resolution
        self._redirects = RedirectValidationService(resolution)

    # ------------------------------------------------------------------ #
    # HttpClient protocol                                                #
    # ------------------------------------------------------------------ #

    def execute(
        self,
        request: HttpScanRequest,
        *,
        limits: HttpLimits,
        cancellation: ScanCancellation,
    ) -> HttpResponseData:
        """Run one logical HTTP exchange, following validated hops only."""
        require_established(self._sandbox)

        current = self._authorize_or_refuse(request.context, request.spec, request.target)
        via: list[str] = []
        seen_locations: set[str] = set()
        remaining_hops = limits.max_redirects

        while True:
            cancellation.check()
            response = self._exchange(current, limits)
            location_raw = _header(response.headers, "location")
            if response.status not in _REDIRECT_STATUSES or location_raw is None:
                return HttpResponseData(
                    status=response.status,
                    headers=response.headers,
                    body=response.body,
                    elapsed_ms=response.elapsed_ms,
                    final_target=current.target,
                    via_redirects=tuple(via),
                    truncated=response.truncated,
                )
            if response.truncated:
                # A clamped body must never be parsed for routing decisions.
                raise ControlledTransportError(
                    TransportFailureKind.RESPONSE_TOO_LARGE,
                    "redirect response exceeded size cap",
                )
            location = location_raw.strip()
            if location in seen_locations:
                raise RedirectDestinationBlockedError()
            seen_locations.add(location)
            if remaining_hops <= 0:
                raise RedirectDestinationBlockedError()
            remaining_hops -= 1
            via.append(location)
            current = self._next_hop(current, location)

    # ------------------------------------------------------------------ #
    # Hop resolution                                                     #
    # ------------------------------------------------------------------ #

    def _next_hop(self, current: HttpScanRequest, location: str) -> HttpScanRequest:
        parts = urllib.parse.urlsplit(location)
        if not parts.scheme and not parts.netloc:
            # Relative: stay on THIS validated origin/pin; merge paths only.
            merged_path = urllib.parse.urljoin(current.spec.path, location)
            spec = HttpRequestSpec(
                method=current.spec.method,
                path=merged_path,
                headers=_strip_hop_headers(current.spec.headers),
            )
            return self._authorize_or_refuse(current.context, spec, current.target)

        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            raise RedirectDestinationBlockedError()
        if current.target.scheme == "https" and scheme == "http":
            # Downgrade policy (ADR-0006): never silently walk HTTPS down.
            raise RedirectDestinationBlockedError()
        try:
            port = parts.port
        except ValueError as exc:
            raise RedirectDestinationBlockedError() from exc

        next_context = self._redirects.evaluate(current.context, location)
        pinned_context = self._pin_context(next_context)
        target = ConnectionTarget.for_context(pinned_context, scheme=scheme, port=port)
        spec = HttpRequestSpec(
            method=current.spec.method,
            path=parts.path or "/",
            headers=_strip_hop_headers(current.spec.headers),
        )
        return self._authorize_or_refuse(pinned_context, spec, target)

    @staticmethod
    def _pin_context(context: ScanNetworkContext) -> ScanNetworkContext:
        """Pin the hop to the validated primary address (ADR-0005/0006).

        The redirect service returns an unpinned context; the transport is
        the consumer that chooses the connection destination, and it may
        only choose among addresses the policy already approved.
        """
        addresses = context.binding.addresses
        if not addresses:
            raise EgressDeniedError()
        pinned = ScanNetworkContext.create(context.binding.with_pinned(addresses[0]))
        return pinned

    def _authorize_or_refuse(
        self, context: ScanNetworkContext, spec: HttpRequestSpec, target: ConnectionTarget
    ) -> HttpScanRequest:
        if context.binding.pinned_address is None:
            raise EgressDeniedError()
        # Belt-and-braces before any exec: the destination must still be
        # authorized by the live egress policy derived from the binding.
        if not context.egress.authorize(target.address):
            raise EgressDeniedError()
        return HttpScanRequest(context=context, spec=spec, target=target)

    # ------------------------------------------------------------------ #
    # Single sandbox exchange                                            #
    # ------------------------------------------------------------------ #

    def _exchange(self, request: HttpScanRequest, limits: HttpLimits) -> HttpResponseData:
        spec_json = json.dumps(
            {
                "url": _pinned_url(request.target, request.spec.path),
                "method": request.spec.method.upper(),
                "headers": [(*pair,) for pair in request.spec.headers]
                + [("Host", request.target.hostname)],
                "body_b64": (
                    base64.b64encode(request.spec.body).decode()
                    if request.spec.body is not None
                    else None
                ),
                "connect_timeout_s": min(limits.connect_timeout_s, 30.0),
                "read_timeout_s": min(limits.read_timeout_s, 30.0),
                "max_response_bytes": limits.max_response_bytes,
                "sni_hostname": request.target.hostname,
            },
            separators=(",", ":"),
        )
        spec_b64 = base64.b64encode(spec_json.encode()).decode()
        if len(spec_b64) > _MAX_SPEC_ARGV_BYTES:
            raise ValueError("request exceeds sandbox argv budget")

        result = self._sandbox.run(["python", "-I", "-c", WORKLOAD_B64, "--spec-b64", spec_b64])
        return _parse_exec_result(result, final_target=request.target)


def _parse_exec_result(result: ExecResult, *, final_target: ConnectionTarget) -> HttpResponseData:
    for line in result.stdout.splitlines():
        if line.startswith(_SUCCESS_PREFIX):
            payload = json.loads(line[len(_SUCCESS_PREFIX) :])
            return HttpResponseData(
                status=int(payload["status"]),
                headers=tuple((str(k), str(v)) for k, v in payload["headers"]),
                body=base64.b64decode(payload["body_b64"]),
                elapsed_ms=float(payload["elapsed_ms"]),
                final_target=final_target,
                truncated=bool(payload.get("truncated", False)),
            )
        if line.startswith(_ERROR_PREFIX):
            payload = json.loads(line[len(_ERROR_PREFIX) :])
            kind = _KIND_MAP.get(str(payload.get("kind")), TransportFailureKind.PROTOCOL_ERROR)
            raise ControlledTransportError(kind, str(payload.get("detail", "")))
    detail = (result.stderr or f"exit={result.exit_code}").strip()[:200]
    detail = detail.replace("\n", " ")
    raise ControlledTransportError(TransportFailureKind.PROTOCOL_ERROR, detail)


def _pinned_url(target: ConnectionTarget, path: str) -> str:
    """Origin URL whose HOST is the pinned IP; the logical name never enters.

    The path/query ride verbatim so relative merges stay exact.
    """
    host = f"[{target.address}]" if target.address.version == 6 else str(target.address)
    suffix = path if path.startswith("/") else f"/{path}"
    port_part = "" if target.port == _DEFAULT_PORTS[target.scheme] else f":{target.port}"
    return f"{target.scheme}://{host}{port_part}{suffix}"


def _header(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers:
        if key.lower() == lowered:
            return value
    return None


def _strip_hop_headers(headers: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Hop-by-hop headers must not ride across redirects."""
    return tuple((k, v) for k, v in headers if k.lower() not in _HOP_BY_HOP_HEADERS)
