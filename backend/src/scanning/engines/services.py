"""Engine-facing services: the ONLY auxiliary capabilities engines receive.

A future scanner engine executes as ``engine.execute(context, services)``
where ``context`` is a fully validated :class:`ScanNetworkContext` and
``services`` bundles narrowly scoped helpers:

* an HTTP client FACTORY (not a raw socket, resolver, or process handle) —
  every request envelope it produces is born from the SAME validated
  context, so the engine structurally cannot aim traffic elsewhere;
* the attempt's cancellation flag and limits.

The executor constructs this object per scan attempt; engines never do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.domain.scanning.http_contract import (
    ControlledTransportError,
    HttpClient,
    HttpLimits,
    ScanCancellation,
    TransportFailureKind,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.domain.scanning.egress import ScanNetworkContext


def _no_transport_yet() -> HttpClient:
    """Placeholder until the Phase 4 sandbox-aware transport lands."""
    raise ControlledTransportError(
        TransportFailureKind.PROTOCOL_ERROR,
        "HTTP transport is not available until Phase 4; execution stays blocked",
    )


def default_engine_services(context: ScanNetworkContext) -> EngineServices:
    """Build the standard per-attempt services for one validated context."""
    return EngineServices(
        http_client_factory=_no_transport_yet,
        cancellation=ScanCancellation.create(),
        limits=HttpLimits(),
        _context=context,
    )


@dataclass(frozen=True)
class EngineServices:
    """Per-attempt capability bundle handed to an engine by the executor."""

    http_client_factory: Callable[[], HttpClient]
    cancellation: ScanCancellation
    limits: HttpLimits
    _context: ScanNetworkContext

    @property
    def context(self) -> ScanNetworkContext:
        """The validated scan context the services are bound to."""
        return self._context
