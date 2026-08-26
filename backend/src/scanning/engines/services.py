"""Engine-facing services: the ONLY auxiliary capabilities engines receive.

A future scanner engine executes as ``engine.execute(context, services)``
where ``context`` is a fully validated :class:`ScanNetworkContext` and
``services`` bundles narrowly scoped helpers:

* an HTTP client FACTORY (not a raw socket, resolver, or process handle) —
  the executor binds every client to THIS attempt's established sandbox and
  resolution service, so requests are structurally confined to the validated
  context (ADR-0005/0006);
* the attempt's cancellation flag and limits.

The executor constructs this object per scan attempt; engines never do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.domain.scanning.egress import ScanNetworkContext
    from src.domain.scanning.http_contract import HttpClient, HttpLimits, ScanCancellation


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
