"""Engine-facing services: the ONLY auxiliary capabilities engines receive.

A future scanner engine executes as ``engine.execute(context, services)``
where ``context`` is a fully validated :class:`ScanNetworkContext` and
``services`` bundles narrowly scoped helpers:

* an HTTP client FACTORY (not a raw socket, resolver, or process handle) —
  the executor binds every client to THIS attempt's established sandbox and
  resolution service, so requests are structurally confined to the validated
  context (ADR-0005/0006);
* the origin request parameters (scheme/port/path) for this attempt;
* the attempt's cancellation flag and limits.

The executor constructs this object per scan attempt; engines never do.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.domain.scanning.http_contract import ALLOWED_HTTP_SCHEMES, DEFAULT_PORTS

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.domain.scanning.egress import ScanNetworkContext
    from src.domain.scanning.http_contract import HttpClient, HttpLimits, ScanCancellation


@dataclass(frozen=True)
class OriginSpec:
    """Origin request parameters for one scan attempt (validated shape)."""

    scheme: str = "https"
    port: int | None = None
    path: str = "/"

    def __post_init__(self) -> None:
        if self.scheme.lower() not in ALLOWED_HTTP_SCHEMES:
            raise ValueError(f"origin scheme {self.scheme!r} is not scannable")
        if not self.path.startswith("/"):
            raise ValueError("origin path must be origin-relative")
        effective = self.port or DEFAULT_PORTS[self.scheme.lower()]
        if not (1 <= effective <= 65535):
            raise ValueError("origin port out of range")


@dataclass(frozen=True)
class EngineServices:
    """Per-attempt capability bundle handed to an engine by the executor."""

    http_client_factory: Callable[[], HttpClient]
    cancellation: ScanCancellation
    limits: HttpLimits
    origin: OriginSpec
    _context: ScanNetworkContext

    @property
    def context(self) -> ScanNetworkContext:
        """The validated scan context the services are bound to."""
        return self._context
