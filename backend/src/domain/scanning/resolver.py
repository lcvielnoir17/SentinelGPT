"""Resolution contract for scan-time hostname resolution (ADR-0002).

The domain defines WHAT must be resolved (all A and AAAA records, fresh, at
scan time) without performing any I/O. Infrastructure supplies an
implementation of :class:`HostnameResolver`; security tests supply fakes.
Nothing in this package ever contacts DNS itself.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from src.domain.scanning.ip_policy import IPAddress


class ResolutionFailureKind(enum.StrEnum):
    """Coarse classification of resolver failures (never leaked to clients)."""

    NAME_NOT_FOUND = "name_not_found"
    NO_RECORDS = "no_records"
    TRANSIENT_ERROR = "transient_error"


@dataclass(frozen=True)
class ResolutionSuccess:
    """Every A/AAAA record the resolver currently observes for a hostname."""

    hostname: str
    addresses: tuple[IPAddress, ...]


@dataclass(frozen=True)
class ResolutionFailure:
    """The hostname could not be resolved; ``detail`` is for logs only."""

    hostname: str
    kind: ResolutionFailureKind
    detail: str = ""


ResolutionOutcome = ResolutionSuccess | ResolutionFailure


class HostnameResolver(Protocol):
    """Fresh, complete A+AAAA lookup boundary.

    Implementations MUST resolve at call time (no stale caches), MUST return
    every A and AAAA record (never a single "best" address), and MUST NOT be
    influenced by registration-time data or client input beyond the name.
    """

    def resolve_all(self, hostname: str) -> ResolutionOutcome:  # pragma: no cover
        """Resolve immediately and completely, or report a typed failure."""
        ...
