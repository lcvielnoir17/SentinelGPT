"""Egress authorization for scan attempts (ADR-0002).

Application-layer policy ONLY: this module decides which destination
addresses a validated binding may use. It is explicitly NOT a network
sandbox — production enforcement must be applied at the network boundary
(network namespace / container policy / nftables deny-by-default egress),
per SRS Chapter 11 Section 6 layers 3 and ADR-0002's control-status table.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from src.domain.errors import EgressDeniedError

if TYPE_CHECKING:
    from src.domain.scanning.binding import ValidatedTargetBinding
    from src.domain.scanning.ip_policy import IPAddress


class EgressPolicy(Protocol):
    """Deny-by-default authorization boundary for destination addresses."""

    def authorize(self, address: IPAddress) -> bool:  # pragma: no cover
        ...


@dataclass(frozen=True)
class DefaultDenyEgressPolicy:
    """Permits exactly the addresses of one validated binding — nothing else."""

    allowed_addresses: frozenset[IPAddress] = field(default_factory=frozenset)

    def authorize(self, address: IPAddress) -> bool:
        return address in self.allowed_addresses


@dataclass(frozen=True)
class ScanNetworkContext:
    """Everything a future engine may know/use about where it may connect.

    Constructed only from an already-validated binding; the egress allow-list
    is derived from that binding's addresses, so callers cannot inject
    arbitrary destinations. Engines must call :meth:`require_destination`
    rather than handling raw hostnames.
    """

    binding: ValidatedTargetBinding
    egress: EgressPolicy

    @classmethod
    def create(cls, binding: ValidatedTargetBinding) -> ScanNetworkContext:
        return cls(
            binding=binding,
            egress=DefaultDenyEgressPolicy(frozenset(binding.addresses)),
        )

    def authorize_destination(self, address: IPAddress) -> None:
        """Refuse any destination outside the validated binding's addresses."""
        if not self.egress.authorize(address):
            raise EgressDeniedError()

    def require_destination(self) -> IPAddress:
        """The pinned destination, or fail closed if none was pinned."""
        pinned = self.binding.pinned_address
        if pinned is None:
            raise EgressDeniedError()
        self.authorize_destination(pinned)
        return pinned
