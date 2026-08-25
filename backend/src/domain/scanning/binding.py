"""Validated target bindings: the only destination handle engines may hold.

A binding is produced exclusively through :meth:`ValidatedTargetBinding.create`,
which runs EVERY resolved address through the scan-time IP policy and refuses
construction if any single record is prohibited. Bindings are immutable and
carry the validated address set plus optional pinned destination — a future
scanner engine receives a binding / scan network context, never a bare
hostname it could re-resolve behind the security layer (DNS-rebinding
defense, ADR-0002).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from src.domain.errors import EgressDeniedError, TargetResolutionBlockedError
from src.domain.scanning.ip_policy import IPAddress

if TYPE_CHECKING:
    import uuid
    from collections.abc import Callable, Sequence

    from src.domain.scanning.ip_policy import IPAddress


@dataclass(frozen=True)
class ValidatedTargetBinding:
    """Immutable, policy-approved destination identity for one scan attempt."""

    hostname: str
    addresses: tuple[IPAddress, ...]
    validated_at: datetime
    target_id: uuid.UUID | None = None
    pinned_address: IPAddress | None = field(default=None)

    @classmethod
    def create(
        cls,
        *,
        hostname: str,
        addresses: Sequence[IPAddress],
        validate: Callable[[tuple[IPAddress, ...]], object],
        now: datetime | None = None,
        target_id: uuid.UUID | None = None,
    ) -> ValidatedTargetBinding:
        """Construct a binding after validating EVERY resolved address.

        ``validate`` is the IP-policy entry point (:func:`evaluate_all`); it
        raises TargetResolutionBlockedError when any record is prohibited.
        Construction without validation is not offered by the service layer.
        """
        address_tuple = tuple(addresses)
        outcome = validate(address_tuple)
        if outcome is not None:
            raise TargetResolutionBlockedError()
        return cls(
            hostname=hostname,
            addresses=address_tuple,
            validated_at=now or datetime.now(UTC),
            target_id=target_id,
        )

    def with_pinned(self, address: IPAddress) -> ValidatedTargetBinding:
        """Pin the destination to one of the validated addresses.

        Engines connect to the pinned address only; selecting anything outside
        the validated set is refused (egress-denied class), which keeps
        validation and connection from drifting apart.
        """
        if address not in self.addresses:
            raise EgressDeniedError()
        return ValidatedTargetBinding(
            hostname=self.hostname,
            addresses=self.addresses,
            validated_at=self.validated_at,
            target_id=self.target_id,
            pinned_address=address,
        )
