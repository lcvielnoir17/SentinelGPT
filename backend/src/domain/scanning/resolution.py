"""Scan-time target resolution service: resolve fresh, validate everything.

Orchestrates the resolver contract and the IP policy into a validated
binding (ADR-0002):

    hostname -> resolve_all -> policy over EVERY A/AAAA record -> binding

Resolution failure and policy refusal are distinct outcomes with distinct
domain errors; client-facing messages stay generic so DNS/internal details
never leak. This component never caches, never trusts stored IPs, and never
accepts caller-supplied addresses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.domain.errors import (
    DnsRebindingDetectedError,
    TargetResolutionBlockedError,
    TargetUnresolvedError,
)
from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.ip_policy import evaluate_all
from src.domain.scanning.resolver import ResolutionSuccess

if TYPE_CHECKING:
    import uuid
    from datetime import datetime

    from src.domain.scanning.resolver import HostnameResolver


class ScanTargetResolutionService:
    """Fresh-resolution + full-record-set validation for one scan attempt."""

    def __init__(self, resolver: HostnameResolver) -> None:
        self._resolver = resolver

    def resolve(
        self,
        hostname: str,
        *,
        target_id: uuid.UUID | None = None,
        now: datetime | None = None,
    ) -> ValidatedTargetBinding:
        """Resolve the hostname now and return a fully-validated binding."""
        outcome = self._resolve_quietly(hostname)
        if not isinstance(outcome, ResolutionSuccess):
            # Resolution failure is not a policy decision; keep it distinct.
            raise TargetUnresolvedError()
        verdict = evaluate_all(outcome.addresses)
        if verdict is not None:
            raise TargetResolutionBlockedError()
        return ValidatedTargetBinding.create(
            hostname=outcome.hostname,
            addresses=outcome.addresses,
            validate=_policy_validate,
            now=now,
            target_id=target_id,
        )

    def ensure_still_valid(self, binding: ValidatedTargetBinding) -> None:
        """Re-resolve and compare against the binding (anti-rebinding check).

        The connection-time address set must equal the validated set. Any
        drift — including a public->private change on any single record — is
        treated as rebinding and refused. Authoritative network-level
        enforcement remains the egress boundary (ADR-0001/0002).
        """
        outcome = self._resolve_quietly(binding.hostname)
        if not isinstance(outcome, ResolutionSuccess):
            raise TargetUnresolvedError()
        if frozenset(outcome.addresses) != frozenset(binding.addresses):
            raise DnsRebindingDetectedError()
        if evaluate_all(outcome.addresses) is not None:
            raise DnsRebindingDetectedError()

    def _resolve_quietly(self, hostname: str):  # type: ignore[no-untyped-def]
        """Invoke the resolver, converting arbitrary failures to the typed
        outcome/error so infrastructure exceptions never escape raw."""
        try:
            return self._resolver.resolve_all(hostname)
        except Exception as exc:  # noqa: BLE001 - boundary conversion
            raise TargetUnresolvedError() from exc


def _policy_validate(addresses: tuple) -> None:  # type: ignore[type-arg]
    """Policy adapter matching the binding factory's validate contract."""
    if evaluate_all(addresses) is not None:
        raise TargetResolutionBlockedError()
