"""Resolution + binding tests with injected fake resolvers (no real DNS)."""

import uuid
from datetime import UTC, datetime

import pytest

from src.domain.errors import (
    DnsRebindingDetectedError,
    TargetResolutionBlockedError,
    TargetUnresolvedError,
)
from src.domain.scanning.resolution import ScanTargetResolutionService
from src.domain.scanning.resolver import (
    ResolutionFailure,
    ResolutionFailureKind,
    ResolutionSuccess,
)

NOW = datetime.now(UTC)
PUBLIC_A = "93.184.216.34"
PUBLIC_B = "8.8.8.8"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


class FakeResolver:
    """Scripted resolver: maps hostname -> outcome or raising exception."""

    def __init__(self, script=None, **kwargs):  # type: ignore[no-untyped-def]
        merged = dict(script or {})
        merged.update(kwargs)
        self._script: dict = merged
        self.calls: list[str] = []

    def resolve_all(self, hostname: str):  # type: ignore[no-untyped-def]
        self.calls.append(hostname)
        entry = self._script.get(hostname)
        if isinstance(entry, Exception):
            raise entry
        if isinstance(entry, (ResolutionFailure, ResolutionSuccess)):
            if isinstance(entry, ResolutionSuccess):
                # The answer always belongs to the name that was asked.
                return ResolutionSuccess(hostname=hostname, addresses=entry.addresses)
            return entry
        if entry is None:
            return ResolutionFailure(hostname, ResolutionFailureKind.NAME_NOT_FOUND)
        return ResolutionSuccess(hostname=hostname, addresses=entry)

    @staticmethod
    def records(*addresses: str) -> ResolutionSuccess:
        import ipaddress

        return ResolutionSuccess(
            hostname="", addresses=tuple(ipaddress.ip_address(a) for a in addresses)
        )


def _service(resolver: FakeResolver) -> ScanTargetResolutionService:
    return ScanTargetResolutionService(resolver)


def test_single_public_a_record_is_accepted() -> None:
    resolver = FakeResolver({"public.example": FakeResolver.records(PUBLIC_A)})
    binding = _service(resolver).resolve("public.example")
    assert [str(a) for a in binding.addresses] == [PUBLIC_A]
    assert binding.validated_at.tzinfo is not None
    assert binding.target_id is None


def test_multiple_public_a_records_all_validated() -> None:
    resolver = FakeResolver({"multi.example": FakeResolver.records(PUBLIC_A, PUBLIC_B)})
    binding = _service(resolver).resolve("multi.example")
    assert len(binding.addresses) == 2  # never silently first-only


def test_mixed_public_and_private_a_records_rejected() -> None:
    resolver = FakeResolver({"mixed.example": FakeResolver.records(PUBLIC_A, "10.0.0.9")})
    with pytest.raises(TargetResolutionBlockedError):
        _service(resolver).resolve("mixed.example")


def test_private_aaaa_record_rejects_public_a_set() -> None:
    resolver = FakeResolver({"v6bad.example": FakeResolver.records(PUBLIC_A, "fd00::9")})
    with pytest.raises(TargetResolutionBlockedError):
        _service(resolver).resolve("v6bad.example")


def test_multiple_aaaa_records_validated() -> None:
    resolver = FakeResolver({"v6.example": FakeResolver.records(PUBLIC_V6, "2620:fe::fe")})
    binding = _service(resolver).resolve("v6.example")
    assert len(binding.addresses) == 2


def test_no_records_is_resolution_failure_not_policy_block() -> None:
    resolver = FakeResolver(
        {"empty.example": ResolutionFailure("empty.example", ResolutionFailureKind.NO_RECORDS)}
    )
    with pytest.raises(TargetUnresolvedError):
        _service(resolver).resolve("empty.example")


def test_resolver_exception_becomes_controlled_domain_error() -> None:
    resolver = FakeResolver({"boom.example": RuntimeError("resolver exploded")})
    with pytest.raises(TargetUnresolvedError):
        _service(resolver).resolve("boom.example")


def test_binding_pin_rejects_unvalidated_address() -> None:
    import ipaddress

    resolver = FakeResolver({"pin.example": FakeResolver.records(PUBLIC_A, PUBLIC_B)})
    service = _service(resolver)
    binding = service.resolve("pin.example")
    pinned = binding.with_pinned(binding.addresses[0])
    assert pinned.pinned_address == binding.addresses[0]
    with pytest.raises(Exception):  # noqa: B017 - EgressDeniedError family
        binding.with_pinned(ipaddress.ip_address("203.0.113.99"))


# ---------------------------------------------------------------------------
# DNS rebinding simulation: validation vs connection-time resolution drift.
# ---------------------------------------------------------------------------


def test_rebinding_public_to_private_is_detected() -> None:
    resolver = FakeResolver(
        {
            "shifty.example": FakeResolver.records(PUBLIC_A),
        }
    )
    service = _service(resolver)
    binding = service.resolve("shifty.example")
    attacker_round = FakeResolver.records("192.168.0.10")
    resolver._script["shifty.example"] = attacker_round
    with pytest.raises(DnsRebindingDetectedError):
        service.ensure_still_valid(binding)


def test_rebinding_check_passes_when_stable() -> None:
    resolver = FakeResolver({"stable.example": FakeResolver.records(PUBLIC_A, PUBLIC_B)})
    service = _service(resolver)
    binding = service.resolve("stable.example")
    service.ensure_still_valid(binding)  # no exception
    assert resolver.calls == ["stable.example", "stable.example"]


def test_rebinding_to_metadata_address_is_detected() -> None:
    resolver = FakeResolver({"meta.example": FakeResolver.records(PUBLIC_A)})
    service = _service(resolver)
    binding = service.resolve("meta.example")
    resolver._script["meta.example"] = FakeResolver.records("169.254.169.254")
    with pytest.raises(DnsRebindingDetectedError):
        service.ensure_still_valid(binding)


def test_target_id_flows_into_binding() -> None:
    resolver = FakeResolver({"t.example": FakeResolver.records(PUBLIC_A)})
    target_id = uuid.uuid4()
    binding = _service(resolver).resolve("t.example", target_id=target_id, now=NOW)
    assert binding.target_id == target_id
    assert binding.validated_at == NOW
