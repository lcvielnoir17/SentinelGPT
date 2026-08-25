"""Egress authorization tests (deny-by-default; binding-derived allow-list)."""

import ipaddress

import pytest

from src.domain.errors import EgressDeniedError
from src.domain.scanning.binding import ValidatedTargetBinding
from src.domain.scanning.egress import (
    ScanNetworkContext,
)

PUBLIC = ipaddress.ip_address("93.184.216.34")
OTHER_PUBLIC = ipaddress.ip_address("8.8.8.8")
PRIVATE = ipaddress.ip_address("192.168.0.10")
METADATA = ipaddress.ip_address("169.254.169.254")


def _binding(addresses: tuple) -> ValidatedTargetBinding:  # type: ignore[type-arg]
    return ValidatedTargetBinding.create(
        hostname="bound.example",
        addresses=addresses,
        validate=lambda _a: None,  # addresses pre-validated by policy tests
    )


def test_validated_target_ip_is_authorized() -> None:
    context = ScanNetworkContext.create(_binding((PUBLIC,)))
    assert context.egress.authorize(PUBLIC) is True


def test_unrelated_public_ip_is_denied() -> None:
    context = ScanNetworkContext.create(_binding((PUBLIC,)))
    assert context.egress.authorize(OTHER_PUBLIC) is False


def test_private_and_metadata_ips_are_denied() -> None:
    context = ScanNetworkContext.create(_binding((PUBLIC,)))
    for bad in (PRIVATE, METADATA):
        with pytest.raises(EgressDeniedError):
            context.authorize_destination(bad)


def test_require_destination_round_trip() -> None:
    binding = _binding((PUBLIC, OTHER_PUBLIC)).with_pinned(OTHER_PUBLIC)
    context = ScanNetworkContext.create(binding)
    assert context.require_destination() == OTHER_PUBLIC


def test_require_destination_fails_closed_without_pin() -> None:
    context = ScanNetworkContext.create(_binding((PUBLIC,)))
    with pytest.raises(EgressDeniedError):
        context.require_destination()


def test_allow_list_cannot_be_injected_after_creation() -> None:
    """Contexts are frozen: no path exists to widen the allow-list later."""
    context = ScanNetworkContext.create(_binding((PUBLIC,)))
    with pytest.raises(Exception):  # noqa: B017,B901 - frozen dataclass rejection
        context.egress.allowed_addresses.add(METADATA)  # type: ignore[attr-defined]


def test_redirect_destination_needs_its_own_context() -> None:
    """A new destination never inherits the previous binding's authorization."""
    original = ScanNetworkContext.create(_binding((PUBLIC,)))
    other_binding = _binding((OTHER_PUBLIC,))
    fresh = ScanNetworkContext.create(other_binding)
    # Original context must NOT authorize the redirect destination...
    assert original.egress.authorize(OTHER_PUBLIC) is False
    # ...only the freshly created one does.
    assert fresh.egress.authorize(OTHER_PUBLIC) is True
