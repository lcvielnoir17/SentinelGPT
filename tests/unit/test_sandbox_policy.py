"""Unit tests for the sandbox egress policy (binding-derived allow-list)."""

from __future__ import annotations

import ipaddress

import pytest

from src.domain.errors import EgressDeniedError
from src.domain.scanning.binding import ValidatedTargetBinding
from src.scanning.sandbox.policy import SandboxEgressPolicy

PUBLIC = ipaddress.ip_address("93.184.216.34")
OTHER_PUBLIC = ipaddress.ip_address("8.8.8.8")
PUBLIC_V6 = ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946")
PRIVATE = ipaddress.ip_address("192.168.0.10")
METADATA = ipaddress.ip_address("169.254.169.254")


def _binding(*addresses: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ValidatedTargetBinding:
    return ValidatedTargetBinding.create(
        hostname="bound.example",
        addresses=addresses,
        validate=lambda _a: None,  # address admission itself is covered by IP-policy tests
    )


def test_allow_list_is_derived_exactly_from_the_binding() -> None:
    policy = SandboxEgressPolicy.for_binding(_binding(PUBLIC, PUBLIC_V6))
    assert policy.allowed_addresses == (PUBLIC, PUBLIC_V6)
    assert policy.hostname == "bound.example"


def test_direct_construction_is_refused() -> None:
    """No caller can hand the sandbox an arbitrary destination list."""
    with pytest.raises(TypeError, match="for_binding"):
        SandboxEgressPolicy(allowed_addresses=(METADATA,))  # type: ignore[call-arg]


def test_no_argument_construction_is_refused() -> None:
    with pytest.raises(TypeError, match="for_binding"):
        SandboxEgressPolicy()


def test_empty_binding_is_refused_fail_closed() -> None:
    empty = _binding()
    with pytest.raises(EgressDeniedError):
        SandboxEgressPolicy.for_binding(empty)


def test_policy_is_immutable_after_creation() -> None:
    policy = SandboxEgressPolicy.for_binding(_binding(PUBLIC))
    with pytest.raises(AttributeError):
        policy._addresses = (PRIVATE,)  # type: ignore[misc]
    with pytest.raises(AttributeError):
        delattr(policy, "_addresses")
    with pytest.raises(AttributeError):
        policy.hostname = "evil.example"  # type: ignore[misc]


def test_authorize_accepts_only_binding_addresses() -> None:
    policy = SandboxEgressPolicy.for_binding(_binding(PUBLIC))
    assert policy.authorize(PUBLIC) is True
    for intruder in (OTHER_PUBLIC, PRIVATE, METADATA):
        assert policy.authorize(intruder) is False
        with pytest.raises(EgressDeniedError):
            policy.require_authorized(intruder)


def test_v4_v6_partition_and_ipv6_rule_flag() -> None:
    v4_only = SandboxEgressPolicy.for_binding(_binding(PUBLIC))
    assert v4_only.allowed_v4 == (PUBLIC,)
    assert v4_only.allowed_v6 == ()
    assert v4_only.requires_ipv6_rules is False

    dual = SandboxEgressPolicy.for_binding(_binding(PUBLIC, PUBLIC_V6))
    assert dual.allowed_v6 == (PUBLIC_V6,)
    assert dual.requires_ipv6_rules is True


def test_repr_does_not_leak_more_than_addresses() -> None:
    policy = SandboxEgressPolicy.for_binding(_binding(PUBLIC))
    rendered = repr(policy)
    assert "93.184.216.34" in rendered
    assert "bound.example" in rendered
