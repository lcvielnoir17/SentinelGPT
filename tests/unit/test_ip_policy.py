"""Unit tests for the scan-time IP admission policy (ADR-0002)."""

import ipaddress

import pytest

from src.domain.scanning.ip_policy import (
    CLOUD_METADATA_V4,
    IpRejectionReason,
    evaluate_all,
    evaluate_ip,
)


@pytest.mark.parametrize(
    ("address", "acceptable_reasons"),
    [
        # Exact reason where classification is stable across interpreters.
        ("127.0.0.1", {IpRejectionReason.LOOPBACK}),
        ("169.254.169.254", {IpRejectionReason.METADATA}),
        ("169.254.10.20", {IpRejectionReason.LINK_LOCAL}),
        ("0.0.0.0", {IpRejectionReason.UNSPECIFIED}),
        ("224.0.0.1", {IpRejectionReason.MULTICAST}),
        ("::1", {IpRejectionReason.LOOPBACK}),
        ("::", {IpRejectionReason.UNSPECIFIED}),
        ("fe80::1", {IpRejectionReason.LINK_LOCAL}),
        ("ff02::1", {IpRejectionReason.MULTICAST}),
        # Interpreter-version-sensitive categories (3.12 vs 3.13 differ on
        # which of private/reserved/not-global flags these): any refusal
        # reason is fine — the security property is the rejection itself.
        ("10.0.0.1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("172.16.0.1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("192.168.1.1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("100.64.0.1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("240.0.0.1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("255.255.255.255", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("fc00::1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("fd12:3456::1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("2001:db8::1", set(IpRejectionReason) - {IpRejectionReason.METADATA}),
        ("::ffff:127.0.0.1", {IpRejectionReason.LOOPBACK, IpRejectionReason.PRIVATE}),
        (
            "::ffff:10.0.0.1",
            set(IpRejectionReason) - {IpRejectionReason.METADATA},
        ),
        (
            "::ffff:192.168.0.1",
            set(IpRejectionReason) - {IpRejectionReason.METADATA},
        ),
    ],
)
def test_prohibited_addresses_are_rejected_with_reason(
    address: str, acceptable_reasons: set[IpRejectionReason]
) -> None:
    verdict = evaluate_ip(ipaddress.ip_address(address))
    assert not verdict.allowed
    assert verdict.reason in acceptable_reasons


@pytest.mark.parametrize(
    "address",
    [
        "93.184.216.34",
        "8.8.8.8",
        "2606:2800:220:1:248:1893:25c8:1946",  # public IPv6
    ],
)
def test_public_addresses_are_admitted(address: str) -> None:
    verdict = evaluate_ip(ipaddress.ip_address(address))
    assert verdict.allowed
    assert verdict.reason is None


def test_metadata_constant_is_explicitly_classified() -> None:
    assert ipaddress.ip_address("169.254.169.254") == CLOUD_METADATA_V4
    assert evaluate_ip(CLOUD_METADATA_V4).reason is IpRejectionReason.METADATA


def test_evaluate_all_returns_first_refusal_across_record_sets() -> None:
    public = ipaddress.ip_address("93.184.216.34")
    private = ipaddress.ip_address("10.0.0.9")
    mixed_v4 = (public, private)
    verdict = evaluate_all(mixed_v4)
    assert verdict is not None and verdict.reason is IpRejectionReason.PRIVATE
    mixed_aaaa = (
        ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"),
        ipaddress.ip_address("fd00::5"),  # one bad AAAA poisons the set
    )
    verdict6 = evaluate_all(mixed_aaaa)
    assert verdict6 is not None and verdict6.reason is IpRejectionReason.PRIVATE


def test_evaluate_all_clean_set_yields_none() -> None:
    clean = (
        ipaddress.ip_address("93.184.216.34"),
        ipaddress.ip_address("8.8.8.8"),
        ipaddress.ip_address("2606:2800:220:1:248:1893:25c8:1946"),
    )
    assert evaluate_all(clean) is None
