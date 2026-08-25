"""Deterministic IP admission policy for scan-time destinations (ADR-0002).

Operates exclusively on already-parsed ``ipaddress`` objects — never raw
strings — so lexical evasions cannot re-enter here. The registration-time
lexical layer (domain.targets.target_normalization) and this policy are
separate controls: neither may be relied upon as a substitute for the other,
and neither replaces production NETWORK-level egress enforcement (SRS
Chapter 11 Section 6 layers 2-4; ADR-0001).
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# AWS/GCP/Azure instance-metadata endpoint. It sits inside link-local space
# (already rejected by range classification) but is listed explicitly so its
# denial reason is unambiguous in logs and tests.
CLOUD_METADATA_V4 = ipaddress.ip_address("169.254.169.254")


class IpRejectionReason(enum.StrEnum):
    """Why a candidate destination address was refused."""

    UNSPECIFIED = "unspecified"
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    METADATA = "cloud_metadata"
    NOT_GLOBAL = "not_globally_routable"


@dataclass(frozen=True)
class PolicyVerdict:
    """Outcome of evaluating one address against the scan-time IP policy."""

    allowed: bool
    address: IPAddress
    reason: IpRejectionReason | None = None


def evaluate_ip(address: IPAddress) -> PolicyVerdict:
    """Admit or refuse one candidate destination address.

    Deterministic and side-effect free. An address is admitted only when it
    is globally routable AND not classified into any prohibited special-use
    category. Every refusal carries exactly one machine-readable reason.
    """
    if address == CLOUD_METADATA_V4:
        return PolicyVerdict(False, address, IpRejectionReason.METADATA)
    # Most-specific classification first so refusal reasons are precise;
    # Python's ``is_private`` also covers several of the categories below
    # depending on interpreter version.
    checks: tuple[tuple[bool, IpRejectionReason], ...] = (
        (address.is_unspecified, IpRejectionReason.UNSPECIFIED),
        (address.is_loopback, IpRejectionReason.LOOPBACK),
        (address.is_link_local, IpRejectionReason.LINK_LOCAL),
        (address.is_multicast, IpRejectionReason.MULTICAST),
        (address.is_reserved, IpRejectionReason.RESERVED),
        # RFC1918, CGNAT 100.64/10, IPv4-mapped loopback/RFC1918
        # (::ffff:0:0/96), and IPv6 unique-local fc00::/7 land here.
        (address.is_private, IpRejectionReason.PRIVATE),
        # Belt-and-braces catch-all: anything not documented as globally
        # routable (e.g. documentation ranges, experimental allocations).
        (not address.is_global, IpRejectionReason.NOT_GLOBAL),
    )
    for refuses, reason in checks:
        if refuses:
            return PolicyVerdict(False, address, reason)
    return PolicyVerdict(True, address)


def evaluate_all(addresses: tuple[IPAddress, ...]) -> PolicyVerdict | None:
    """Evaluate every address; return the FIRST refusal verdict, else None.

    Scan-time policy is fail-closed over the whole record set: one prohibited
    A or AAAA record poisons the entire hostname (SRS Chapter 11 Section 6).
    """
    for address in addresses:
        verdict = evaluate_ip(address)
        if not verdict.allowed:
            return verdict
    return None
