"""Shared target URL/hostname validation & normalization.

Single SSRF-prevention gate required by SRS Chapter 2 Section 13, Chapter 3
Section 18 ("all user-supplied target values pass through a single, shared
validation/normalization function") and Chapter 5 Section 4 (creation-time
rejection of private IP ranges, localhost, and cloud metadata addresses with
422 UNPROCESSABLE_TARGET).

Scope note (SSRF layering, SRS Chapter 11 Section 6): these checks are purely
lexical — canonical hostname forms, IP-literal range classification, numeric-
encoding rejection, and a metadata-name blocklist. DNS is deliberately NOT
resolved here: registration-time resolution without scan-time re-resolution
would be a TOCTOU/DNS-rebinding false comfort (see docs/adr/0001-ssrf-validation-layering.md).
Resolution-time blocking (403 TARGET_RESOLUTION_BLOCKED) via scan-time
re-resolution plus sandbox egress enforcement is a MANDATORY BLOCKER before
any scanner executes; this module is the deterministic layer that must agree
with it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from src.domain.errors import InvalidTargetError

MAX_HOSTNAME_LENGTH = 255
MAX_NORMALIZED_URL_LENGTH = 500

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Known cloud-metadata DNS names (SRS Chapter 11 Section 6: the metadata
# address "169.254.169.254 and equivalents"). The link-local IP itself is
# covered by ``ipaddress`` classification below.
METADATA_NAME_BLOCKLIST = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
    }
)

# Private/internal naming spaces that can never be legitimate public scan
# targets, blocked lexically because they resolve only inside private networks:
#   .internal     — ICANN-reserved private-use TLD (also covers AWS VPC names)
#   .local        — RFC 6762 mDNS
#   .localhost    — RFC 6761 special-use, guaranteed loopback
#   .localdomain  — glibc/libvirt/Vagrant default private search domain;
#                   "localhost.localdomain" is a standard loopback alias
#   .home.arpa    — RFC 8375 home-network reserved domain
#   .lan          — ubiquitous SOHO-router private convention (no public DNS)
# This list is deliberately small and principled; it is NOT exhaustive by
# design — ADR-0001 keeps scan-time re-resolution as the authoritative control.
PRIVATE_NAME_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".localdomain",
    ".home.arpa",
    ".lan",
)

# Numeric-IP classification is ASCII-only by construction: Python's Unicode-
# aware ``str.isdigit()``/``int()`` accept characters such as Arabic-Indic
# "٠١٢..." and fullwidth "０１２...", which IDNA resolution maps back to the
# corresponding ASCII digits — a bypass class, never a legitimate hostname.
_ASCII_DIGITS = frozenset("0123456789")


def _is_ascii_digits(text: str) -> bool:
    """True when non-empty and every character is an ASCII 0-9 digit."""
    return bool(text) and all(c in _ASCII_DIGITS for c in text)


@dataclass(frozen=True)
class NormalizedTarget:
    """Canonicalized, validated target identity ready for persistence."""

    hostname: str
    normalized_url: str


def _reject(message: str) -> None:
    raise InvalidTargetError(message)


def _as_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return an IP object for IPv4/v6 literals (incl. integer-encoded v4)."""
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    # Decimal/hex integer forms (e.g. "2130706433", "0x7f000001") resolve to
    # 127.0.0.1 in many HTTP clients — classify them as the IPs they denote.
    # ASCII-only: unicode-digit strings are rejected earlier as hostnames.
    try:
        if _is_ascii_digits(candidate):
            return ipaddress.ip_address(int(candidate))
        if candidate.lower().startswith("0x") and len(candidate) > 2:
            return ipaddress.ip_address(int(candidate, 16))
    except (ValueError, OverflowError):
        return None
    return None


def _is_disallowed_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for private/loopback/link-local/reserved/multicast/unspecified."""
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_reserved,
            ip.is_multicast,
            ip.is_unspecified,
        )
    )


def _strip_trailing_dot(host: str) -> str:
    """Canonicalize FQDN form: "example.com." == "example.com".

    Trailing dots are legal DNS syntax but change string identity; without
    this, "localhost." bypasses the localhost check and equivalent names
    register as distinct targets.
    """
    return host.rstrip(".")


def _looks_like_numeric_host(host: str) -> bool:
    """True when every dot-label is pure-decimal or 0x-hex (inet_aton-ish).

    Numeric means ASCII 0-9 (or ASCII 0x-hex) exclusively — Unicode digit
    characters must never enter IPv4 classification. Ordinary public hostnames
    never consist solely of numeric/hex labels, so this cannot misclassify
    legitimate DNS names like "0x7f.example.com" ("example" is not a
    numeric/hex label).
    """
    labels = host.split(".")
    for label in labels:
        if _is_ascii_digits(label):
            continue
        if (
            len(label) > 2
            and label[:2] in ("0x", "0X")
            and all(c in "0123456789abcdefABCDEF" for c in label[2:])
        ):
            continue
        return False
    return True


def _is_canonical_dotted_quad(host: str) -> bool:
    """True only for strict dotted-decimal: 4 labels, 0-255, no leading zeros."""
    labels = host.split(".")
    if len(labels) != 4:
        return False
    for label in labels:
        if not _is_ascii_digits(label):
            return False
        # Leading zeros invoke octal interpretation in inet_aton parsers.
        if len(label) > 1 and label[0] == "0":
            return False
        if int(label) > 255:
            return False
    return True


def _contains_non_ascii_numeric(host: str) -> bool:
    """True when the host contains a non-ASCII character with numeric value.

    Structural guard for the IDNA bypass class: characters such as Arabic-
    Indic "٠١٢" or fullwidth "０１２" digits carry numeric values and are
    mapped back to ASCII digits by common IDNA resolution, so a host built
    from them can resolve to loopback/private space even though it never
    looks like an IP literal to ASCII-only parsing. Legitimate alphabetic
    internationalized names (e.g. "münchen.de") contain no such characters
    and remain accepted.
    """
    return any(ch.isdigit() and ord(ch) > 127 for ch in host)


def _validate_host(host: str) -> str:
    host = _strip_trailing_dot(host)
    if not host:
        _reject("URL has no hostname.")
    if _contains_non_ascii_numeric(host):
        _reject("Non-ASCII numeric characters are not allowed in hostnames.")
    if host == "localhost" or host.endswith(".localhost"):
        _reject("localhost targets are not allowed.")
    if host in METADATA_NAME_BLOCKLIST or any(
        host.endswith(suffix) for suffix in PRIVATE_NAME_SUFFIXES
    ):
        _reject("Private/internal network names are not allowed as targets.")
    # Non-canonical numeric forms ("127.1", "0x7f.0.0.1", "0177.0.0.1",
    # integer-encoded IPs) are interpreted inconsistently across resolvers;
    # reject them outright instead of trying to guess their decoded value.
    if _looks_like_numeric_host(host) and not _is_canonical_dotted_quad(host):
        _reject(
            "Non-canonical numeric hostname forms are not allowed; use a "
            "standard DNS name or dotted-decimal IPv4 literal."
        )
    ip = _as_ip_literal(host)
    if ip is not None and _is_disallowed_ip(ip):
        _reject(
            "Targets resolving inside private, loopback, link-local, or reserved ranges are not allowed."
        )
    return host


def normalize_target(hostname: str, url: str) -> NormalizedTarget:
    """Validate and canonicalize a user-supplied target.

    Returns the lowercase hostname and the canonical URL (lowercased scheme/
    host, no userinfo, no fragment). Raises InvalidTargetError on any rule
    violation so callers can map it to 422 UNPROCESSABLE_TARGET.
    """
    hostname = hostname.strip()
    url = url.strip()
    if not hostname or len(hostname) > MAX_HOSTNAME_LENGTH:
        _reject("hostname must be between 1 and 255 characters.")
    if not url:
        _reject("url must not be empty.")

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise InvalidTargetError("URL could not be parsed.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        _reject("Only http and https URLs are allowed.")
    if parts.username is not None or parts.password is not None:
        _reject("Credentials embedded in the URL are not allowed.")

    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetError("URL contains an invalid port.") from exc

    host = parts.hostname or ""
    host = _validate_host(host)  # also canonicalizes away the FQDN trailing dot
    if len(host) > MAX_HOSTNAME_LENGTH:
        _reject("Resolved hostname exceeds 255 characters.")

    # The supplied hostname must identify the same host as the URL (both
    # compared in canonical trailing-dot-stripped, lowercase form).
    if host != _strip_trailing_dot(hostname.strip().lower().strip("[]")):
        _reject("hostname does not match the URL host.")

    display_host = f"[{host}]" if ":" in host else host
    netloc = f"{display_host}:{port}" if port is not None else display_host
    normalized_url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    if len(normalized_url) > MAX_NORMALIZED_URL_LENGTH:
        _reject("Normalized URL exceeds 500 characters.")

    return NormalizedTarget(hostname=host, normalized_url=normalized_url)
