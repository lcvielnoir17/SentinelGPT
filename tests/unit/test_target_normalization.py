"""Unit tests for the shared target normalization/SSRF-prevention function.

Negative-path coverage is mandatory per SRS Chapter 3, Section 18's
non-negotiable test gate (SSRF-attempt targets must be rejected).
"""

import pytest

from src.domain.errors import InvalidTargetError
from src.domain.targets.target_normalization import normalize_target


def test_normalizes_host_case_and_default_path() -> None:
    result = normalize_target("Example.COM", "https://Example.COM")
    assert result.hostname == "example.com"
    assert result.normalized_url == "https://example.com/"


def test_preserves_path_query_and_port_drops_fragment() -> None:
    result = normalize_target("example.com", "HTTP://Example.COM:8080/app?q=1#frag")
    assert result.normalized_url == "http://example.com:8080/app?q=1"


@pytest.mark.parametrize(
    ("hostname", "url"),
    [
        # Non-http(s) schemes.
        ("example.com", "ftp://example.com"),
        ("example.com", "file:///etc/passwd"),
        ("example.com", "javascript:alert(1)"),
        # Missing hostname.
        ("", "https:///path"),
        # Localhost forms.
        ("localhost", "http://localhost/"),
        ("sub.localhost", "http://sub.localhost/"),
        # Trailing-dot FQDN bypasses (audit finding M-1).
        ("localhost.", "http://localhost./"),
        ("127.0.0.1.", "http://127.0.0.1./"),
        ("sub.localhost.", "http://sub.localhost./"),
        # Non-canonical IPv4 representations (inet_aton-style evasions).
        ("127.1", "http://127.1/"),
        ("0x7f.0.0.1", "http://0x7f.0.0.1/"),
        ("0177.0.0.1", "http://0177.0.0.1/"),
        ("1.2.3.04", "http://1.2.3.04/"),
        ("256.100.50.1", "http://256.100.50.1/"),
        ("2130706433", "http://2130706433/"),  # integer-encoded loopback
        ("0xbeef", "http://0xbeef/"),
        # F-1: Unicode-digit IPv4 forms (audit bypass class). Python's
        # isdigit()/int() accept these; IDNA resolution maps them back to
        # ASCII digits, so they can denote 127.0.0.1.
        ("١٢٧.٠.٠.١", "http://١٢٧.٠.٠.١/"),
        ("１２７.０.０.１", "http://１２７.０.０.１/"),
        ("１２７．０．０．１", "http://１２７．０．０．１/"),
        ("¹²⁷.⁰.⁰.¹", "http://¹²⁷.⁰.⁰.¹/"),
        # Private / loopback / link-local / metadata IP literals (RFC1918+).
        ("127.0.0.1", "http://127.0.0.1/"),
        ("10.0.0.5", "http://10.0.0.5/"),
        ("172.16.0.9", "http://172.16.0.9/"),
        ("192.168.1.1", "http://192.168.1.1/"),
        ("169.254.169.254", "http://169.254.169.254/latest/meta-data/"),
        ("[::1]", "http://[::1]/"),
        # Integer/hex-encoded loopback evasions.
        ("2130706433", "http://2130706433/"),
        ("0x7f000001", "http://0x7f000001/"),
        # Embedded credentials.
        ("example.com", "https://user:pass@example.com/"),
        # Hostname/URL mismatch.
        ("other.com", "https://example.com/"),
        # Invalid port.
        ("example.com", "https://example.com:notaport/"),
        # Oversized values.
        ("h" * 256, f"https://{'h' * 256}/"),
        ("example.com", "https://example.com/" + "p" * 600),
    ],
)
def test_rejects_invalid_or_ssrf_targets(hostname: str, url: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_target(hostname, url)


@pytest.mark.parametrize(
    ("hostname", "url"),
    [
        # Known cloud-metadata DNS names (SRS Ch11 §6 "and equivalents").
        ("metadata.google.internal", "http://metadata.google.internal/"),
        ("metadata.google.internal.", "http://metadata.google.internal./"),
        ("metadata.goog", "https://metadata.goog/computeMetadata/v1/"),
        # RFC 6762 / ICANN private-use name spaces resolve only internally.
        ("api.internal", "https://api.internal/health"),
        ("nas.local", "http://nas.local/"),
        ("host.internal.", "http://host.internal./"),
        # F-2: loopback aliases and remaining common private naming spaces.
        ("localhost.localdomain", "http://localhost.localdomain/"),
        ("localhost.localdomain.", "http://localhost.localdomain./"),
        ("foo.localdomain", "http://foo.localdomain/"),
        ("foo.home.arpa", "http://foo.home.arpa/"),
        ("nas.lan", "http://nas.lan/"),
    ],
)
def test_rejects_metadata_and_private_names(hostname: str, url: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_target(hostname, url)


@pytest.mark.parametrize(
    ("hostname", "url"),
    [
        ("93.184.216.34", "http://93.184.216.34/"),
        ("8.8.8.8", "https://8.8.8.8/dns-query"),
        ("2606:2800:220:1:248:1893:25c8:1946", "http://[2606:2800:220:1:248:1893:25c8:1946]/"),
    ],
)
def test_allows_public_ip_literals(hostname: str, url: str) -> None:
    result = normalize_target(hostname, url)
    assert result.hostname == hostname.lower()


@pytest.mark.parametrize(
    ("hostname", "url"),
    [
        # Ordinary DNS names that merely LOOK numeric-adjacent must survive.
        ("0x7f.example.com", "https://0x7f.example.com/"),
        ("cafe.example.com", "https://cafe.example.com/"),
        ("sub-domain.example.co.uk", "https://sub-domain.example.co.uk/a?b=1"),
        ("xn--80ak6aa92e.com", "https://xn--80ak6aa92e.com/"),
    ],
)
def test_does_not_reject_legitimate_public_hostnames(hostname: str, url: str) -> None:
    result = normalize_target(hostname, url)
    assert result.hostname == hostname.lower()


def test_alphabetic_internationalized_names_remain_accepted() -> None:
    """F-1 scope check: only non-ASCII *numeric* characters are rejected.

    Legitimate alphabetic IDN hostnames carry no numeric Unicode characters
    and stay registrable; the invariant targets the IDNA-digit bypass class.
    """
    result = normalize_target("münchen.de", "https://münchen.de/seite")
    assert result.hostname == "münchen.de"
    assert result.normalized_url == "https://münchen.de/seite"


def test_ipv6_normalized_url_keeps_brackets() -> None:
    host = "2606:2800:220:1:248:1893:25c8:1946"
    result = normalize_target(host, f"http://[{host}]:8000/x")
    assert result.normalized_url == f"http://[{host}]:8000/x"


def test_trailing_dot_is_canonicalized_not_bypassed() -> None:
    """FQDN trailing dot must not create a second identity for one host."""
    plain = normalize_target("example.com", "https://example.com")
    dotted = normalize_target("example.com.", "https://example.com./path")
    assert dotted.hostname == plain.hostname == "example.com"
    assert dotted.normalized_url == "https://example.com/path"
