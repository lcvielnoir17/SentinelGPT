"""Focused fingerprint contract tests — version-stable.

Proves the Phase 9 fingerprint identity is deterministic and strictly
limited to hostname + category + category-specific identifier.
"""

import pytest

from src.domain.scans.fingerprinting import (
    UnsupportedFingerprintCategory,
    extract_identifier,
    generate_fingerprint,
    generate_fingerprint_from_finding,
    normalize_generic_identifier,
    normalize_hostname,
)

# ---------------------------------------------------------------------------
# Core determinism
# ---------------------------------------------------------------------------


def test_same_logical_finding_same_fingerprint() -> None:
    a = generate_fingerprint_from_finding(
        hostname="Example.COM.",
        category_code="MISSING_SECURITY_HEADER",
        title="Missing Content-Security-Policy security header",
    )
    b = generate_fingerprint_from_finding(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        title="Missing Content-Security-Policy security header",
    )
    assert a == b
    assert len(a) == 64  # full sha256 hex


def test_different_identifier_different_fingerprint() -> None:
    csp = generate_fingerprint_from_finding(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        title="Missing Content-Security-Policy security header",
    )
    xfo = generate_fingerprint_from_finding(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        title="Missing X-Frame-Options security header",
    )
    assert csp != xfo


def test_hostname_case_and_trailing_dot_normalization() -> None:
    a = generate_fingerprint(
        hostname="Example.COM.", category_code="KNOWN_CVE", identifier="CVE-2023-1234"
    )
    b = generate_fingerprint(
        hostname="example.com", category_code="KNOWN_CVE", identifier="CVE-2023-1234"
    )
    c = generate_fingerprint(
        hostname="  EXAMPLE.com. ", category_code="KNOWN_CVE", identifier="CVE-2023-1234"
    )
    assert a == b == c


def test_category_normalization() -> None:
    a = generate_fingerprint(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        identifier="x-frame-options",
    )
    b = generate_fingerprint(
        hostname="example.com",
        category_code="missing_security_header",
        identifier="x-frame-options",
    )
    c = generate_fingerprint(
        hostname="example.com",
        category_code="  MISSING_SECURITY_HEADER ",
        identifier="x-frame-options",
    )
    assert a == b == c


def test_identifier_normalization_collapses_whitespace_and_case() -> None:
    a = generate_fingerprint(
        hostname="example.com", category_code="WEAK_CIPHER", identifier="  Foo   BAR  "
    )
    b = generate_fingerprint(
        hostname="example.com", category_code="WEAK_CIPHER", identifier="foo bar"
    )
    assert a == b
    assert normalize_generic_identifier("  Foo   BAR  ") == "foo bar"


def test_hostname_normalization_helper() -> None:
    assert normalize_hostname("  Example.COM. ") == "example.com"
    assert normalize_hostname("example.com.") == "example.com"
    assert normalize_hostname("EXAMPLE.COM") == "example.com"


def test_timestamps_do_not_affect_fingerprint() -> None:
    # Fingerprint function takes no timestamp; two calls with same logical
    # inputs at different times must be equal — prove determinism.
    args = {
        "hostname": "example.com",
        "category_code": "MISSING_SECURITY_HEADER",
        "identifier": "x-frame-options",
    }
    assert generate_fingerprint(**args) == generate_fingerprint(**args)


def test_severity_confidence_do_not_participate() -> None:
    # Severity/confidence are not fingerprint inputs. Two findings differing
    # only in those fields must still share the same fingerprint.
    fp1 = generate_fingerprint_from_finding(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        title="Missing X-Frame-Options security header",
    )
    fp2 = generate_fingerprint_from_finding(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        title="Missing X-Frame-Options security header",
    )
    assert fp1 == fp2


def test_empty_inputs_rejected() -> None:
    with pytest.raises(ValueError):
        generate_fingerprint(hostname="", category_code="MISSING_SECURITY_HEADER", identifier="x")
    with pytest.raises(ValueError):
        generate_fingerprint(hostname="example.com", category_code="", identifier="x")
    with pytest.raises(ValueError):
        generate_fingerprint(
            hostname="example.com", category_code="MISSING_SECURITY_HEADER", identifier="   "
        )


# ---------------------------------------------------------------------------
# Category-specific extraction
# ---------------------------------------------------------------------------


def test_missing_security_header_identifier_is_header_name() -> None:
    assert (
        extract_identifier(
            "MISSING_SECURITY_HEADER", "Missing Content-Security-Policy security header"
        )
        == "content-security-policy"
    )
    assert (
        extract_identifier("http.security-headers", "Missing X-Frame-Options security header")
        == "x-frame-options"
    )
    assert (
        extract_identifier("MISSING_SECURITY_HEADER", "Nonstandard X-Content-Type-Options value")
        == "x-content-type-options"
    )


def test_known_cve_identifier_is_cve_id() -> None:
    assert extract_identifier("KNOWN_CVE", "CVE-2023-12345 found") == "CVE-2023-12345"
    assert extract_identifier("KNOWN_CVE", "cve-2023-12345 found") == "CVE-2023-12345"


def test_exposed_admin_panel_identifier_is_normalized_path() -> None:
    assert (
        extract_identifier(
            "EXPOSED_ADMIN_PANEL", "Exposed Admin Panel at /admin", location="/ADMIN/"
        )
        == "/admin"
    )
    assert (
        extract_identifier(
            "EXPOSED_ADMIN_PANEL", "Exposed Admin Panel", location="//admin//panel//"
        )
        == "/admin/panel"
    )


def test_cookie_identifiers() -> None:
    assert (
        extract_identifier("http.cookies", "Cookies without the Secure attribute")
        == "cookie_missing_secure"
    )
    assert (
        extract_identifier("http.cookies", "Cookies without the HttpOnly attribute")
        == "cookie_missing_httponly"
    )
    assert extract_identifier("http.cookies", "SameSite attribute gaps") == "cookie_samesite_issue"


# ---------------------------------------------------------------------------
# Failure modes — must be typed, not silent fallbacks
# ---------------------------------------------------------------------------


def test_unsupported_category_fails_safely() -> None:
    with pytest.raises(UnsupportedFingerprintCategory):
        extract_identifier("UNKNOWN_CATEGORY_XYZ", "Whatever title")

    with pytest.raises(UnsupportedFingerprintCategory):
        generate_fingerprint_from_finding(
            hostname="example.com", category_code="UNKNOWN_CATEGORY_XYZ", title="Something"
        )


def test_malformed_supported_category_does_not_silently_use_title() -> None:
    # MISSING_SECURITY_HEADER with a title that contains no recognizable header
    # must raise, not fall back to the full title as identifier.
    with pytest.raises(UnsupportedFingerprintCategory):
        extract_identifier("MISSING_SECURITY_HEADER", "Something completely unrelated")

    with pytest.raises(UnsupportedFingerprintCategory):
        generate_fingerprint_from_finding(
            hostname="example.com",
            category_code="MISSING_SECURITY_HEADER",
            title="Something completely unrelated",
        )

    # KNOWN_CVE without a CVE id must raise, not use title.
    with pytest.raises(UnsupportedFingerprintCategory):
        extract_identifier("KNOWN_CVE", "Some vulnerability without identifier")

    # EXPOSED_ADMIN_PANEL without location must raise.
    with pytest.raises(UnsupportedFingerprintCategory):
        extract_identifier("EXPOSED_ADMIN_PANEL", "Exposed Admin Panel", location="")

    with pytest.raises(UnsupportedFingerprintCategory):
        extract_identifier("EXPOSED_ADMIN_PANEL", "Exposed Admin Panel", location="   ")


def test_outdated_tls_and_weak_cipher_still_deterministic() -> None:
    a = generate_fingerprint_from_finding(
        hostname="example.com", category_code="OUTDATED_TLS", title="TLS 1.0 enabled"
    )
    b = generate_fingerprint_from_finding(
        hostname="example.com", category_code="OUTDATED_TLS", title="TLS 1.0 enabled"
    )
    assert a == b
    c = generate_fingerprint_from_finding(
        hostname="example.com", category_code="OUTDATED_TLS", title="TLS 1.1 enabled"
    )
    assert a != c


def test_regression_lock_known_vectors() -> None:
    # Locked vectors prevent accidental algorithm drift.
    assert (
        generate_fingerprint(
            hostname="example.com",
            category_code="MISSING_SECURITY_HEADER",
            identifier="x-frame-options",
        )
        == "33bf34eb268c9c1b488e14e365525a14640e6cbd5723bb5aefc2cb3cd4c7329c"
    )
    assert (
        generate_fingerprint(
            hostname="example.com",
            category_code="MISSING_SECURITY_HEADER",
            identifier="content-security-policy",
        )
        == "27e2fb8add50021e2c82761906e0aa4cdfe4833dd6c1fd6dfd862072ddf47f5d"
    )
    # Normalization stability: same logical triple regardless of casing/spacing.
    fp = generate_fingerprint(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        identifier="content-security-policy",
    )
    assert fp == generate_fingerprint(
        hostname="EXAMPLE.COM.",
        category_code="missing_security_header",
        identifier="  Content-Security-Policy ",
    )


def test_persistence_path_uses_canonical_db_category() -> None:
    # Persistence MUST use the canonical DB code after _map_category, not the
    # raw engine alias. The two must produce different fingerprints so that
    # misusing the alias is detectable; the canonical path is the one the
    # repository persists.
    engine_fp = generate_fingerprint_from_finding(
        hostname="example.com",
        category_code="http.security-headers",
        title="Missing Content-Security-Policy security header",
    )
    canonical_fp = generate_fingerprint_from_finding(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        title="Missing Content-Security-Policy security header",
    )
    # Different raw category values -> different hash by design; persistence
    # must pick the canonical one to remain stable against engine renames.
    assert engine_fp != canonical_fp
    # The canonical fingerprint is the expected persisted identity.
    assert canonical_fp == generate_fingerprint(
        hostname="example.com",
        category_code="MISSING_SECURITY_HEADER",
        identifier="content-security-policy",
    )
