"""Deterministic cross-scan finding fingerprints (SRS Ch4 §6.1; Ch8 §6).

Identity contract (version-stable):
    fingerprint = SHA256(
        normalize(target.hostname) + "|" +
        normalize(canonical_finding_category.code) + "|" +
        normalize(category_specific_identifier)
    )

The fingerprint links occurrences of the same underlying security issue
across scans for lifecycle tracking (NEW / PERSISTENT / RESOLVED /
REGRESSED). Inputs are restricted to hostname, category code and a
category-specific identifier. Severity, confidence, evidence text,
timestamps, AI output and random values are NEVER used.

Canonical category rule (critical):
    Fingerprint generation MUST use the canonical persisted database
    finding-category code — the value stored in scan_finding after
    scan_service._map_category() — not the raw engine category. The
    pipeline therefore maps (engine category -> canonical DB code)
    BEFORE fingerprinting. For example, engine category
    "http.security-headers" is persisted as "MISSING_SECURITY_HEADER";
    the fingerprint must be generated from the latter. Alias keys such
    as "http.security-headers" remain supported only for backward
    compatibility/test convenience and must not be used on the
    persistence path.

Category-specific identifier extraction is version-controlled here.
Unsupported or unidentifiable categories fail with a typed error
rather than producing an unstable fingerprint.

Normalization:
- hostname: strip, lower-case, strip trailing dot
- category: strip, upper-case
- identifier: lower-case, collapse whitespace, strip (header/path/CVE
  helpers apply their own rules, e.g. CVE upper-case)
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def normalize_hostname(hostname: str) -> str:
    """Lowercase, strip trailing dot, strip whitespace."""
    return hostname.strip().lower().rstrip(".")


def normalize_header_name(raw: str) -> str:
    """Lowercase, strip whitespace and colon suffix."""
    return raw.strip().lower().rstrip(":")


def normalize_path(path: str) -> str:
    """Strip trailing slash, lowercase, collapse consecutive slashes."""
    p = path.strip().lower()
    while "//" in p:
        p = p.replace("//", "/")
    return p.rstrip("/") or "/"


def normalize_cve_id(raw: str) -> str:
    """Uppercase, strip whitespace."""
    return raw.strip().upper()


def normalize_generic_identifier(raw: str) -> str:
    """Lowercase, collapse whitespace, strip."""
    return " ".join(raw.strip().lower().split())


# ---------------------------------------------------------------------------
# Category-specific identifier extraction rules
# ---------------------------------------------------------------------------

_HEADER_TITLE_RE = re.compile(
    r"Missing\s+(?P<name>[A-Z][A-Za-z0-9-]+)\s+security\s+header", re.IGNORECASE
)
_NONSTANDARD_XCTO_RE = re.compile(r"Nonstandard\s+(X-Content-Type-Options)\s+value", re.IGNORECASE)
_COOKIE_SECURE_RE = re.compile(r"Cookies?\s+without\s+the\s+(Secure)\s+attribute", re.I)
_COOKIE_HTTPONLY_RE = re.compile(r"Cookies?\s+without\s+the\s+(HttpOnly)\s+attribute", re.I)
_CVE_ID_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)


def _extract_security_header_identifier(title: str, location: str) -> str | None:  # noqa: ARG001
    """Extract header name from e.g. 'Missing Content-Security-Policy ...'."""
    m = _HEADER_TITLE_RE.search(title)
    if m:
        return normalize_header_name(m.group("name"))
    m2 = _NONSTANDARD_XCTO_RE.search(title)
    if m2:
        return normalize_header_name(m2.group(1))
    for known in (
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ):
        if known in title.lower():
            return known
    return None


def _extract_cookie_identifier(title: str, location: str) -> str | None:  # noqa: ARG001
    """Extract hygiene-issue type from cookie findings."""
    if _COOKIE_SECURE_RE.search(title):
        return "cookie_missing_secure"
    if _COOKIE_HTTPONLY_RE.search(title):
        return "cookie_missing_httponly"
    if "samesite" in title.lower():
        return "cookie_samesite_issue"
    return None


def _extract_transport_identifier(title: str, location: str) -> str | None:  # noqa: ARG001
    """Transport findings are per-scan posture observations; stable keys."""
    lowered = title.lower()
    if "hsts" in lowered or "https downgrade" in lowered:
        return "transport_hsts_downgrade"
    if "tls" in lowered or "certificate" in lowered:
        return "transport_tls"
    return "transport_posture"


def _extract_server_info_identifier(title: str, location: str) -> str | None:  # noqa: ARG001
    """Server-info disclosures are keyed by specific header name."""
    m = re.search(r"exposed:\s*(\S+)", title, re.IGNORECASE)
    if m:
        return normalize_header_name(m.group(1))
    return "server_info_disclosure"


def extract_identifier(category_code: str, title: str, location: str = "") -> str:
    """Extract the category-specific identity element.

    Raises ``UnsupportedFingerprintCategory`` for categories with no defined
    rule or when the required identifier cannot be derived. No silent
    fallback to the full title is performed.
    """
    code_upper = category_code.strip().upper()
    cat_lower = category_code.strip().lower()

    extractor = _IDENTIFIER_EXTRACTORS.get(code_upper) or _IDENTIFIER_EXTRACTORS.get(cat_lower)
    if extractor is None:
        raise UnsupportedFingerprintCategory(category_code)

    raw_result = extractor(title, location)
    if not isinstance(raw_result, str) or not raw_result.strip():
        raise UnsupportedFingerprintCategory(
            f"{category_code}: cannot extract identifier from title {title!r}"
        )
    return raw_result


class UnsupportedFingerprintCategory(Exception):
    """Raised when no identifier-extraction rule covers a category or input."""

    def __init__(self, category_code: str) -> None:
        self.category_code = category_code
        super().__init__(f"No fingerprint identifier rule defined for category {category_code!r}")


_Extractor = Any  # Callable[[str, str], str | None] — Any keeps lambdas simple for mypy

_IDENTIFIER_EXTRACTORS: dict[str, _Extractor] = {
    "MISSING_SECURITY_HEADER": _extract_security_header_identifier,
    "http.security-headers": _extract_security_header_identifier,
    "http.cookies": _extract_cookie_identifier,
    "http.transport": _extract_transport_identifier,
    "http.server-info": _extract_server_info_identifier,
    "KNOWN_CVE": lambda title, loc: (  # noqa: ARG005
        normalize_cve_id(m.group(1)) if (m := _CVE_ID_RE.search(title)) else None
    ),
    "EXPOSED_ADMIN_PANEL": lambda title, loc: normalize_path(loc) if loc.strip() else None,  # noqa: ARG005
    "OUTDATED_TLS": lambda title, loc: normalize_generic_identifier(title) or None,  # noqa: ARG005
    "WEAK_CIPHER": lambda title, loc: normalize_generic_identifier(title) or None,  # noqa: ARG005
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_fingerprint(
    *,
    hostname: str,
    category_code: str,
    identifier: str,
) -> str:
    """Deterministic SHA-256-based cross-scan finding identity.

    Same logical finding across two scans -> same fingerprint.
    Inputs are normalized; only hostname, category code and the
    category-specific identifier participate.
    """
    normalized_host = normalize_hostname(hostname)
    normalized_cat = category_code.strip().upper()
    normalized_ident = normalize_generic_identifier(identifier)
    if not normalized_host or not normalized_cat or not normalized_ident:
        raise ValueError("hostname, category_code and identifier must be non-empty")
    raw = f"{normalized_host}|{normalized_cat}|{normalized_ident}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_fingerprint_from_finding(
    *,
    hostname: str,
    category_code: str,
    title: str,
    location: str = "",
) -> str:
    """Convenience wrapper: extracts the identifier then generates the hash."""
    identifier = extract_identifier(category_code, title, location)
    return generate_fingerprint(
        hostname=hostname, category_code=category_code, identifier=identifier
    )
