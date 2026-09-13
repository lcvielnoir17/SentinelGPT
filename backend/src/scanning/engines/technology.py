"""Passive technology detection from already-collected response data.

The detector consumes ONLY what the HTTP engine already fetched (response
headers, bounded body prefix); it performs no network requests, resolves
no names, and opens no sockets. Output is observations — never findings:
an observed ``nginx`` does not imply a vulnerability, and no canonical
finding identity (fingerprint) is minted for technology rows.

Design rules:

* Allowlist-gated identities: only curated technology slugs are ever
  emitted. An attacker-controlled ``X-Powered-By: DefinitelyFakeCMS``
  matches nothing and yields no observation.
* Versions are claimed only when the banner format IS the product version
  (``nginx/1.25``); ambiguous values (CLR build numbers, free text)
  identify the family with ``version=None``. Versions are never invented.
* Conflicting indicators are all reported (a stack has layers); identical
  (technology, version) detections deduplicate with merged sources.
* All evidence is attacker-controlled input: bounded, control-stripped,
  and echoed as quoted snippets only (see ``bound_evidence``). Technology
  observations must stay inert data for downstream prompt framing — they
  carry no instructions and are never trusted.
* Body scanning is bounded to the first ``MAX_BODY_SCAN_CHARS`` decoded
  characters; binary bodies decode lossily and specific markers keep
  false positives low.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.domain.scanning.findings import Confidence, bound_evidence

MAX_BODY_SCAN_CHARS = 32_768
MAX_EVIDENCE_CHARS = 200

# Families stay coarse on purpose: they describe the layer, not a product.
FAMILY_SERVER = "server"
FAMILY_FRAMEWORK = "framework"
FAMILY_LANGUAGE = "language"
FAMILY_CMS = "cms"
FAMILY_PROXY = "proxy"


@dataclass(frozen=True)
class Technology:
    """One detected technology (observation-grade, not a vulnerability)."""

    slug: str
    display: str
    family: str
    version: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    sources: tuple[str, ...] = ()
    evidence: str = ""

    def observation_category(self) -> str:
        return f"technology.{self.family}.{self.slug}"

    def title(self) -> str:
        labeled = f"{self.display} {self.version}".strip()
        return f"Technology detected: {labeled}"

    def detail(self) -> str:
        version_note = (
            f"version {self.version}" if self.version else "version unknown (family only)"
        )
        return (
            f"Passive indicator identifies {self.display} ({self.family}, "
            f"{version_note}) at {self.confidence.value.upper()} confidence. "
            f"This is inventory, not a vulnerability."
        )


# --------------------------------------------------------------------------- #
# Curated signature tables (allowlist: unknown values never identify)          #
# --------------------------------------------------------------------------- #

# Server header product token → (slug, display, family, version-authoritative).
# Version-authoritative means "name/version IS the product version".
_SERVER_PRODUCTS: dict[str, tuple[str, str, str, bool]] = {
    "nginx": ("nginx", "nginx", FAMILY_SERVER, True),
    "apache": ("apache-httpd", "Apache httpd", FAMILY_SERVER, True),
    "apache-coyote": ("apache-tomcat", "Apache Tomcat", FAMILY_SERVER, True),
    "microsoft-iis": ("microsoft-iis", "Microsoft IIS", FAMILY_SERVER, True),
    "litespeed": ("litespeed", "LiteSpeed", FAMILY_SERVER, True),
    "openresty": ("openresty", "OpenResty", FAMILY_SERVER, True),
    "caddy": ("caddy", "Caddy", FAMILY_SERVER, True),
    "tengine": ("tengine", "Tengine", FAMILY_SERVER, True),
    "cloudflare": ("cloudflare", "Cloudflare", FAMILY_PROXY, False),
    "akamaighost": ("akamai", "Akamai", FAMILY_PROXY, False),
    "envoy": ("envoy", "Envoy", FAMILY_SERVER, False),
}

# Exact full-value server banners that carry no version but identify firmly.
_SERVER_EXACT: dict[str, tuple[str, str, str]] = {
    "cloudflare": ("cloudflare", "Cloudflare", FAMILY_PROXY),
}

# X-Powered-By product → (slug, display, family, version-authoritative).
_POWERED_BY: dict[str, tuple[str, str, str, bool]] = {
    "php": ("php", "PHP", FAMILY_LANGUAGE, True),
    "asp.net": ("aspnet", "ASP.NET", FAMILY_FRAMEWORK, False),
    "express": ("express", "Express", FAMILY_FRAMEWORK, False),
    "next.js": ("nextjs", "Next.js", FAMILY_FRAMEWORK, False),
}

# Meta generator / x-generator allowlisted CMS names → display.
_CMS_NAMES: dict[str, str] = {
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla!",
    "ghost": "Ghost",
    "typo3": "TYPO3",
    "mediawiki": "MediaWiki",
}

_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+){0,3})$")
_TOKEN_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-]*?)(?:/v?([\w.\-]+))?$")
_META_GENERATOR_RE = re.compile(
    r"<meta[^>]{0,500}?name\s*=\s*[\"']generator[\"'][^>]{0,500}?>", re.IGNORECASE
)
_META_CONTENT_RE = re.compile(r"content\s*=\s*[\"']([^\"']{1,200})[\"']", re.IGNORECASE)
_GENERATOR_VALUE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-! ]*?)(?:\s+v?(\d+(?:\.\d+){0,3}))?\s*$")

# HTML path markers → (slug, display, family). Specific literals only.
_HTML_MARKERS: tuple[tuple[str, str, str, str], ...] = (
    ("/_next/static/", "nextjs", "Next.js", FAMILY_FRAMEWORK),
    ("__NEXT_DATA__", "nextjs", "Next.js", FAMILY_FRAMEWORK),
    ("data-reactroot", "react", "React", FAMILY_FRAMEWORK),
    ("wp-content/", "wordpress", "WordPress", FAMILY_CMS),
    ("wp-includes/", "wordpress", "WordPress", FAMILY_CMS),
    ("sites/default/files", "drupal", "Drupal", FAMILY_CMS),
    ("media/jui/", "joomla", "Joomla!", FAMILY_CMS),
    ("ng-version=", "angular", "Angular", FAMILY_FRAMEWORK),
)


@dataclass
class _Accumulator:
    """Deduplicate (slug, version), merging evidence sources."""

    rows: dict[tuple[str, str | None], Technology] = field(default_factory=dict)

    def add(
        self,
        *,
        slug: str,
        display: str,
        family: str,
        version: str | None,
        confidence: Confidence,
        source: str,
        evidence: str,
    ) -> None:
        key = (slug, version)
        snippet = bound_evidence(f"{source}: {evidence}", MAX_EVIDENCE_CHARS)
        existing = self.rows.get(key)
        if existing is None:
            self.rows[key] = Technology(
                slug=slug,
                display=display,
                family=family,
                version=version,
                confidence=confidence,
                sources=(source,),
                evidence=snippet,
            )
            return
        merged_sources = tuple(sorted(set(existing.sources) | {source}))
        merged_confidence = (
            Confidence.HIGH
            if Confidence.HIGH in (existing.confidence, confidence)
            else existing.confidence
        )
        self.rows[key] = Technology(
            slug=existing.slug,
            display=existing.display,
            family=existing.family,
            version=existing.version,
            confidence=merged_confidence,
            sources=merged_sources,
            evidence=existing.evidence,
        )

    def technologies(self) -> tuple[Technology, ...]:
        return tuple(sorted(self.rows.values(), key=lambda t: (t.family, t.slug, t.version or "")))


def _split_product_token(token: str) -> tuple[str, str | None]:
    """``name[/version]`` split; version kept only when strictly numeric."""
    token = token.strip()
    if not token or token.startswith("("):
        return "", None
    match = _TOKEN_RE.match(token)
    if not match:
        return "", None
    name, raw_version = match.group(1), match.group(2)
    version: str | None = None
    if raw_version and _VERSION_RE.match(raw_version):
        version = raw_version.lstrip("v")
    return name, version


def _detect_from_server(value: str, acc: _Accumulator) -> None:
    for chunk in re.split(r"[,\s]+", value):
        name, version = _split_product_token(chunk)
        if not name:
            continue
        key = name.lower()
        if key in _SERVER_EXACT:
            slug, display, family = _SERVER_EXACT[key]
            acc.add(
                slug=slug,
                display=display,
                family=family,
                version=None,
                confidence=Confidence.HIGH,
                source="header:server",
                evidence=value,
            )
            continue
        entry = _SERVER_PRODUCTS.get(key)
        if entry is None:
            continue
        slug, display, family, authoritative = entry
        if not slug:
            continue
        acc.add(
            slug=slug,
            display=display,
            family=family,
            version=version if authoritative else None,
            confidence=Confidence.HIGH,
            source="header:server",
            evidence=value,
        )


def _detect_from_powered_by(value: str, acc: _Accumulator) -> None:
    name, version = _split_product_token(value.split(";")[0])
    entry = _POWERED_BY.get(name.lower())
    if entry is None:
        return
    slug, display, family, authoritative = entry
    acc.add(
        slug=slug,
        display=display,
        family=family,
        version=version if authoritative else None,
        confidence=Confidence.HIGH,
        source="header:x-powered-by",
        evidence=value,
    )


def _detect_from_headers(headers: tuple[tuple[str, str], ...], acc: _Accumulator) -> None:
    header_map: dict[str, list[str]] = {}
    for key, value in headers:
        header_map.setdefault(key.lower(), []).append(value)
    for value in header_map.get("server", []):
        _detect_from_server(value, acc)
    for value in header_map.get("x-powered-by", []):
        _detect_from_powered_by(value, acc)
    for header_name in ("x-aspnet-version", "x-aspnetmvc-version"):
        for value in header_map.get(header_name, []):
            if value.strip():
                acc.add(
                    slug="aspnet",
                    display="ASP.NET",
                    family=FAMILY_FRAMEWORK,
                    version=None,
                    confidence=Confidence.HIGH,
                    source=f"header:{header_name}",
                    evidence=value,
                )
    for value in header_map.get("x-generator", []):
        _detect_cms_value(value, acc, source="header:x-generator")
    for value in header_map.get("via", []):
        lowered = value.lower()
        if "cloudfront" in lowered:
            acc.add(
                slug="cloudfront",
                display="CloudFront",
                family=FAMILY_PROXY,
                version=None,
                confidence=Confidence.MEDIUM,
                source="header:via",
                evidence=value,
            )
        if "fastly" in lowered:
            acc.add(
                slug="fastly",
                display="Fastly",
                family=FAMILY_PROXY,
                version=None,
                confidence=Confidence.MEDIUM,
                source="header:via",
                evidence=value,
            )
        if "varnish" in lowered:
            acc.add(
                slug="varnish",
                display="Varnish",
                family=FAMILY_PROXY,
                version=None,
                confidence=Confidence.MEDIUM,
                source="header:via",
                evidence=value,
            )
    if any(header_map.get(name) for name in ("cf-ray",)):
        values = header_map.get("cf-ray", [])
        acc.add(
            slug="cloudflare",
            display="Cloudflare",
            family=FAMILY_PROXY,
            version=None,
            confidence=Confidence.HIGH,
            source="header:cf-ray",
            evidence=values[0] if values else "present",
        )
    for header_name in ("x-fastly-request-id", "x-amz-cf-id"):
        if header_name in header_map:
            slug = "fastly" if "fastly" in header_name else "cloudfront"
            display = "Fastly" if "fastly" in header_name else "CloudFront"
            acc.add(
                slug=slug,
                display=display,
                family=FAMILY_PROXY,
                version=None,
                confidence=Confidence.HIGH,
                source=f"header:{header_name}",
                evidence="present",
            )
    cookies = [v for k, v in headers if k.lower() == "set-cookie"]
    for cookie in cookies:
        name = cookie.split(";", 1)[0].split("=", 1)[0].strip().lower()
        if name == "laravel_session":
            acc.add(
                slug="laravel",
                display="Laravel",
                family=FAMILY_FRAMEWORK,
                version=None,
                confidence=Confidence.MEDIUM,
                source="cookie:laravel_session",
                evidence="session cookie name",
            )


def _detect_cms_value(value: str, acc: _Accumulator, *, source: str) -> None:
    match = _GENERATOR_VALUE_RE.match(value.strip()[:200])
    if not match:
        return
    name, version = match.group(1).strip(), match.group(2)
    key = re.sub(r"[^a-z0-9]", "", name.lower())
    display = _CMS_NAMES.get(key)
    if display is None:
        return
    acc.add(
        slug=key,
        display=display,
        family=FAMILY_CMS,
        version=version,
        confidence=Confidence.HIGH,
        source=source,
        evidence=value.strip()[:200],
    )


def _detect_from_body(body: bytes, acc: _Accumulator) -> None:
    if not body or b"<" not in body[:1024]:
        return
    try:
        text = body[:MAX_BODY_SCAN_CHARS].decode("latin-1")
    except Exception:
        return
    lowered = text.lower()
    for marker, slug, display, family in _HTML_MARKERS:
        if marker in lowered:
            start = max(0, lowered.find(marker) - 40)
            acc.add(
                slug=slug,
                display=display,
                family=family,
                version=None,
                confidence=Confidence.MEDIUM,
                source="html:marker",
                evidence=text[start : start + 120],
            )
    for tag in _META_GENERATOR_RE.findall(text):
        content = _META_CONTENT_RE.search(tag)
        if content:
            _detect_cms_value(content.group(1), acc, source="html:meta-generator")
            break


def detect_technologies(
    headers: tuple[tuple[str, str], ...], body: bytes = b""
) -> tuple[Technology, ...]:
    """Detect technologies from already-collected response data (pure).

    Deterministic: same inputs always yield the same ordered tuple.
    Never emits findings, versions it cannot justify, or identities
    outside the curated allowlist.
    """
    acc = _Accumulator()
    _detect_from_headers(headers, acc)
    _detect_from_body(body, acc)
    return acc.technologies()


__all__ = [
    "Technology",
    "detect_technologies",
    "MAX_BODY_SCAN_CHARS",
]
