"""Passive HTTP security-analysis engine Ã¢â‚¬â€ the FIRST real engine (ADR-0007).

Scope (deliberately narrow):

* ONE logical request to the validated origin (transport-managed redirects
  included); NO crawling, no speculative paths, no endpoint discovery.
* Passive inspection of what the target already returns: security headers,
  Set-Cookie attribute hygiene, transport/TLS posture, and ordinary server
  information headers.

Hard rules enforced structurally:

* The engine receives ONLY ``(context, services)``. It has no resolver, no
  socket, no process-spawning capability, no Docker handle, and cannot construct a transport:
  its sole network capability is the factory inside ``EngineServices``,
  which produces sandbox-bound clients for THIS context.
* Observations are gathered first; findings are derived by deterministic
  assessment. Absence of a header is reported at LOW/INFO with HIGH
  confidence Ã¢â‚¬â€ never dramatized.
* Evidence is bounded/redacted via the shared findings model; cookie VALUES
  are dropped unconditionally.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.domain.errors import EgressDeniedError
from src.domain.scanning.findings import (
    MAX_COOKIE_NAMES_IN_EVIDENCE,
    Confidence,
    Finding,
    Observation,
    Severity,
    bound_evidence,
    dumps_stable,
    redact_cookie_value,
)
from src.domain.scanning.http_contract import (
    ConnectionTarget,
    ControlledTransportError,
    HttpRequestSpec,
    HttpScanRequest,
)
from src.scanning.engines.technology import Technology, detect_technologies

if TYPE_CHECKING:
    from src.domain.scanning.egress import ScanNetworkContext
    from src.domain.scanning.http_contract import (
        HttpClient,
        HttpLimits,
        HttpResponseData,
        ScanCancellation,
    )
    from src.scanning.engines.services import EngineServices, OriginSpec

_ENGINE_CATEGORY_HEADERS = "http.security-headers"
_ENGINE_CATEGORY_COOKIES = "http.cookies"
_ENGINE_CATEGORY_TRANSPORT = "http.transport"
_ENGINE_CATEGORY_SERVER = "http.server-info"

_SECURITY_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("content-security-policy", "Content-Security-Policy", "limits script/style sources"),
    ("strict-transport-security", "Strict-Transport-Security", "forces HTTPS for future visits"),
    ("x-content-type-options", "X-Content-Type-Options", "disables MIME sniffing when 'nosniff'"),
    ("x-frame-options", "X-Frame-Options", "controls framing/clickjacking posture"),
    ("referrer-policy", "Referrer-Policy", "restricts referrer leakage"),
    ("permissions-policy", "Permissions-Policy", "restricts powerful browser features"),
)


class RequestBudgetExceededError(Exception):
    """Engine refused to run: the attempt's request budget is exhausted."""


@dataclass(frozen=True)
class HttpAnalysisResult:
    """Deterministic structured output consumed by the future AI layer."""

    engine_name: str
    target_hostname: str
    request_scheme: str
    request_port: int
    request_path: str
    status: int | None
    redirect_count: int
    truncated: bool
    content_type: str
    response_bytes: int | None
    observations: tuple[Observation, ...]
    findings: tuple[Finding, ...]
    error_kind: str | None = None
    error_detail: str = ""
    engine_version: str = "1"
    # Structured technology inventory (mirrors the technology.* observations
    # above for DB persistence; observations remain the AI-readable form).
    technologies: tuple[Technology, ...] = ()

    def to_dict(self) -> dict[str, object]:
        severity_counts: dict[str, int] = {}
        for finding in self.findings:
            key = finding.severity.value
            severity_counts[key] = severity_counts.get(key, 0) + 1
        return {
            "engine": self.engine_name,
            "target": self.target_hostname,
            "request": {
                "scheme": self.request_scheme,
                "port": self.request_port,
                "path": self.request_path,
                "status": self.status,
                "redirect_count": self.redirect_count,
                "truncated": self.truncated,
                "content_type": self.content_type,
                "response_bytes": self.response_bytes,
            },
            "observations": [o.to_dict() for o in self.observations],
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "observation_count": len(self.observations),
                "finding_count": len(self.findings),
                "severity_counts": dict(sorted(severity_counts.items())),
            },
            "error": (
                {"kind": self.error_kind, "detail": self.error_detail} if self.error_kind else None
            ),
        }

    def serialize(self) -> str:
        return dumps_stable(self.to_dict())


@dataclass(frozen=True)
class HttpSecurityAnalysisEngine:
    """Passive analyzer over the Phase 4 sandbox-aware transport."""

    name: str = "http-security-analysis"
    version: str = "1"

    def execute(
        self,
        context: ScanNetworkContext,
        services: EngineServices,
    ) -> HttpAnalysisResult:
        limits = services.limits
        cancellation = services.cancellation
        origin = services.origin
        hostname = context.binding.hostname
        location = f"{origin.scheme}://{hostname}{origin.path}"

        if limits.max_requests < 1:
            raise RequestBudgetExceededError("request budget below minimum")

        client: HttpClient = services.http_client_factory()
        request = self._build_request(context, services)

        try:
            response = self._single_request(client, request, limits, cancellation)
        except ControlledTransportError as exc:
            return self._unreachable_result(context, origin, exc)

        observations: list[Observation] = []
        findings: list[Finding] = []
        self._assess_transport(context, origin, response, observations)
        self._assess_headers(response, location, observations, findings)
        _assess_cookies(response, location, observations, findings)
        _assess_cookie_prefixes(response, location, observations, findings)
        _assess_cors(response, location, observations, findings)
        _assess_cache(response, location, observations, findings)
        _assess_header_values(response, location, observations, findings)
        _assess_server_info(response, observations)
        _assess_server_detail(response, location, observations, findings)
        technologies = _assess_technology(response, location, observations)

        content_type = _header(response.headers, "content-type") or ""
        return HttpAnalysisResult(
            engine_name=self.name,
            engine_version=self.version,
            target_hostname=hostname,
            request_scheme=origin.scheme.lower(),
            request_port=response.final_target.port,
            request_path=origin.path,
            status=response.status,
            redirect_count=len(response.via_redirects),
            truncated=response.truncated,
            content_type=bound_evidence(content_type, 128),
            response_bytes=len(response.body),
            observations=tuple(observations),
            findings=tuple(findings),
            technologies=technologies,
        )

    # ------------------------------------------------------------------ #
    # Request plumbing (single logical request; no crawling)             #
    # ------------------------------------------------------------------ #

    def _build_request(
        self, context: ScanNetworkContext, services: EngineServices
    ) -> HttpScanRequest:
        origin = services.origin
        spec = HttpRequestSpec(method="GET", path=origin.path)
        target = ConnectionTarget.for_context(context, scheme=origin.scheme, port=origin.port)
        if not context.egress.authorize(target.address):
            raise EgressDeniedError()
        return HttpScanRequest(context=context, spec=spec, target=target)

    def _single_request(
        self,
        client: HttpClient,
        request: HttpScanRequest,
        limits: HttpLimits,
        cancellation: ScanCancellation,
    ) -> HttpResponseData:
        cancellation.check()
        return client.execute(request, limits=limits, cancellation=cancellation)

    def _unreachable_result(
        self,
        context: ScanNetworkContext,
        origin: OriginSpec,
        exc: ControlledTransportError,
    ) -> HttpAnalysisResult:
        observation = Observation.create(
            category=_ENGINE_CATEGORY_TRANSPORT,
            title="Target unreachable through validated transport",
            detail=(
                f"The attempt ended in a controlled transport failure "
                f"({exc.kind.value}); no security analysis was possible."
            ),
            evidence=str(exc.kind.value),
            location=f"{origin.scheme}://{context.binding.hostname}{origin.path}",
        )
        finding = Finding.create(
            category=_ENGINE_CATEGORY_TRANSPORT,
            title="No HTTP response obtained",
            description=(
                "The validated transport could not complete the exchange; "
                "the destination may be down, filtered, or misconfigured."
            ),
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            evidence=str(exc.kind.value),
            location=f"{origin.scheme}://{context.binding.hostname}{origin.path}",
            recommendation="Verify availability out-of-band; retry later.",
            observation_ids=(observation.id,),
        )
        return HttpAnalysisResult(
            engine_name=self.name,
            engine_version=self.version,
            target_hostname=context.binding.hostname,
            request_scheme=str(origin.scheme).lower(),
            request_port=int(origin.port or 0),
            request_path=origin.path,
            status=None,
            redirect_count=0,
            truncated=False,
            content_type="",
            response_bytes=None,
            observations=(observation,),
            findings=(finding,),
            error_kind=exc.kind.value,
            error_detail=bound_evidence(exc.detail, 256),
        )

    # ------------------------------------------------------------------ #
    # Passive assessments                                                #
    # ------------------------------------------------------------------ #

    def _assess_transport(
        self,
        context: ScanNetworkContext,
        origin: OriginSpec,
        response: HttpResponseData,
        out: list[Observation],
    ) -> None:
        scheme = origin.scheme.lower()
        out.append(
            Observation.create(
                category=_ENGINE_CATEGORY_TRANSPORT,
                title="Transport posture",
                detail=(
                    f"Exchange completed over {scheme.upper()} with certificate "
                    f"verification {'enforced' if scheme == 'https' else 'not applicable'}; "
                    f"{len(response.via_redirects)} validated redirect hop(s); "
                    f"body {len(response.body)} bytes"
                    + (" (clamped)" if response.truncated else "")
                    + "."
                ),
                evidence=json.dumps(
                    {
                        "scheme": scheme,
                        "status": response.status,
                        "redirects": list(response.via_redirects)[:10],
                        "truncated": response.truncated,
                        "bytes": len(response.body),
                    },
                    separators=(",", ":"),
                ),
                location=f"{scheme}://{context.binding.hostname}{origin.path}",
            )
        )

    def _assess_headers(
        self,
        response: HttpResponseData,
        location: str,
        out: list[Observation],
        findings_out: list[Finding],
    ) -> None:
        header_map = {k.lower(): v for k, v in response.headers}
        for lowered, display, purpose in _SECURITY_HEADERS:
            value = header_map.get(lowered)
            if value is not None and lowered == "x-content-type-options":
                normalized = value.strip().lower()
                if normalized != "nosniff":
                    observation = Observation.create(
                        category=_ENGINE_CATEGORY_HEADERS,
                        title=f"{display} has a nonstandard value",
                        detail=(
                            f"{display} should be exactly 'nosniff' to "
                            f"{purpose}; got an unrecognized value."
                        ),
                        evidence=f"{display}: {value}",
                        location=location,
                    )
                    out.append(observation)
                    findings_out.append(
                        Finding.create(
                            category=_ENGINE_CATEGORY_HEADERS,
                            title=f"Nonstandard {display} value",
                            description=(
                                f"The header is present but does not disable "
                                f"MIME sniffing as intended ({purpose})."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            evidence=f"{display}: {value}",
                            location=location,
                            recommendation=f"Set {display}: nosniff.",
                            observation_ids=(observation.id,),
                        )
                    )
                else:
                    out.append(
                        Observation.create(
                            category=_ENGINE_CATEGORY_HEADERS,
                            title=f"{display} present",
                            detail=f"{display} is set to 'nosniff'.",
                            evidence=f"{display}: {value}",
                            location=location,
                        )
                    )
                continue
            if value is None:
                observation = Observation.create(
                    category=_ENGINE_CATEGORY_HEADERS,
                    title=f"{display} absent",
                    detail=f"The response does not send {display}, which {purpose}.",
                    evidence="",
                    location=location,
                )
                out.append(observation)
                severity = (
                    Severity.LOW
                    if lowered
                    in {
                        "content-security-policy",
                        "strict-transport-security",
                        "x-content-type-options",
                        "x-frame-options",
                    }
                    else Severity.INFO
                )
                findings_out.append(
                    Finding.create(
                        category=_ENGINE_CATEGORY_HEADERS,
                        title=f"Missing {display} security header",
                        description=(
                            f"The response does not explicitly {purpose} "
                            f"because the header is absent."
                        ),
                        severity=severity,
                        confidence=Confidence.HIGH,
                        evidence="",
                        location=location,
                        recommendation=f"Consider sending {display}.",
                        observation_ids=(observation.id,),
                    )
                )
            else:
                out.append(
                    Observation.create(
                        category=_ENGINE_CATEGORY_HEADERS,
                        title=f"{display} present",
                        detail=f"{display} is set.",
                        evidence=f"{display}: {value}",
                        location=location,
                    )
                )
        if scheme_is_http(response):
            hsts = header_map.get("strict-transport-security")
            if hsts is not None:
                observation = Observation.create(
                    category=_ENGINE_CATEGORY_HEADERS,
                    title="HSTS sent over plain HTTP",
                    detail="Strict-Transport-Security has no effect on an http:// response.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    location=location,
                )
                out.append(observation)


def scheme_is_http(response: HttpResponseData) -> bool:
    """True when the final exchange used plain http (target scheme proxy)."""
    return response.final_target.scheme == "http"


def _header(headers: tuple[tuple[str, str], ...], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers:
        if key.lower() == lowered:
            return value
    return None


def _assess_cookies(
    response: HttpResponseData,
    location: str,
    out: list[Observation],
    findings_out: list[Finding],
) -> None:
    cookies = [v for k, v in response.headers if k.lower() == "set-cookie"]
    if not cookies:
        return
    redacted = [redact_cookie_value(c) for c in cookies]
    out.append(
        Observation.create(
            category=_ENGINE_CATEGORY_COOKIES,
            title=f"{len(cookies)} Set-Cookie header(s) observed",
            detail="Cookie values are redacted; only names and attribute flags kept.",
            evidence="\n".join(redacted[:MAX_COOKIE_NAMES_IN_EVIDENCE]),
            location=location,
        )
    )
    missing_secure: list[str] = []
    missing_httponly: list[str] = []
    samesite_issues: list[str] = []
    for original, reduced in zip(cookies, redacted, strict=True):
        name = reduced.split(" ")[0]
        attr_part = original.split(";", 1)[1] if ";" in original else ""
        flags = [token.strip().lower() for token in attr_part.split(";") if token.strip()]
        if "secure" not in flags:
            missing_secure.append(name)
        if "httponly" not in flags:
            missing_httponly.append(name)
        samesite_values = [f.split("=", 1)[1] for f in flags if f.startswith("samesite=")]
        if not samesite_values:
            samesite_issues.append(f"{name}: unspecified")
        elif samesite_values[0] not in {"strict", "lax", "none"}:
            samesite_issues.append(f"{name}: invalid '{samesite_values[0]}'")
    if missing_secure:
        out.append(_cookie_observation("Secure", missing_secure, location))
        findings_out.append(
            _cookie_finding(
                "Cookies without the Secure attribute",
                "These cookies can be transmitted over plaintext connections.",
                Severity.LOW,
                "Add the Secure attribute to every cookie.",
                missing_secure,
                location,
                out[-1].id,
            )
        )
    if missing_httponly:
        out.append(_cookie_observation("HttpOnly", missing_httponly, location))
        findings_out.append(
            _cookie_finding(
                "Cookies without the HttpOnly attribute",
                "Script running on the origin can read these cookies.",
                Severity.LOW,
                "Add HttpOnly to session-bearing cookies.",
                missing_httponly,
                location,
                out[-1].id,
            )
        )
    if samesite_issues:
        evidence = "; ".join(samesite_issues[:MAX_COOKIE_NAMES_IN_EVIDENCE])
        observation = Observation.create(
            category=_ENGINE_CATEGORY_COOKIES,
            title="SameSite attribute gaps",
            detail="Some cookies lack a valid SameSite attribute.",
            evidence=evidence,
            location=location,
        )
        out.append(observation)
        findings_out.append(
            Finding.create(
                category=_ENGINE_CATEGORY_COOKIES,
                title="SameSite attribute missing or invalid",
                description="CSRF protection benefits from explicit SameSite settings.",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                evidence=evidence,
                location=location,
                recommendation="Set SameSite=Lax or Strict where appropriate.",
                observation_ids=(observation.id,),
            )
        )


def _cookie_observation(attribute: str, names: list[str], location: str) -> Observation:
    listed = ", ".join(names[:MAX_COOKIE_NAMES_IN_EVIDENCE])
    suffix = "" if len(names) <= MAX_COOKIE_NAMES_IN_EVIDENCE else " …"
    return Observation.create(
        category=_ENGINE_CATEGORY_COOKIES,
        title=f"Cookies missing {attribute}",
        detail=f"{len(names)} cookie(s) lack the {attribute} attribute.",
        evidence=bound_evidence(listed + suffix),
        location=location,
    )


def _cookie_finding(
    title: str,
    description: str,
    severity: Severity,
    recommendation: str,
    names: list[str],
    location: str,
    observation_id: str,
) -> Finding:
    listed = ", ".join(names[:MAX_COOKIE_NAMES_IN_EVIDENCE])
    suffix = "" if len(names) <= MAX_COOKIE_NAMES_IN_EVIDENCE else " …"
    return Finding.create(
        category=_ENGINE_CATEGORY_COOKIES,
        title=title,
        description=description,
        severity=severity,
        confidence=Confidence.HIGH,
        evidence=bound_evidence(listed + suffix),
        location=location,
        recommendation=recommendation,
        observation_ids=(observation_id,),
    )


def _assess_server_info(response: HttpResponseData, out: list[Observation]) -> None:
    interesting = ("server", "x-powered-by", "x-generator", "x-framework")
    header_map = {k.lower(): v for k, v in response.headers}
    for key in interesting:
        value = header_map.get(key)
        if value:
            out.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_SERVER,
                    title=f"Server information exposed: {key}",
                    detail="Ordinary response header reveals implementation detail.",
                    evidence=f"{key}: {value}",
                    location="response-headers",
                )
            )


_VERSION_RE = r"(?:^|[^0-9a-zA-Z])(?:v?\d+\.\d+(?:\.\d+)*|\/\d+)"
_DEBUG_HEADER_PREFIX = "x-debug"


def _parse_cookie_attributes(cookie: str) -> tuple[str, set[str], dict[str, str]]:
    """(name, flag-set, key=value map) for one Set-Cookie header value."""
    parts = cookie.split(";")
    name_part = parts[0].strip()
    name = name_part.split("=", 1)[0].strip() if "=" in name_part else name_part
    flags: set[str] = set()
    pairs: dict[str, str] = {}
    for token in parts[1:]:
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            key, _, value = token.partition("=")
            key = key.strip().lower()
            flags.add(key)
            pairs[key] = value.strip()
        else:
            flags.add(token.lower())
    return name, flags, pairs


def _assess_cookie_prefixes(
    response: HttpResponseData,
    location: str,
    out: list[Observation],
    findings_out: list[Finding],
) -> None:
    """__Host- / __Secure- prefix rules (deterministic, syntactic).

    __Host- requires Secure + Path=/ + no Domain; __Secure- requires
    Secure. Violations aggregate into one finding; cookie values are
    never stored (names only).
    """
    cookies = [v for k, v in response.headers if k.lower() == "set-cookie"]
    violations: list[str] = []
    for cookie in cookies:
        name, flags, pairs = _parse_cookie_attributes(cookie)
        lowered = name.lower()
        if lowered.startswith("__host-"):
            missing = []
            if "secure" not in flags:
                missing.append("Secure")
            if pairs.get("path", "") != "/":
                missing.append("Path=/")
            if "domain" in flags:
                missing.append("no-Domain")
            if missing:
                violations.append(f"{name} (missing {'+'.join(missing)})")
        elif lowered.startswith("__secure-"):
            if "secure" not in flags:
                violations.append(f"{name} (missing Secure)")
    if not violations:
        return
    evidence = bound_evidence("; ".join(violations[:MAX_COOKIE_NAMES_IN_EVIDENCE]))
    observation = Observation.create(
        category=_ENGINE_CATEGORY_COOKIES,
        title="Cookie prefix violation",
        detail="Prefixed cookies do not meet the naming requirements browsers enforce.",
        evidence=evidence,
        location=location,
    )
    out.append(observation)
    findings_out.append(
        Finding.create(
            category=_ENGINE_CATEGORY_COOKIES,
            title="Cookie prefix violation",
            description=(
                "Cookies using the __Host- or __Secure- prefix miss required "
                "attributes, so browsers ignore the prefix protection."
            ),
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            evidence=evidence,
            location=location,
            recommendation="Give __Host- cookies Secure + Path=/ and no Domain; "
            "give __Secure- cookies Secure.",
            observation_ids=(observation.id,),
        )
    )


def _assess_cors(
    response: HttpResponseData,
    location: str,
    out: list[Observation],
    findings_out: list[Finding],
) -> None:
    """Passive CORS posture from the response's own ACAO/ACAC headers.

    Only combinations visible without sending an Origin are claimed: a
    credentialed wildcard is a real vulnerability; a bare wildcard is
    low-risk. Origin reflection cannot be detected from this controlled
    request (no Origin is sent) and is deliberately not claimed.
    """
    header_map = {k.lower(): v for k, v in response.headers}
    allow_origin = (header_map.get("access-control-allow-origin") or "").strip()
    allow_creds = (header_map.get("access-control-allow-credentials") or "").strip().lower()
    if allow_origin != "*":
        return
    credentialed = allow_creds == "true"
    observation = Observation.create(
        category=_ENGINE_CATEGORY_HEADERS,
        title="Wildcard CORS origin",
        detail=(
            "Access-Control-Allow-Origin is '*' "
            + ("with credentials allowed." if credentialed else "without credentials.")
        ),
        evidence="Access-Control-Allow-Origin: *"
        + (f"; Access-Control-Allow-Credentials: {allow_creds}" if allow_creds else ""),
        location=location,
    )
    out.append(observation)
    if credentialed:
        findings_out.append(
            Finding.create(
                category=_ENGINE_CATEGORY_HEADERS,
                title="Credentialed CORS wildcard",
                description=(
                    "Any origin may read credentialed responses, defeating "
                    "the same-origin policy for authenticated users."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence="Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                location=location,
                recommendation="Echo explicit trusted origins instead of '*', "
                "or stop allowing credentials.",
                observation_ids=(observation.id,),
            )
        )
    else:
        findings_out.append(
            Finding.create(
                category=_ENGINE_CATEGORY_HEADERS,
                title="Wildcard CORS origin",
                description="Any origin may read unauthenticated responses.",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                evidence="Access-Control-Allow-Origin: *",
                location=location,
                recommendation="Restrict to explicit origins when the data is sensitive.",
                observation_ids=(observation.id,),
            )
        )


def _assess_cache(
    response: HttpResponseData,
    location: str,
    out: list[Observation],
    findings_out: list[Finding],
) -> None:
    """Shared-cache storage of cookie-bearing responses.

    Only the clear-cut case is claimed: cookies present plus an explicit
    shared-cache directive (public/s-maxage). Absent or private directives
    produce no finding (insufficient evidence, not a pass).
    """
    header_map = {k.lower(): v for k, v in response.headers}
    cookies = [v for k, v in response.headers if k.lower() == "set-cookie"]
    if not cookies:
        return
    cache_control = header_map.get("cache-control", "")
    directives = {d.strip().split("=", 1)[0].lower() for d in cache_control.split(",")}
    if not ({"public", "s-maxage"} & directives):
        return
    names = [redact_cookie_value(c).split(" ", 1)[0] for c in cookies]
    evidence = bound_evidence(
        f"Cache-Control: {cache_control}; cookies: "
        + ", ".join(names[:MAX_COOKIE_NAMES_IN_EVIDENCE])
    )
    observation = Observation.create(
        category=_ENGINE_CATEGORY_HEADERS,
        title="Cacheable sensitive response",
        detail="A cookie-bearing response explicitly permits shared caching.",
        evidence=evidence,
        location=location,
    )
    out.append(observation)
    findings_out.append(
        Finding.create(
            category=_ENGINE_CATEGORY_HEADERS,
            title="Cacheable sensitive response",
            description=(
                "Shared caches may store a response tied to one user's "
                "session and serve it to others."
            ),
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            evidence=evidence,
            location=location,
            recommendation="Send Cache-Control: private, no-store on session responses.",
            observation_ids=(observation.id,),
        )
    )


def _parse_csp_directives(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        directives[parts[0].lower()] = parts[1:]
    return directives


def _hsts_max_age(value: str) -> int | None:
    for chunk in value.split(";"):
        chunk = chunk.strip()
        if chunk.lower().startswith("max-age="):
            try:
                return int(chunk.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                return None
    return None


def _assess_header_values(
    response: HttpResponseData,
    location: str,
    out: list[Observation],
    findings_out: list[Finding],
) -> None:
    """Value-level checks for PRESENT security headers.

    Absence is owned by _assess_headers; here only demonstrably weak
    values are claimed. Titles reuse the header-name identity on purpose:
    a weak value is the same issue class as the missing header, and
    severity transitions surface through comparison.
    """
    header_map = {k.lower(): v for k, v in response.headers}

    referrer = header_map.get("referrer-policy")
    if referrer is not None and referrer.strip().lower() == "unsafe-url":
        observation = Observation.create(
            category=_ENGINE_CATEGORY_HEADERS,
            title="Permissive Referrer-Policy value",
            detail="Referrer-Policy: unsafe-url leaks full URLs to any origin.",
            evidence=f"Referrer-Policy: {referrer}",
            location=location,
        )
        out.append(observation)
        findings_out.append(
            Finding.create(
                category=_ENGINE_CATEGORY_HEADERS,
                title="Permissive Referrer-Policy value",
                description="Full request URLs (often carrying tokens/ids) leak cross-origin.",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=f"Referrer-Policy: {referrer}",
                location=location,
                recommendation="Use strict-origin-when-cross-origin or stricter.",
                observation_ids=(observation.id,),
            )
        )

    csp = header_map.get("content-security-policy")
    if csp is not None:
        directives = _parse_csp_directives(csp)
        weak_sources = []
        for name in ("script-src", "style-src", "default-src"):
            for token in directives.get(name, []):
                if token.strip("'\"").lower() in {"unsafe-inline", "unsafe-eval"}:
                    weak_sources.append(f"{name} {token}")
        if weak_sources:
            evidence = bound_evidence("; ".join(weak_sources))
            observation = Observation.create(
                category=_ENGINE_CATEGORY_HEADERS,
                title="Permissive Content-Security-Policy value",
                detail="The policy allows inline/eval execution, blunting XSS protection.",
                evidence=evidence,
                location=location,
            )
            out.append(observation)
            findings_out.append(
                Finding.create(
                    category=_ENGINE_CATEGORY_HEADERS,
                    title="Permissive Content-Security-Policy value",
                    description="unsafe-inline/unsafe-eval keeps XSS exploitable despite CSP.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence=evidence,
                    location=location,
                    recommendation="Remove unsafe-inline/unsafe-eval; use nonces or hashes.",
                    observation_ids=(observation.id,),
                )
            )

    hsts = header_map.get("strict-transport-security")
    if hsts is not None and not scheme_is_http(response):
        max_age = _hsts_max_age(hsts)
        if max_age is None or max_age < 31536000:
            observation = Observation.create(
                category=_ENGINE_CATEGORY_HEADERS,
                title="Weak Strict-Transport-Security max-age",
                detail="HSTS max-age is missing or under one year.",
                evidence=f"Strict-Transport-Security: {hsts}",
                location=location,
            )
            out.append(observation)
            findings_out.append(
                Finding.create(
                    category=_ENGINE_CATEGORY_HEADERS,
                    title="Weak Strict-Transport-Security max-age",
                    description="Short HSTS lifetimes leave long windows without upgrade protection.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence=f"Strict-Transport-Security: {hsts}",
                    location=location,
                    recommendation="Set max-age=31536000 (or longer) with includeSubDomains.",
                    observation_ids=(observation.id,),
                )
            )
        elif "includesubdomains" not in hsts.lower().replace(" ", "").replace("-", ""):
            out.append(
                Observation.create(
                    category=_ENGINE_CATEGORY_HEADERS,
                    title="HSTS without includeSubDomains",
                    detail="Subdomains are not covered by the HSTS policy.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    location=location,
                )
            )


def _assess_technology(
    response: HttpResponseData, location: str, out: list[Observation]
) -> tuple[Technology, ...]:
    """Passive technology inventory (observations only, never findings).

    Consumes the already-fetched headers/body through the pure
    ``technology`` detector: no new requests, no fingerprint identity,
    no severity. Observations ride the normal result path into the
    evidence set so analysts (human or AI) gain asset context; the
    returned structured rows feed target-technology persistence.
    """
    technologies = detect_technologies(response.headers, response.body)
    for tech in technologies:
        out.append(
            Observation.create(
                category=tech.observation_category(),
                title=tech.title(),
                detail=tech.detail(),
                evidence=tech.evidence,
                location=location,
            )
        )
    return technologies


def _assess_server_detail(
    response: HttpResponseData,
    location: str,
    out: list[Observation],
    findings_out: list[Finding],
) -> None:
    """Version disclosure and debug indicators (one finding per header).

    Per-header identity keeps lifecycle precise: fixing one header
    resolves its finding while other disclosures persist.
    """
    header_map = {k.lower(): v for k, v in response.headers}
    version_headers = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")
    for name in version_headers:
        value = header_map.get(name)
        if not value:
            continue
        disclosed = name in ("x-aspnet-version", "x-aspnetmvc-version") or bool(
            re.search(_VERSION_RE, value, re.IGNORECASE)
        )
        if not disclosed:
            continue
        evidence = bound_evidence(f"{name}: {value}")
        observation = Observation.create(
            category=_ENGINE_CATEGORY_SERVER,
            title=f"Server version disclosed: {name}",
            detail="A response header exposes implementation version detail useful for targeting.",
            evidence=evidence,
            location=location,
        )
        out.append(observation)
        findings_out.append(
            Finding.create(
                category=_ENGINE_CATEGORY_SERVER,
                title=f"Server version disclosed: {name}",
                description="Version disclosure helps attackers match exploits to this stack.",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=evidence,
                location=location,
                recommendation="Strip version tokens from response headers.",
                observation_ids=(observation.id,),
            )
        )
    debug_names = [k for k, v in response.headers if k.lower().startswith(_DEBUG_HEADER_PREFIX)]
    if debug_names:
        evidence = bound_evidence(", ".join(sorted({n.lower() for n in debug_names})))
        observation = Observation.create(
            category=_ENGINE_CATEGORY_SERVER,
            title="Debug header exposed",
            detail="Debug-mode headers suggest a non-production configuration.",
            evidence=evidence,
            location=location,
        )
        out.append(observation)
        findings_out.append(
            Finding.create(
                category=_ENGINE_CATEGORY_SERVER,
                title="Debug header exposed",
                description="Debug headers indicate verbose/diagnostic behavior is enabled.",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=evidence,
                location=location,
                recommendation="Disable debug headers outside development.",
                observation_ids=(observation.id,),
            )
        )
