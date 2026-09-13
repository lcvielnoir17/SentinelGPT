"""Composite engine: several engines, one sandbox, one attempt.

Runs a primary engine and an optional secondary engine sequentially inside
the SAME established sandbox and validated context, merging their
observations and findings into one result while preserving per-engine
attribution (engine code/version/findings triples) so persistence can
record one execution row per engine.

No new network capability: each composed engine uses only the shared
sandbox-bound client factory, and the attempt's request budget covers
both (the HTTP engine's single request plus the TLS engine's single
request fit the default budget of four).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.domain.scanning.egress import ScanNetworkContext
    from src.domain.scanning.findings import Finding, Observation
    from src.scanning.engines.services import EngineServices


@dataclass(frozen=True)
class CompositeScanResult:
    """Merged engine outputs with per-engine attribution preserved.

    The request envelope mirrors the primary result so downstream stages
    (evidence set, AI analysis, fallback explanations) consume the merged
    result exactly like a single-engine one. Missing envelope fields fall
    back to the attempt context — never to invented values.
    """

    findings: tuple[Any, ...] = ()
    observations: tuple[Any, ...] = ()
    # (engine_code, engine_version, findings) per engine, primary first.
    engine_results: tuple[tuple[str, str, tuple[Any, ...]], ...] = ()
    # Structured technology inventory merged across engines (observations
    # above remain the AI-readable form; this feeds DB persistence).
    technologies: tuple[Any, ...] = ()
    engine_code: str = ""
    engine_version: str = "1"
    engine_name: str = ""
    target_hostname: str = ""
    request_scheme: str = ""
    request_port: int = 0
    request_path: str = "/"
    status: int | None = None
    redirect_count: int = 0
    truncated: bool = False
    content_type: str = ""
    response_bytes: int | None = None
    error_kind: str | None = None
    error_detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "engine": self.engine_code,
            "findings": [f.to_dict() for f in self.findings],
            "observations": [o.to_dict() for o in self.observations],
            "engines": [
                {"code": code, "version": version, "finding_count": len(findings)}
                for code, version, findings in self.engine_results
            ],
        }


@dataclass(frozen=True)
class CompositeEngine:
    """Run primary then secondary engine in one attempt (ADR-0005/0006/0007)."""

    name: str = "composite"
    primary: Any = None
    secondary: Any | None = None
    primary_code: str = ""
    primary_version: str = "1"
    secondary_code: str = ""
    secondary_version: str = "1"

    def execute(
        self,
        context: ScanNetworkContext,
        services: EngineServices,
    ) -> CompositeScanResult:
        primary_result = self.primary.execute(context, services)
        findings: list[Finding] = list(primary_result.findings)
        observations: list[Observation] = list(primary_result.observations)
        technologies: list[Any] = list(getattr(primary_result, "technologies", ()))
        breakdown: list[tuple[str, str, tuple[Finding, ...]]] = [
            (self.primary_code, self.primary_version, tuple(primary_result.findings))
        ]
        if self.secondary is not None:
            secondary_result = self.secondary.execute(context, services)
            findings.extend(secondary_result.findings)
            observations.extend(secondary_result.observations)
            technologies.extend(getattr(secondary_result, "technologies", ()))
            breakdown.append(
                (
                    self.secondary_code,
                    self.secondary_version,
                    tuple(secondary_result.findings),
                )
            )
        return CompositeScanResult(
            findings=tuple(findings),
            observations=tuple(observations),
            technologies=tuple(technologies),
            engine_results=tuple(breakdown),
            engine_code=self.primary_code,
            engine_version=self.primary_version,
            **_primary_envelope(primary_result, context, services),
        )


def _primary_envelope(
    primary_result: Any, context: ScanNetworkContext, services: EngineServices
) -> dict[str, Any]:
    """Request envelope for the merged result (primary wins, context fills).

    Production primary results always carry the full envelope; the
    context-derived fallbacks exist only so test doubles and future
    engines without envelope fields still yield a complete, honest
    result (scheme/path/hostname from the validated attempt itself).
    """
    scheme = services.origin.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    return {
        "engine_name": str(getattr(primary_result, "engine_name", "") or ""),
        "target_hostname": str(
            getattr(primary_result, "target_hostname", "") or context.binding.hostname
        ),
        "request_scheme": str(getattr(primary_result, "request_scheme", "") or scheme),
        "request_port": int(getattr(primary_result, "request_port", 0) or 0)
        or int(services.origin.port or default_port),
        "request_path": str(getattr(primary_result, "request_path", "") or services.origin.path),
        "status": getattr(primary_result, "status", None),
        "redirect_count": int(getattr(primary_result, "redirect_count", 0) or 0),
        "truncated": bool(getattr(primary_result, "truncated", False)),
        "content_type": str(getattr(primary_result, "content_type", "") or ""),
        "response_bytes": getattr(primary_result, "response_bytes", None),
        "error_kind": getattr(primary_result, "error_kind", None),
        "error_detail": str(getattr(primary_result, "error_detail", "") or ""),
    }


__all__ = ["CompositeEngine", "CompositeScanResult"]
