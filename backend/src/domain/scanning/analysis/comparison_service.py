"""Fail-closed AI comparison service (mirrors the scan-analysis service).

Contract: ``analyze(evidence) → (evidence, ComparisonAssessment |
ComparisonUnavailable)``. The SAME immutable evidence object returns in
BOTH outcomes — deterministic comparison always survives AI failure.
Provider exceptions map onto the typed failure classification;
unexpected exceptions degrade to UNEXPECTED with only the exception TYPE
preserved (no internals leak).

The analyzer is duck-typed (``analyze(evidence, *, system_instructions,
user_prompt)``): the Gemini evidence analyzer satisfies it at runtime,
and deterministic scripted doubles satisfy it in tests. No provider code
changes are required.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.domain.scanning.analysis.comparison_models import (
    AnalysisFailureKind,
    ComparisonAssessment,
    ComparisonUnavailable,
)
from src.domain.scanning.analysis.comparison_prompts import (
    COMPARE_OUTPUT_SCHEMA_VERSION,
    COMPARE_PROMPT_SCHEMA_VERSION,
    build_compare_prompts,
)
from src.domain.scanning.analysis.comparison_validator import (
    validate_comparison_response,
)

if TYPE_CHECKING:
    from src.domain.scanning.analysis.comparison_evidence import ComparisonEvidence


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ScriptedComparisonAnalyzer:
    """Deterministic analyzer double for tests (mirrors ScriptedAnalyzer)."""

    response: str | dict[str, Any]
    raises: bool = False
    provider: str = "scripted"
    model: str = "scripted-v1"
    model_version: str = "1"

    def analyze(
        self,
        evidence: ComparisonEvidence,
        *,
        system_instructions: str,
        user_prompt: str,
    ) -> str | dict[str, Any]:
        del evidence, system_instructions, user_prompt
        if self.raises:
            assert isinstance(self.response, BaseException), (
                "raises=True requires an exception instance"
            )
            raise self.response
        return self.response


class ComparisonAnalysisService:
    """Orchestrates prompts → provider → validation, failing closed."""

    def __init__(
        self,
        analyzer: Any,
        *,
        clock: Any | None = None,
    ) -> None:
        self._analyzer = analyzer
        self._clock = clock or _utc_now

    def analyze(
        self, evidence: ComparisonEvidence
    ) -> tuple[ComparisonEvidence, ComparisonAssessment | ComparisonUnavailable]:
        from src.domain.scanning.analysis.models import AnalysisProviderError

        system_instructions, user_prompt = build_compare_prompts(evidence)
        metadata_base = {
            "provider": str(getattr(self._analyzer, "provider", "unknown")),
            "model": str(getattr(self._analyzer, "model", "unknown")),
            "model_version": str(getattr(self._analyzer, "model_version", "unknown")),
            "prompt_schema_version": COMPARE_PROMPT_SCHEMA_VERSION,
            "output_schema_version": COMPARE_OUTPUT_SCHEMA_VERSION,
        }
        try:
            raw = self._analyzer.analyze(
                evidence,
                system_instructions=system_instructions,
                user_prompt=user_prompt,
            )
        except AnalysisProviderError as exc:
            return evidence, self._unavailable(evidence, exc.kind, exc.detail)
        except Exception as exc:  # noqa: BLE001 - typed degradation boundary
            return evidence, self._unavailable(
                evidence, AnalysisFailureKind.UNEXPECTED, type(exc).__name__
            )

        validation = validate_comparison_response(
            raw, evidence, provider_metadata_base=metadata_base, now=self._clock()
        )
        if not validation.accepted:
            kind = validation.failure_kind or AnalysisFailureKind.SCHEMA_INVALID
            return evidence, self._unavailable(evidence, kind, "; ".join(validation.errors)[:300])
        assert validation.assessment is not None
        return evidence, validation.assessment

    def _unavailable(
        self,
        evidence: ComparisonEvidence,
        kind: AnalysisFailureKind,
        detail: str,
    ) -> ComparisonUnavailable:
        return ComparisonUnavailable(
            comparison_evidence_id=evidence.comparison_evidence_id,
            failure_kind=kind,
            detail=detail[:300].replace("\n", " "),
            created_at=self._clock(),
        )
