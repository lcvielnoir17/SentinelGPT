"""EvidenceAnalyzer protocol + fail-closed analysis service (ADR-0008).

The service is the ONLY entry point callers use. Its contract:

    analyze(evidence_set) → (evidence_set, Assessment | AssessmentUnavailable)

Invariants:

* The SAME immutable evidence set object is returned in BOTH outcomes —
  deterministic Phase 5 findings always survive AI failure.
* Provider exceptions are mapped onto the typed failure classification;
  unexpected exceptions degrade to UNEXPECTED with only the exception TYPE
  preserved (no internals leak).
* Prompt assembly happens here so every analyzer sees identical inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from src.domain.scanning.analysis.correlation import build_candidate_groups
from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    AnalysisProviderError,
    Assessment,
    AssessmentUnavailable,
)
from src.domain.scanning.analysis.prompts import (
    OUTPUT_SCHEMA_VERSION,
    PROMPT_SCHEMA_VERSION,
    build_prompts,
)
from src.domain.scanning.analysis.validator import validate_analysis_response

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.domain.scanning.analysis.correlation import CandidateGroup
    from src.domain.scanning.analysis.evidence import EvidenceSet


@runtime_checkable
class EvidenceAnalyzer(Protocol):
    """A provider-agnostic analyzer over serialized evidence.

    Implementations return the RAW provider payload (str or dict); schema
    validation is centralized in the service's validator so no provider can
    skip it.
    """

    provider: str
    model: str
    model_version: str

    def analyze(
        self,
        evidence_set: EvidenceSet,
        candidate_groups: tuple[CandidateGroup, ...],
        *,
        system_instructions: str,
        user_prompt: str,
    ) -> str | dict[str, Any]: ...


@dataclass(frozen=True)
class ScriptedAnalyzer:
    """Deterministic analyzer for tests/baselines.

    ``response`` is returned verbatim unless ``raises`` is True, in which
    case it must be a BaseException instance that will be raised — letting
    tests simulate provider failures through the normal protocol path.
    """

    response: str | dict[str, Any]
    raises: bool = False
    provider: str = "scripted"
    model: str = "scripted-v1"
    model_version: str = "1"

    def analyze(
        self,
        evidence_set: EvidenceSet,
        candidate_groups: tuple[CandidateGroup, ...],
        *,
        system_instructions: str,
        user_prompt: str,
    ) -> str | dict[str, Any]:
        del evidence_set, candidate_groups, system_instructions, user_prompt
        if self.raises:
            assert isinstance(self.response, BaseException), (
                "raises=True requires an exception instance"
            )
            raise self.response
        return self.response


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AiAnalysisService:
    """Orchestrates prompt → provider → validation, failing closed."""

    def __init__(
        self,
        analyzer: EvidenceAnalyzer,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._analyzer = analyzer
        self._clock = clock or _utc_now

    def analyze(
        self,
        evidence_set: EvidenceSet,
        candidate_groups: tuple[CandidateGroup, ...] | None = None,
    ) -> tuple[EvidenceSet, Assessment | AssessmentUnavailable]:
        groups = (
            candidate_groups
            if candidate_groups is not None
            else build_candidate_groups(evidence_set)
        )
        system_instructions, user_prompt = build_prompts(evidence_set, groups)
        metadata_base = {
            "provider": self._analyzer.provider,
            "model": self._analyzer.model,
            "model_version": self._analyzer.model_version,
            "prompt_schema_version": PROMPT_SCHEMA_VERSION,
            "output_schema_version": OUTPUT_SCHEMA_VERSION,
        }
        try:
            raw = self._analyzer.analyze(
                evidence_set,
                groups,
                system_instructions=system_instructions,
                user_prompt=user_prompt,
            )
        except AnalysisProviderError as exc:
            return evidence_set, self._unavailable(evidence_set, exc.kind, exc.detail)
        except Exception as exc:  # noqa: BLE001 - typed degradation boundary
            return evidence_set, self._unavailable(
                evidence_set, AnalysisFailureKind.UNEXPECTED, type(exc).__name__
            )

        validation = validate_analysis_response(
            raw, evidence_set, provider_metadata_base=metadata_base, now=self._clock()
        )
        if not validation.accepted:
            kind = validation.failure_kind or AnalysisFailureKind.SCHEMA_INVALID
            return evidence_set, self._unavailable(
                evidence_set, kind, "; ".join(validation.errors)[:300]
            )
        assert validation.assessment is not None
        return evidence_set, validation.assessment

    def _unavailable(
        self,
        evidence_set: EvidenceSet,
        kind: AnalysisFailureKind,
        detail: str,
    ) -> AssessmentUnavailable:
        return AssessmentUnavailable(
            evidence_set_id=evidence_set.evidence_set_id,
            failure_kind=kind,
            detail=detail[:300].replace("\n", " "),
            created_at=self._clock(),
        )
