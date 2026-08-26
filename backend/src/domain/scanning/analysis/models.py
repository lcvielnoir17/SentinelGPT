"""Structured models for the AI correlation layer (ADR-0008).

Layering:

    EvidenceSet (immutable, deterministic, Phase 5 findings)
        ↓ EvidenceAnalyzer (provider, possibly non-deterministic)
    raw response
        ↓ ResponseValidator (fail-closed, evidence-grounded)
    Assessment | AssessmentUnavailable

Integrity rules encoded here:

* Every AI claim carries an :class:`EvidenceStatus`; claims whose referenced
  finding IDs do not exist in the supplied evidence are FORCED to
  ``UNSUPPORTED`` and counted — never silently treated as evidence-backed.
* Assessments reference evidence; they never replace or modify it.
* Non-determinism is represented honestly: provider metadata always marks
  LLM-derived assessments ``nondeterministic=True``.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.domain.scanning.findings import Severity, dumps_stable

if TYPE_CHECKING:
    from datetime import datetime


class EvidenceStatus(enum.StrEnum):
    """How strongly a claim is tied to the supplied evidence set."""

    SUPPORTED = "supported"
    INFERRED = "inferred"
    UNSUPPORTED = "unsupported"


class AnalysisFailureKind(enum.StrEnum):
    """Typed, client-safe failure classification for AI analysis."""

    PROVIDER_UNAVAILABLE = "provider_unavailable"
    AUTHENTICATION_FAILED = "authentication_failed"
    TIMEOUT = "timeout"
    MALFORMED_RESPONSE = "malformed_response"
    SCHEMA_INVALID = "schema_invalid"
    LIMIT_EXCEEDED = "limit_exceeded"
    UNEXPECTED = "unexpected"


@dataclass(frozen=True)
class Claim:
    """One AI statement bound to the evidence it relies on."""

    text: str
    finding_ids: tuple[str, ...]
    status: EvidenceStatus
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "finding_ids": list(self.finding_ids),
            "status": self.status.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CorrelatedGroup:
    """AI-refined cluster of EXISTING findings (IDs pre-validated)."""

    group_id: str
    title: str
    finding_ids: tuple[str, ...]
    rationale: str = ""
    status: EvidenceStatus = EvidenceStatus.SUPPORTED

    @staticmethod
    def derive_group_id(title: str, finding_ids: tuple[str, ...]) -> str:
        identity = f"group|{title}|{'|'.join(sorted(finding_ids))}"
        return hashlib.sha256(identity.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "title": self.title,
            "finding_ids": list(self.finding_ids),
            "rationale": self.rationale,
            "status": self.status.value,
        }


@dataclass(frozen=True)
class RemediationItem:
    """One remediation suggestion traceable to findings."""

    title: str
    detail: str
    finding_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "detail": self.detail,
            "finding_ids": list(self.finding_ids),
        }


@dataclass(frozen=True)
class ProviderMetadata:
    """Honest provenance for one AI analysis run."""

    provider: str
    model: str
    model_version: str
    prompt_schema_version: str
    output_schema_version: str
    created_at: datetime
    nondeterministic: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "model_version": self.model_version,
            "prompt_schema_version": self.prompt_schema_version,
            "output_schema_version": self.output_schema_version,
            "created_at": self.created_at.isoformat(),
            "nondeterministic": self.nondeterministic,
        }


@dataclass(frozen=True)
class Assessment:
    """Validated AI assessment sitting ON TOP OF immutable evidence."""

    assessment_id: str
    evidence_set_id: str
    overall_summary: str
    priority: Severity
    correlated_groups: tuple[CorrelatedGroup, ...] = field(default=())
    remediation: tuple[RemediationItem, ...] = field(default=())
    limitations: tuple[str, ...] = field(default=())
    claims: tuple[Claim, ...] = field(default=())
    unsupported_claim_count: int = 0
    provider_metadata: ProviderMetadata | None = None

    @staticmethod
    def derive_assessment_id(
        evidence_set_id: str,
        provider: str,
        model: str,
        prompt_schema_version: str,
        output_schema_version: str,
        content_canonical: str,
    ) -> str:
        identity = "|".join(
            [
                "assessment",
                evidence_set_id,
                provider,
                model,
                prompt_schema_version,
                output_schema_version,
                content_canonical,
            ]
        )
        return hashlib.sha256(identity.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "evidence_set_id": self.evidence_set_id,
            "overall_summary": self.overall_summary,
            "priority": self.priority.value,
            "correlated_groups": [g.to_dict() for g in self.correlated_groups],
            "remediation": [r.to_dict() for r in self.remediation],
            "limitations": list(self.limitations),
            "claims": [c.to_dict() for c in self.claims],
            "unsupported_claim_count": self.unsupported_claim_count,
            "provider_metadata": (
                self.provider_metadata.to_dict() if self.provider_metadata else None
            ),
        }

    def serialize(self) -> str:
        return dumps_stable(self.to_dict())


@dataclass(frozen=True)
class AssessmentUnavailable:
    """Fail-closed outcome: deterministic evidence survives, AI does not."""

    evidence_set_id: str
    failure_kind: AnalysisFailureKind
    detail: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_set_id": self.evidence_set_id,
            "failure_kind": self.failure_kind.value,
            "detail": self.detail,
            "created_at": self.created_at.isoformat(),
        }

    def serialize(self) -> str:
        return dumps_stable(self.to_dict())


class AnalysisProviderError(Exception):
    """Typed provider-side failure raised by infrastructure adapters."""

    def __init__(self, kind: AnalysisFailureKind, detail: str = "") -> None:
        self.kind = kind
        self.detail = detail[:500]
        super().__init__(f"{kind.value}: {self.detail}".rstrip(": "))
