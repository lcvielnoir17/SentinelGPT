"""Structured models for AI comparison narration.

Layering (mirrors the scan-analysis layer):

    ComparisonEvidence (immutable, deterministic, scan A vs scan B)
        ↓ provider (possibly non-deterministic)
    raw response
        ↓ comparison validator (fail-closed, evidence-grounded)
    ComparisonAssessment | ComparisonUnavailable

Integrity rules encoded here:

* Every finding/fingerprint reference is checked against the evidence
  registries. Unknown references never become supported: they are forced
  to UNSUPPORTED and counted.
* Priority ``from_level``/``to_level`` must equal the deterministic
  record snapshots; mismatches are dropped and counted, never laundered.
* Assessments reference evidence; they never replace or modify it, and
  the schema contains NO severity/lifecycle/priority write path — the AI
  cannot mutate canonical truth by construction.
* Non-determinism is represented honestly via provider metadata.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    Claim,
    EvidenceStatus,
    ProviderMetadata,
)
from src.domain.scanning.findings import dumps_stable


@dataclass(frozen=True)
class ComparisonClaim:
    """One AI statement bound to comparison records it relies on."""

    text: str
    finding_ids: tuple[str, ...] = ()
    fingerprints: tuple[str, ...] = ()
    status: EvidenceStatus = EvidenceStatus.SUPPORTED
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "finding_ids": list(self.finding_ids),
            "fingerprints": list(self.fingerprints),
            "status": self.status.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class PriorityChange:
    """A narrated priority transition (levels verified against records)."""

    finding_id: str
    fingerprint: str
    from_level: str
    to_level: str
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "from_level": self.from_level,
            "to_level": self.to_level,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RegressionInsight:
    """A narrated regression anchored to one fingerprint."""

    finding_id: str
    fingerprint: str
    previous_state: str = ""
    current_state: str = ""
    why_matters: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "previous_state": self.previous_state,
            "current_state": self.current_state,
            "why_matters": self.why_matters,
        }


@dataclass(frozen=True)
class ResolvedItem:
    """A narrated resolution anchored to one fingerprint."""

    finding_id: str
    fingerprint: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "note": self.note,
        }


@dataclass(frozen=True)
class ComparisonAction:
    """One AI-suggested remediation step traceable to findings.

    ``verification`` describes HOW to confirm a fix (future rescan or
    check) — never an assertion that anything is already fixed.
    """

    title: str
    detail: str = ""
    finding_ids: tuple[str, ...] = ()
    verification: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "detail": self.detail,
            "finding_ids": list(self.finding_ids),
            "verification": self.verification,
        }


@dataclass(frozen=True)
class ComparisonAssessment:
    """Validated AI comparison narration sitting ON TOP OF evidence."""

    assessment_id: str
    comparison_evidence_id: str
    executive_summary: str
    technical_summary: str
    key_changes: tuple[ComparisonClaim, ...] = field(default=())
    priority_changes: tuple[PriorityChange, ...] = field(default=())
    regressions: tuple[RegressionInsight, ...] = field(default=())
    resolved_items: tuple[ResolvedItem, ...] = field(default=())
    recommended_actions: tuple[ComparisonAction, ...] = field(default=())
    limitations: tuple[str, ...] = field(default=())
    citations: tuple[ComparisonClaim, ...] = field(default=())
    unsupported_claim_count: int = 0
    provider_metadata: ProviderMetadata | None = None

    @staticmethod
    def derive_assessment_id(
        comparison_evidence_id: str,
        provider: str,
        model: str,
        prompt_schema_version: str,
        output_schema_version: str,
        content_canonical: str,
    ) -> str:
        identity = "|".join(
            [
                "comparison-assessment",
                comparison_evidence_id,
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
            "comparison_evidence_id": self.comparison_evidence_id,
            "executive_summary": self.executive_summary,
            "technical_summary": self.technical_summary,
            "key_changes": [c.to_dict() for c in self.key_changes],
            "priority_changes": [p.to_dict() for p in self.priority_changes],
            "regressions": [r.to_dict() for r in self.regressions],
            "resolved_items": [r.to_dict() for r in self.resolved_items],
            "recommended_actions": [a.to_dict() for a in self.recommended_actions],
            "limitations": list(self.limitations),
            "citations": [c.to_dict() for c in self.citations],
            "unsupported_claim_count": self.unsupported_claim_count,
            "provider_metadata": (
                self.provider_metadata.to_dict() if self.provider_metadata else None
            ),
        }

    def serialize(self) -> str:
        return dumps_stable(self.to_dict())


@dataclass(frozen=True)
class ComparisonUnavailable:
    """Fail-closed outcome: deterministic comparison survives, AI does not."""

    comparison_evidence_id: str
    failure_kind: AnalysisFailureKind
    detail: str
    created_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        stamp = (self.created_at or datetime.now(UTC)).isoformat()
        return {
            "comparison_evidence_id": self.comparison_evidence_id,
            "failure_kind": self.failure_kind.value,
            "detail": self.detail,
            "created_at": stamp,
        }

    def serialize(self) -> str:
        return dumps_stable(self.to_dict())


__all__ = [
    "Claim",
    "EvidenceStatus",
    "AnalysisFailureKind",
    "ComparisonClaim",
    "PriorityChange",
    "RegressionInsight",
    "ResolvedItem",
    "ComparisonAction",
    "ComparisonAssessment",
    "ComparisonUnavailable",
    "ProviderMetadata",
]
