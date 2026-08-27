"""Per-finding AI explanation model (SRS Ch9 §4).

A per-finding explanation is the unit a human reviewer actually reads: one
explanation describes one finding, anchored to specific evidence rows.

The schema mirrors the SRS:

* ``finding_id`` is the canonical finding the explanation describes.
* ``claims`` is the structured list of factual assertions, each bound
  to specific evidence references — this is the validator's source of
  truth, NOT the rendered prose.
* ``explanation_text`` is a deterministic render of the validated claims
  into prose, for display. The claims array is authoritative.
* ``remediation`` is the human-readable fix guidance.
* ``validation_status`` is one of:

  - ``VALIDATED``      — every claim's evidence references were checked
    against the actual evidence rows.
  - ``FALLBACK_USED``  — the AI was unavailable, timed out, or produced
    output that failed validation; the explanation is a deterministic
    template (no AI text appears here).
  - ``PENDING``        — the AI call is in flight; never persisted.

Groundedness invariant: this module NEVER introduces evidence IDs that
were not supplied in the evidence set. That check belongs in the
validator; this module only carries the data.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from src.domain.scanning.findings import dumps_stable


class ExplanationStatus(enum.StrEnum):
    """How this explanation was produced (visible to the user)."""

    VALIDATED = "validated"
    FALLBACK_USED = "fallback_used"
    PENDING = "pending"


@dataclass(frozen=True)
class EvidenceReference:
    """A pointer from a claim to one evidence row that backs it."""

    evidence_id: str
    snippet: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"evidence_id": self.evidence_id, "snippet": self.snippet}


@dataclass(frozen=True)
class Claim:
    """One factual assertion bound to the evidence it relies on.

    ``text`` is the assertion (one sentence, deterministic). ``references``
    are the evidence rows the validator confirmed back the assertion. A
    claim with no references is INFERRED at best and UNSUPPORTED at worst.
    """

    text: str
    references: tuple[EvidenceReference, ...] = field(default=())

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.text,
            "references": [r.to_dict() for r in self.references],
        }


@dataclass(frozen=True)
class Remediation:
    """Human-readable fix guidance for a finding."""

    summary: str
    steps: tuple[str, ...] = field(default=())
    stack_specific_notes: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "steps": list(self.steps),
            "stack_specific_notes": self.stack_specific_notes,
        }


@dataclass(frozen=True)
class FindingExplanation:
    """One explanation for one finding (SRS Ch9 §4 schema).

    The same `finding_id` must NEVER carry two explanations — the database
    enforces uniqueness; the application enforces "regenerate" creates a
    new scan that re-detects the finding rather than mutating this row.
    """

    finding_id: str
    claims: tuple[Claim, ...]
    explanation_text: str
    severity_rationale: str
    remediation: Remediation
    validation_status: ExplanationStatus
    prompt_template_version: str
    model_name: str
    model_version: str
    provider: str
    confidence_note: str = ""
    is_nondeterministic: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "claims": [c.to_dict() for c in self.claims],
            "explanation_text": self.explanation_text,
            "severity_rationale": self.severity_rationale,
            "remediation": self.remediation.to_dict(),
            "validation_status": self.validation_status.value,
            "prompt_template_version": self.prompt_template_version,
            "model": {
                "provider": self.provider,
                "name": self.model_name,
                "version": self.model_version,
                "nondeterministic": self.is_nondeterministic,
            },
            "confidence_note": self.confidence_note,
        }

    def serialize(self) -> str:
        return dumps_stable(self.to_dict())


def render_explanation_text(claims: tuple[Claim, ...]) -> str:
    """Deterministically render the validated claims into prose.

    The prose is a view over the claims array, never the other way around
    (SRS Ch9 §4, second-to-last bullet). The validator checks the claims;
    a downstream renderer checks the prose display.
    """
    if not claims:
        return "No evidence-validated claims are available for this finding."
    sentences = [claim.text.strip() for claim in claims if claim.text.strip()]
    return " ".join(sentences)


__all__ = [
    "Claim",
    "EvidenceReference",
    "ExplanationStatus",
    "FindingExplanation",
    "Remediation",
    "render_explanation_text",
]
