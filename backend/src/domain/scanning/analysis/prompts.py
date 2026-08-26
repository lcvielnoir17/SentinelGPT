"""Versioned prompt assembly for AI analysis (ADR-0008).

The prompt is built exclusively from the canonical evidence payload and
deterministic candidate groups. Changing these instructions requires
bumping ``PROMPT_SCHEMA_VERSION`` so assessments remain interpretable
across versions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.domain.scanning.findings import dumps_stable

if TYPE_CHECKING:
    from src.domain.scanning.analysis.correlation import CandidateGroup
    from src.domain.scanning.analysis.evidence import EvidenceSet

PROMPT_SCHEMA_VERSION = "v1"
OUTPUT_SCHEMA_VERSION = "v1"

SYSTEM_INSTRUCTIONS_V1 = """\
You are a security-analysis assistant for SentinelGPT.

You will receive ONE JSON document containing:
  * evidence_set: deterministic findings (and observations) produced by a
    passive HTTP analysis engine, plus request/transport metadata;
  * candidate_groups: pre-computed finding-ID clusters.

Hard rules:
1. Use ONLY the supplied evidence. Never invent findings, hosts,
   headers, cookies, vulnerabilities, CVEs, or CWEs.
2. Do not invent finding IDs. Every claim MUST reference existing finding
   IDs from the evidence set.
3. Distinguish evidence-backed conclusions from inference. If you reason
   beyond the literal findings, mark that claim INFERRED; if you cannot
   anchor it to any supplied ID, mark it UNSUPPORTED.
4. Preserve severity/confidence semantics: do not escalate a LOW/HIGH
   finding into CRITICAL without new evidence — and you have none.
5. Return remediation guidance that maps to specific findings where possible.
6. State limitations explicitly when evidence is thin or absent.
7. Output ONLY one JSON object matching this schema, with no prose around it:

{
  "overall_summary": string,
  "priority": "info" | "low" | "medium" | "high" | "critical",
  "correlated_groups": [
    {"title": string, "finding_ids": [string], "rationale": string}
  ],
  "remediation": [
    {"title": string, "detail": string, "finding_ids": [string]}
  ],
  "limitations": [string],
  "claims": [
    {"text": string, "finding_ids": [string],
     "status": "supported" | "inferred" | "unsupported",
     "detail": string}
  ]
}

Claim "status" semantics: use "supported" when the statement restates what
the referenced findings literally record; "inferred" when you reason beyond
the literal findings; "unsupported" only for statements you cannot anchor.
The validator independently re-checks every reference and will force
"unsupported" on unknown IDs regardless of what you declare.

Any finding_ids you output that do not exist in the evidence set will be
marked UNSUPPORTED and counted against your response.
"""


def build_user_prompt(
    evidence_set: EvidenceSet,
    candidate_groups: tuple[CandidateGroup, ...],
) -> str:
    """Deterministic user payload: canonical evidence + seed groups."""
    payload = {
        "prompt_schema_version": PROMPT_SCHEMA_VERSION,
        "output_schema_version": OUTPUT_SCHEMA_VERSION,
        "evidence_set": evidence_set.to_dict(),
        "candidate_groups": [g.to_dict() for g in candidate_groups],
    }
    return dumps_stable(payload)


def build_prompts(
    evidence_set: EvidenceSet,
    candidate_groups: tuple[CandidateGroup, ...],
) -> tuple[str, str]:
    """Return (system_instructions, user_prompt) for schema v1."""
    return SYSTEM_INSTRUCTIONS_V1, build_user_prompt(evidence_set, candidate_groups)
