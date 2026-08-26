"""AI correlation & evidence analysis layer (ADR-0008).

Compute-only: consumes deterministic Phase 5 findings, produces validated
AI assessments or typed failures. Contains NO network/process capability —
providers live in ``src/infrastructure/ai/`` behind the EvidenceAnalyzer
protocol.
"""

from src.domain.scanning.analysis.correlation import CandidateGroup, build_candidate_groups
from src.domain.scanning.analysis.evidence import EVIDENCE_SCHEMA_VERSION, EvidenceSet
from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    AnalysisProviderError,
    Assessment,
    AssessmentUnavailable,
    Claim,
    CorrelatedGroup,
    EvidenceStatus,
    ProviderMetadata,
    RemediationItem,
)
from src.domain.scanning.analysis.prompts import (
    OUTPUT_SCHEMA_VERSION,
    PROMPT_SCHEMA_VERSION,
)
from src.domain.scanning.analysis.service import (
    AiAnalysisService,
    EvidenceAnalyzer,
    ScriptedAnalyzer,
)

__all__ = [
    "OUTPUT_SCHEMA_VERSION",
    "PROMPT_SCHEMA_VERSION",
    "EVIDENCE_SCHEMA_VERSION",
    "AiAnalysisService",
    "AnalysisFailureKind",
    "AnalysisProviderError",
    "Assessment",
    "AssessmentUnavailable",
    "CandidateGroup",
    "Claim",
    "CorrelatedGroup",
    "EvidenceAnalyzer",
    "EvidenceSet",
    "EvidenceStatus",
    "ProviderMetadata",
    "RemediationItem",
    "ScriptedAnalyzer",
    "build_candidate_groups",
]
