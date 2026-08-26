"""Unit tests for the fail-closed AI analysis service (ADR-0008)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from src.domain.scanning.analysis.correlation import build_candidate_groups
from src.domain.scanning.analysis.evidence import EvidenceSet
from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    AnalysisProviderError,
    Assessment,
    AssessmentUnavailable,
)
from src.domain.scanning.analysis.prompts import (
    OUTPUT_SCHEMA_VERSION,
    PROMPT_SCHEMA_VERSION,
)
from src.domain.scanning.analysis.service import AiAnalysisService, ScriptedAnalyzer
from src.domain.scanning.findings import Confidence, Finding, Severity
from src.scanning.engines.http_analysis import HttpAnalysisResult

NOW = datetime(2026, 2, 3, tzinfo=UTC)


def _result() -> HttpAnalysisResult:
    finding = Finding.create(
        category="http.security-headers",
        title="Missing Content-Security-Policy security header",
        description="d",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        location="https://target.example/",
    )
    return HttpAnalysisResult(
        engine_name="http-security-analysis",
        target_hostname="target.example",
        request_scheme="https",
        request_port=443,
        request_path="/",
        status=200,
        redirect_count=0,
        truncated=False,
        content_type="text/html",
        response_bytes=64,
        observations=(),
        findings=(finding,),
        error_kind=None,
        error_detail="",
        engine_version="1",
    )


def _valid_payload() -> dict[str, Any]:
    evidence = EvidenceSet.from_result(_result())
    return {
        "overall_summary": "One low-severity hardening gap.",
        "priority": "low",
        "correlated_groups": [
            {"title": "Headers", "finding_ids": list(evidence.finding_ids), "rationale": "r"}
        ],
        "remediation": [],
        "limitations": [],
        "claims": [],
    }


def _service(response: Any, *, raises: bool = False) -> AiAnalysisService:
    return AiAnalysisService(ScriptedAnalyzer(response, raises=raises), clock=lambda: NOW)


def test_successful_scripted_analysis_returns_assessment_and_same_evidence() -> None:
    evidence = EvidenceSet.from_result(_result())
    result_evidence, outcome = _service(_valid_payload()).analyze(evidence)

    assert result_evidence is evidence  # identity preserved
    assert isinstance(outcome, Assessment)
    assert outcome.evidence_set_id == evidence.evidence_set_id
    assert outcome.overall_summary == "One low-severity hardening gap."
    assert outcome.provider_metadata is not None
    assert outcome.provider_metadata.prompt_schema_version == PROMPT_SCHEMA_VERSION
    assert outcome.provider_metadata.output_schema_version == OUTPUT_SCHEMA_VERSION
    assert outcome.provider_metadata.created_at == NOW


def test_candidate_groups_default_to_deterministic_build() -> None:
    captured: dict[str, tuple] = {}

    class CapturingAnalyzer(ScriptedAnalyzer):
        def analyze(self, evidence_set, candidate_groups, *, system_instructions, user_prompt):  # type: ignore[no-untyped-def]
            captured["groups"] = candidate_groups
            return super().analyze(
                evidence_set,
                candidate_groups,
                system_instructions=system_instructions,
                user_prompt=user_prompt,
            )

    evidence = EvidenceSet.from_result(_result())
    _, outcome = AiAnalysisService(CapturingAnalyzer(_valid_payload()), clock=lambda: NOW).analyze(
        evidence
    )
    assert isinstance(outcome, Assessment)
    assert captured["groups"] == build_candidate_groups(evidence)


@pytest.mark.parametrize(
    ("raised", "expected_kind"),
    [
        (AnalysisProviderError(AnalysisFailureKind.TIMEOUT, "slow"), AnalysisFailureKind.TIMEOUT),
        (
            AnalysisProviderError(AnalysisFailureKind.AUTHENTICATION_FAILED, "bad key"),
            AnalysisFailureKind.AUTHENTICATION_FAILED,
        ),
        (RuntimeError("exploded"), AnalysisFailureKind.UNEXPECTED),
    ],
)
def test_provider_failures_preserve_evidence_fail_closed(
    raised: Exception, expected_kind: AnalysisFailureKind
) -> None:
    evidence = EvidenceSet.from_result(_result())
    snapshot = evidence.serialize()

    service = _service(raised, raises=True)
    _, outcome = service.analyze(evidence)

    assert isinstance(outcome, AssessmentUnavailable)
    assert outcome.failure_kind is expected_kind
    assert outcome.evidence_set_id == evidence.evidence_set_id
    assert outcome.created_at == NOW
    # Deterministic findings survive byte-for-byte.
    assert evidence.serialize() == snapshot
    if expected_kind is AnalysisFailureKind.UNEXPECTED:
        assert "RuntimeError" in outcome.detail
        assert "exploded" not in outcome.detail  # internals not leaked


def test_malformed_response_string_maps_to_malformed() -> None:
    _, outcome = _service("{definitely-not-json").analyze(EvidenceSet.from_result(_result()))
    assert isinstance(outcome, AssessmentUnavailable)
    assert outcome.failure_kind is AnalysisFailureKind.MALFORMED_RESPONSE


def test_schema_invalid_response_maps_to_schema_invalid() -> None:
    bad = {"overall_summary": "", "priority": "nope"}
    _, outcome = _service(bad).analyze(EvidenceSet.from_result(_result()))
    assert isinstance(outcome, AssessmentUnavailable)
    assert outcome.failure_kind is AnalysisFailureKind.SCHEMA_INVALID


def test_unsupported_claims_are_counted_in_accepted_assessment() -> None:
    payload = _valid_payload()
    payload["claims"] = [{"text": "Fabricated claim", "finding_ids": ["ghost-id"], "detail": ""}]
    _, outcome = _service(payload).analyze(EvidenceSet.from_result(_result()))
    assert isinstance(outcome, Assessment)
    assert outcome.unsupported_claim_count == 1
    ghost = next(c for c in outcome.claims if c.status.value == "unsupported")
    assert ghost.finding_ids == ("ghost-id",)


def test_explicit_candidate_groups_override_default_clustering() -> None:
    evidence = EvidenceSet.from_result(_result())
    from src.domain.scanning.analysis.correlation import CandidateGroup

    custom = (
        CandidateGroup(
            group_id="custom",
            category="http.security-headers",
            title="Custom cluster",
            finding_ids=evidence.finding_ids,
        ),
    )
    captured: dict[str, tuple] = {}

    class Capturing(ScriptedAnalyzer):
        def analyze(self, evidence_set, candidate_groups, *, system_instructions, user_prompt):  # type: ignore[no-untyped-def]
            captured["groups"] = candidate_groups
            return super().analyze(
                evidence_set,
                candidate_groups,
                system_instructions=system_instructions,
                user_prompt=user_prompt,
            )

    _, outcome = AiAnalysisService(Capturing(_valid_payload()), clock=lambda: NOW).analyze(
        evidence, candidate_groups=custom
    )
    assert isinstance(outcome, Assessment)
    assert captured["groups"] == custom
