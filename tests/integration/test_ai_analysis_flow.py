"""End-to-end Phase 6 flow: engine → evidence → prompts → analyzer → validator.

Runs the REAL Phase 5 chain against the seeded local webapp, converts the
result into an EvidenceSet, and drives the analysis service with a
ScriptedAnalyzer whose payload references REAL finding IDs captured from the
live run — proving traceability end-to-end without any external AI call.

A second test exercises the optional live Gemini path, auto-skipping unless
GEMINI_API_KEY is present in the environment; it sends only serialized
evidence and asserts a controlled outcome (never an exception).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest
from tests.integration.test_http_analysis_live import _run_engine

from src.domain.scanning.analysis.correlation import build_candidate_groups
from src.domain.scanning.analysis.evidence import EvidenceSet
from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    AnalysisProviderError,
    AssessmentUnavailable,
    EvidenceStatus,
)
from src.domain.scanning.analysis.prompts import (
    OUTPUT_SCHEMA_VERSION,
    PROMPT_SCHEMA_VERSION,
    SYSTEM_INSTRUCTIONS_V1,
    build_user_prompt,
)
from src.domain.scanning.analysis.service import AiAnalysisService, ScriptedAnalyzer
from src.domain.scanning.findings import Confidence, Severity

pytestmark = pytest.mark.integration

_FIXED_NOW = datetime(2026, 6, 1, tzinfo=UTC)


def _assessment_payload_for(evidence: EvidenceSet) -> dict:
    ids = list(evidence.finding_ids)
    return {
        "overall_summary": "Hardening gaps found on a minimal seeded webapp.",
        "priority": "low",
        "correlated_groups": [
            {"title": "Header hardening", "finding_ids": ids, "rationale": "same response"}
        ],
        "remediation": [
            {
                "title": "Add security headers",
                "detail": "See findings",
                "finding_ids": ids[:2],
            }
        ],
        "limitations": ["Single response analyzed"],
        "claims": [
            {
                "text": "Security headers are absent",
                "finding_ids": ids[:2],
                "status": "supported",
                "detail": "",
            }
        ],
    }


def test_engine_to_ai_flow_end_to_end(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result, _sandbox = _run_engine(make_sandbox_for, webapp, "webapp.test")

    # ---- deterministic half -------------------------------------------------
    evidence = EvidenceSet.from_result(result)
    groups = build_candidate_groups(evidence)

    prompt = build_user_prompt(evidence, groups)
    assert PROMPT_SCHEMA_VERSION == "v1" and OUTPUT_SCHEMA_VERSION == "v1"
    assert json.loads(prompt)["evidence_set"]["evidence_set_id"] == evidence.evidence_set_id

    # ---- AI half with REAL finding IDs --------------------------------------
    service = AiAnalysisService(
        ScriptedAnalyzer(_assessment_payload_for(evidence)), clock=lambda: _FIXED_NOW
    )
    out_evidence, outcome = service.analyze(evidence)

    assert out_evidence is evidence  # identity survives the round trip
    assert not isinstance(outcome, AssessmentUnavailable)
    assert outcome.evidence_set_id == evidence.evidence_set_id
    assert outcome.unsupported_claim_count == 0
    assert all(set(g.finding_ids) <= set(evidence.finding_ids) for g in outcome.correlated_groups)
    assert {c.status for c in outcome.claims} == {EvidenceStatus.SUPPORTED}


def test_ai_failure_mid_flow_preserves_deterministic_findings(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result, _ = _run_engine(make_sandbox_for, webapp, "webapp.test")
    evidence = EvidenceSet.from_result(result)
    snapshot = evidence.serialize()

    failing = ScriptedAnalyzer(
        AnalysisProviderError(AnalysisFailureKind.TIMEOUT, "upstream"), raises=True
    )
    _, outcome = AiAnalysisService(failing, clock=lambda: _FIXED_NOW).analyze(evidence)

    assert isinstance(outcome, AssessmentUnavailable)
    assert outcome.failure_kind is AnalysisFailureKind.TIMEOUT
    assert outcome.evidence_set_id == evidence.evidence_set_id
    assert evidence.serialize() == snapshot


def test_fabricated_finding_ids_are_marked_unsupported_live(
    docker_runtime, daemon_alive, webapp, make_sandbox_for
) -> None:
    result, _ = _run_engine(make_sandbox_for, webapp, "webapp.test")
    evidence = EvidenceSet.from_result(result)

    fabricated = dict(_assessment_payload_for(evidence))
    fabricated["claims"] = [
        {
            "text": "The server is vulnerable to X",
            "finding_ids": ["fabricated-id-1"],
            "status": "supported",  # provider lies about support
            "detail": "",
        }
    ]
    _, outcome = AiAnalysisService(ScriptedAnalyzer(fabricated)).analyze(evidence)

    vulnerable = next(c for c in outcome.claims if "vulnerable to X" in c.text)
    assert vulnerable.status is EvidenceStatus.UNSUPPORTED
    assert outcome.unsupported_claim_count >= 1


# --------------------------------------------------------------------------- #
# Optional LIVE Gemini check (opt-in; skips without GEMINI_API_KEY).           #
# Sends ONLY serialized seeded evidence — never a target URL or scanner state. #
# --------------------------------------------------------------------------- #


def _seeded_engine_result():
    from src.domain.scanning.findings import Finding
    from src.scanning.engines.http_analysis import HttpAnalysisResult as R

    finding = Finding.create(
        category="http.security-headers",
        title="Missing Content-Security-Policy security header",
        description="Seeded evidence for the opt-in live AI check.",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        location="https://seeded.example/",
    )
    return R(
        engine_name="http-security-analysis",
        target_hostname="seeded.example",
        request_scheme="https",
        request_port=443,
        request_path="/",
        status=200,
        redirect_count=0,
        truncated=False,
        content_type="text/html",
        response_bytes=128,
        observations=(),
        findings=(finding,),
        error_kind=None,
        error_detail="",
        engine_version="1",
    )


def test_optional_live_gemini_analyzes_seeded_evidence_only() -> None:
    from src.infrastructure.ai.gemini_provider import GeminiEvidenceAnalyzer

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        pytest.skip("GEMINI_API_KEY not set - live Gemini test skipped")

    result = _seeded_engine_result()
    evidence = EvidenceSet.from_result(result)
    groups = build_candidate_groups(evidence)
    user_prompt = build_user_prompt(evidence, groups)

    analyzer = GeminiEvidenceAnalyzer(api_key=api_key)
    raw = analyzer.analyze(
        evidence,
        groups,
        system_instructions=SYSTEM_INSTRUCTIONS_V1,
        user_prompt=user_prompt,
    )

    from src.domain.scanning.analysis.validator import validate_analysis_response

    validation = validate_analysis_response(
        raw,
        evidence,
        provider_metadata_base={
            "provider": analyzer.provider,
            "model": analyzer.model,
            "model_version": analyzer.model_version,
            "prompt_schema_version": PROMPT_SCHEMA_VERSION,
            "output_schema_version": OUTPUT_SCHEMA_VERSION,
        },
        now=datetime.now(UTC),
    )
    # Either outcome is acceptable live; what matters is that it is CONTROLLED
    # (a validated assessment or a typed failure), never an unguarded raise.
    assert validation.accepted or validation.failure_kind is not None
