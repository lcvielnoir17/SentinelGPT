"""Unit tests for versioned prompt assembly (ADR-0008)."""

from __future__ import annotations

import json

from src.domain.scanning.analysis.correlation import build_candidate_groups
from src.domain.scanning.analysis.evidence import EvidenceSet
from src.domain.scanning.analysis.prompts import (
    OUTPUT_SCHEMA_VERSION,
    PROMPT_SCHEMA_VERSION,
    SYSTEM_INSTRUCTIONS_V1,
    build_prompts,
    build_user_prompt,
)
from src.domain.scanning.findings import Confidence, Finding, Severity
from src.scanning.engines.http_analysis import HttpAnalysisResult


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


def _evidence() -> EvidenceSet:
    return EvidenceSet.from_result(_result())


def test_schema_versions_are_v1() -> None:
    assert PROMPT_SCHEMA_VERSION == "v1"
    assert OUTPUT_SCHEMA_VERSION == "v1"


def test_user_prompt_is_deterministic_json_containing_evidence_and_groups() -> None:
    evidence = _evidence()
    groups = build_candidate_groups(evidence)

    first = build_user_prompt(evidence, groups)
    second = build_user_prompt(evidence, groups)
    assert first == second

    parsed = json.loads(first)
    assert parsed["prompt_schema_version"] == "v1"
    assert parsed["output_schema_version"] == "v1"
    assert parsed["evidence_set"]["evidence_set_id"] == evidence.evidence_set_id
    assert parsed["candidate_groups"][0]["finding_ids"] == list(groups[0].finding_ids)


def test_system_instructions_encode_hallucination_controls() -> None:
    lowered = SYSTEM_INSTRUCTIONS_V1.lower()
    assert "only the supplied evidence" in lowered
    assert "never invent findings" in lowered
    assert "do not invent finding ids" in lowered
    assert "inferred" in lowered and "unsupported" in lowered
    assert "json" in lowered
    # The prompt must not smuggle network capability or target access.
    assert "httpx" not in lowered
    assert "socket" not in lowered
    assert "subprocess" not in lowered


def test_build_prompts_pairs_system_and_user() -> None:
    system, user = build_prompts(_evidence(), ())
    assert system == SYSTEM_INSTRUCTIONS_V1
    assert json.loads(user)["evidence_set"]["findings"][0]["title"].startswith("Missing")


def test_different_evidence_changes_prompt_but_not_schema_version() -> None:
    other = EvidenceSet.from_result(
        HttpAnalysisResult(
            engine_name="http-security-analysis",
            target_hostname="other.example",
            request_scheme="http",
            request_port=80,
            request_path="/x",
            status=404,
            redirect_count=0,
            truncated=True,
            content_type="text/plain",
            response_bytes=8,
            observations=(),
            findings=(),
            error_kind=None,
            error_detail="",
            engine_version="1",
        )
    )
    prompt_a = build_user_prompt(_evidence(), ())
    prompt_b = build_user_prompt(other, ())
    assert prompt_a != prompt_b
    assert json.loads(prompt_b)["prompt_schema_version"] == PROMPT_SCHEMA_VERSION
