"""Unit tests for the AI response validator (ADR-0008 integrity boundary)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from src.domain.scanning.analysis.evidence import EvidenceSet
from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    EvidenceStatus,
)
from src.domain.scanning.analysis.validator import validate_analysis_response
from src.domain.scanning.findings import Confidence, Finding, Severity
from src.scanning.engines.http_analysis import HttpAnalysisResult

NOW = datetime(2026, 1, 1, tzinfo=UTC)
META = {
    "provider": "scripted",
    "model": "scripted-v1",
    "model_version": "1",
    "prompt_schema_version": "v1",
    "output_schema_version": "v1",
}


def _result() -> HttpAnalysisResult:
    finding = Finding.create(
        category="http.security-headers",
        title="Missing Content-Security-Policy security header",
        description="d",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        location="https://target.example/",
    )
    other = Finding.create(
        category="http.cookies",
        title="Cookies without the Secure attribute",
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
        findings=(finding, other),
        error_kind=None,
        error_detail="",
        engine_version="1",
    )


def _evidence() -> EvidenceSet:
    return EvidenceSet.from_result(_result())


def _real_ids() -> tuple[str, str]:
    evidence = _evidence()
    return evidence.findings[0].id, evidence.findings[1].id


def _valid_payload() -> dict:
    csp_id, cookie_id = _real_ids()
    return {
        "overall_summary": "Two low-severity hardening gaps detected.",
        "priority": "low",
        "correlated_groups": [
            {
                "title": "Header hardening family",
                "finding_ids": [csp_id],
                "rationale": "Same response, same fix pattern.",
            }
        ],
        "remediation": [
            {"title": "Add CSP", "detail": "default-src 'self'", "finding_ids": [csp_id]}
        ],
        "limitations": ["Single response analyzed"],
        "claims": [
            {
                "text": "CSP is absent",
                "finding_ids": [csp_id],
                "detail": "direct",
                "status": "supported",
            },
            {
                "text": "Likely static site",
                "finding_ids": [cookie_id],
                "detail": "guess beyond literal findings",
                "status": "inferred",
            },
        ],
    }


def test_valid_response_is_accepted_with_metadata() -> None:
    result = validate_analysis_response(
        _valid_payload(), _evidence(), provider_metadata_base=META, now=NOW
    )
    assert result.accepted and result.assessment is not None
    assessment = result.assessment
    assert assessment.evidence_set_id == _evidence().evidence_set_id
    assert assessment.priority is Severity.LOW
    assert assessment.unsupported_claim_count == 0
    assert assessment.provider_metadata is not None
    assert assessment.provider_metadata.nondeterministic is True
    assert assessment.provider_metadata.created_at == NOW
    statuses = {c.text: c.status for c in assessment.claims}
    assert statuses["CSP is absent"] is EvidenceStatus.SUPPORTED
    assert statuses["Likely static site"] is EvidenceStatus.INFERRED


def test_string_payload_is_parsed_and_accepted() -> None:
    result = validate_analysis_response(
        json.dumps(_valid_payload()), _evidence(), provider_metadata_base=META, now=NOW
    )
    assert result.accepted


def test_malformed_json_fails_closed() -> None:
    result = validate_analysis_response(
        "{not json", _evidence(), provider_metadata_base=META, now=NOW
    )
    assert not result.accepted
    assert result.failure_kind is AnalysisFailureKind.MALFORMED_RESPONSE


def test_non_object_payload_rejected() -> None:
    result = validate_analysis_response(["list"], _evidence(), provider_metadata_base=META, now=NOW)
    assert not result.accepted
    assert result.failure_kind is AnalysisFailureKind.MALFORMED_RESPONSE


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p.pop("overall_summary"),
        lambda p: p.update(priority="catastrophic"),
        lambda p: p.update(correlated_groups="not-a-list"),
        lambda p: p["correlated_groups"].append({"title": ""}),
        lambda p: p["remediation"].append("string-not-object"),
        lambda p: p.update(claims={"not": "a-list"}),
    ],
)
def test_schema_violations_fail_closed(mutator) -> None:  # type: ignore[no-untyped-def]
    payload = _valid_payload()
    mutator(payload)
    result = validate_analysis_response(payload, _evidence(), provider_metadata_base=META, now=NOW)
    assert not result.accepted
    assert result.failure_kind is AnalysisFailureKind.SCHEMA_INVALID
    assert result.errors


def test_oversized_bytes_rejected_as_limit_exceeded() -> None:
    huge = b'{"pad":"' + b"x" * 300_000 + b'"}'
    result = validate_analysis_response(huge, _evidence(), provider_metadata_base=META, now=NOW)
    assert not result.accepted
    assert result.failure_kind is AnalysisFailureKind.LIMIT_EXCEEDED


def test_unknown_group_reference_marked_unsupported_and_dropped() -> None:
    csp_id, cookie_id = _real_ids()
    payload = _valid_payload()
    payload["correlated_groups"] = [
        {
            "title": "Phantom cluster",
            "finding_ids": [csp_id, "fabricated-id"],
            "rationale": "r",
        },
        {
            "title": "Fully phantom",
            "finding_ids": ["ghost-1", "ghost-2"],
            "rationale": "r",
        },
    ]
    result = validate_analysis_response(payload, _evidence(), provider_metadata_base=META, now=NOW)
    assert result.accepted  # valid claims remain usable...
    assessment = result.assessment
    assert assessment is not None
    assert assessment.unsupported_claim_count == 3  # 2 unknowns + dropped group
    assert all(g.title != "Fully phantom" for g in assessment.correlated_groups)
    kept = next(g for g in assessment.correlated_groups if g.title == "Phantom cluster")
    assert kept.finding_ids == (csp_id,)
    unsupported_statuses = {c.status for c in result.unsupported_claims}
    assert unsupported_statuses == {EvidenceStatus.UNSUPPORTED}
    assert cookie_id  # silence unused in this variant


def test_unknown_claim_reference_becomes_unsupported_claim() -> None:
    payload = _valid_payload()
    payload["claims"] = [
        {"text": "Server is vulnerable to X", "finding_ids": ["nope"], "detail": ""}
    ]
    result = validate_analysis_response(payload, _evidence(), provider_metadata_base=META, now=NOW)
    assert result.accepted
    assessment = result.assessment
    assert assessment is not None
    assert assessment.unsupported_claim_count >= 1
    vulnerable = next(c for c in assessment.claims if "vulnerable" in c.text)
    assert vulnerable.status is EvidenceStatus.UNSUPPORTED


def test_validator_never_mutates_evidence_set() -> None:
    evidence = _evidence()
    snapshot = evidence.serialize()
    validate_analysis_response(_valid_payload(), evidence, provider_metadata_base=META, now=NOW)
    bad = {"overall_summary": "x"}
    validate_analysis_response(bad, evidence, provider_metadata_base=META, now=NOW)
    assert evidence.serialize() == snapshot


def test_assessment_id_deterministic_for_identical_input() -> None:
    r1 = validate_analysis_response(
        _valid_payload(), _evidence(), provider_metadata_base=META, now=NOW
    )
    r2 = validate_analysis_response(
        json.loads(json.dumps(_valid_payload())),
        _evidence(),
        provider_metadata_base=META,
        now=NOW,
    )
    assert r1.assessment is not None and r2.assessment is not None
    assert r1.assessment.assessment_id == r2.assessment.assessment_id
