"""Unit tests for the immutable EvidenceSet (ADR-0008)."""

from __future__ import annotations

import dataclasses
import ipaddress

import pytest

from src.domain.scanning.analysis.evidence import EVIDENCE_SCHEMA_VERSION, EvidenceSet
from src.domain.scanning.findings import Confidence, Finding, Observation, Severity
from src.scanning.engines.http_analysis import HttpAnalysisResult

PIN = "93.184.216.34"


def _finding(title: str, category: str = "http.security-headers") -> Finding:
    return Finding.create(
        category=category,
        title=title,
        description=f"{title} description",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        location="https://target.example/",
    )


def _observation(title: str) -> Observation:
    return Observation.create(category="http.transport", title=title, detail=title.lower())


def _result(
    *,
    findings: tuple[Finding, ...] | None = None,
    observations: tuple[Observation, ...] = (),
    elapsed_ms: float = 5.0,
    hostname: str = "target.example",
    status: int | None = 200,
) -> HttpAnalysisResult:
    return HttpAnalysisResult(
        engine_name="http-security-analysis",
        target_hostname=hostname,
        request_scheme="https",
        request_port=443,
        request_path="/",
        status=status,
        redirect_count=0,
        truncated=False,
        content_type="text/html",
        response_bytes=128,
        observations=observations or (_observation("Transport posture"),),
        findings=findings
        if findings is not None
        else (
            _finding("Missing Content-Security-Policy security header"),
            _finding("Missing X-Content-Type-Options security header"),
        ),
        error_kind=None,
        error_detail="",
        engine_version="1",
    )


def test_deterministic_evidence_set_id_and_serialization() -> None:
    a = EvidenceSet.from_result(_result())
    b = EvidenceSet.from_result(_result())
    assert a.evidence_set_id == b.evidence_set_id
    assert a.serialize() == b.serialize()
    assert len(a.evidence_set_id) == 16


def test_elapsed_timing_is_excluded_from_evidence() -> None:
    fast = EvidenceSet.from_result(_result(elapsed_ms=1.0))
    slow = EvidenceSet.from_result(_result(elapsed_ms=9_999.0))
    assert fast.evidence_set_id == slow.evidence_set_id


def test_changed_finding_changes_evidence_id() -> None:
    base = EvidenceSet.from_result(_result())
    changed = EvidenceSet.from_result(
        _result(
            findings=(
                _finding("Missing Content-Security-Policy security header"),
                _finding("Different finding entirely"),
            )
        )
    )
    assert base.evidence_set_id != changed.evidence_set_id


def test_findings_sorted_and_lookup_works() -> None:
    evidence = EvidenceSet.from_result(_result())
    ids = [f.id for f in evidence.findings]
    assert ids == sorted(ids)
    first = evidence.findings[0]
    assert evidence.get_finding(first.id) is first
    assert evidence.has_finding(first.id)
    assert evidence.get_finding("nonexistent") is None
    assert not evidence.has_finding("nonexistent")
    assert evidence.finding_ids == tuple(ids)


def test_evidence_is_immutable() -> None:
    evidence = EvidenceSet.from_result(_result())
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.target_hostname = "evil.example"  # type: ignore[misc]
    with pytest.raises(TypeError):
        evidence.findings[0] = None  # type: ignore[index]
    # The ID index is a read-only mapping: fabricated references cannot be
    # injected to smuggle unsupported claims past the validator.
    with pytest.raises(TypeError):
        evidence._finding_index["fabricated-id"] = evidence.findings[0]  # type: ignore[index]


def test_schema_version_and_metadata_captured() -> None:
    evidence = EvidenceSet.from_result(_result(status=503))
    assert evidence.schema_version == EVIDENCE_SCHEMA_VERSION
    assert evidence.engine_name == "http-security-analysis"
    assert evidence.engine_version == "1"
    assert evidence.target_hostname == "target.example"
    assert evidence.status == 503
    assert evidence.request_scheme == "https"
    assert ipaddress.ip_address(PIN)  # keep import meaningful for typing tests


def test_serialization_contains_canonical_payload() -> None:
    evidence = EvidenceSet.from_result(_result())
    serialized = evidence.serialize()
    assert evidence.evidence_set_id in serialized
    assert "sgpt.evidence.v1" in serialized
    assert "Missing X-Content-Type-Options security header" in serialized
