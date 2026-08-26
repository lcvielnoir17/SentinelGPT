"""Unit tests for deterministic candidate correlation (ADR-0008)."""

from __future__ import annotations

from src.domain.scanning.analysis.correlation import build_candidate_groups
from src.domain.scanning.analysis.evidence import EvidenceSet
from src.domain.scanning.findings import Confidence, Finding, Severity
from src.scanning.engines.http_analysis import HttpAnalysisResult


def _finding(title: str, category: str) -> Finding:
    return Finding.create(
        category=category,
        title=title,
        description=f"{title}",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        location="https://target.example/",
    )


def _result(findings: tuple[Finding, ...]) -> HttpAnalysisResult:
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
        findings=findings,
        error_kind=None,
        error_detail="",
        engine_version="1",
    )


def _evidence(findings: tuple[Finding, ...]) -> EvidenceSet:
    return EvidenceSet.from_result(_result(findings))


def test_seed_groups_cover_the_four_known_families() -> None:
    evidence = _evidence(
        (
            _finding("Missing CSP", "http.security-headers"),
            _finding("Missing HSTS", "http.security-headers"),
            _finding("Cookie without Secure", "http.cookies"),
            _finding("Transport posture issue", "http.transport"),
            _finding("Server header exposed", "http.server-info"),
        )
    )
    groups = build_candidate_groups(evidence)
    titles = {g.title for g in groups}
    assert {
        "Missing security-header family",
        "Cookie hygiene cluster",
        "Transport / TLS posture",
        "Server-information disclosure",
    } <= titles

    header_group = next(g for g in groups if g.category == "http.security-headers")
    expected_ids = {f.id for f in evidence.findings if f.category == "http.security-headers"}
    assert set(header_group.finding_ids) == expected_ids


def test_unknown_category_gets_catch_all_cluster() -> None:
    evidence = _evidence((_finding("Odd finding", "custom.category"),))
    groups = build_candidate_groups(evidence)
    assert len(groups) == 1
    assert groups[0].category == "custom.category"
    assert groups[0].finding_ids[0] == evidence.findings[0].id


def test_empty_evidence_yields_no_groups() -> None:
    assert build_candidate_groups(_evidence(())) == ()


def test_grouping_is_deterministic_and_sorted() -> None:
    findings = (
        _finding("Missing CSP", "http.security-headers"),
        _finding("Server header exposed", "http.server-info"),
        _finding("Cookie without Secure", "http.cookies"),
    )
    g1 = build_candidate_groups(_evidence(findings))
    g2 = build_candidate_groups(_evidence(findings))
    assert g1 == g2
    assert [g.group_id for g in g1] == sorted(g.group_id for g in g1)


def test_no_invented_finding_ids() -> None:
    evidence = _evidence(
        (
            _finding("Missing CSP", "http.security-headers"),
            _finding("Server header exposed", "http.server-info"),
        )
    )
    known = set(evidence.finding_ids)
    for group in build_candidate_groups(evidence):
        assert set(group.finding_ids) <= known


def test_to_dict_shape() -> None:
    evidence = _evidence((_finding("Missing CSP", "http.security-headers"),))
    group = build_candidate_groups(evidence)[0]
    payload = group.to_dict()
    assert set(payload) == {"group_id", "category", "title", "finding_ids"}
