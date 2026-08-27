"""Regression tests for the per-finding fallback payload builder.

This code path runs at scan-completion time. If it ever emits a finding
without an explanation, the per-finding API endpoint starts returning
empty bodies to the user — a UX regression AND a violation of SRS
Ch2 §11's "never silently present incomplete data" principle.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.domain.scanning.findings import Confidence, Finding, Severity
from src.domain.scans.scan_service import ScanService


@dataclass
class _FakeFinding:
    id: str
    category: str
    title: str = ""
    description: str = ""
    evidence: str = ""
    location: str = ""
    recommendation: str = ""
    severity: Severity = Severity.LOW
    confidence: Confidence = Confidence.HIGH


def test_per_finding_fallback_payload_covers_every_finding() -> None:
    """Every finding in the result must have a non-empty fallback entry."""
    result = type("R", (), {})()
    result.findings = (
        Finding.create(
            category="MISSING_SECURITY_HEADER",
            title="Missing HSTS",
            description="",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
        ),
        Finding.create(
            category="KNOWN_CVE",
            title="CVE-2024-1234 something",
            description="",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        ),
    )

    payload = ScanService._build_per_finding_fallback_payload(result)

    assert set(payload) == {f.id for f in result.findings}
    for finding in result.findings:
        entry = payload[finding.id]
        assert entry["finding_id"] == finding.id
        assert entry["validation_status"] == "fallback_used"
        assert entry["explanation_text"]
        assert entry["claims"]


def test_per_finding_fallback_payload_handles_empty_findings() -> None:
    """A scan with zero findings produces an empty payload, not an error."""
    result = type("R", (), {})()
    result.findings = ()
    assert ScanService._build_per_finding_fallback_payload(result) == {}


def test_per_finding_fallback_payload_uses_deterministic_template() -> None:
    """The fallback text is the template, not anything from the AI layer."""
    result = type("R", (), {})()
    result.findings = (
        Finding.create(
            category="EXPOSED_ADMIN_PANEL",
            title="Admin panel at /admin",
            description="",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        ),
    )
    payload = ScanService._build_per_finding_fallback_payload(result)
    finding = result.findings[0]
    text = payload[finding.id]["explanation_text"]
    # The template's language for EXPOSED_ADMIN_PANEL is fixed.
    assert "administrative interface" in text
    assert "publicly exposed" in text


def test_per_finding_fallback_payload_does_not_include_ai_metadata() -> None:
    """Fallback entries must NEVER claim an AI provider produced them."""
    result = type("R", (), {})()
    result.findings = (
        Finding.create(
            category="WEAK_CIPHER",
            title="Weak cipher",
            description="",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
        ),
    )
    payload = ScanService._build_per_finding_fallback_payload(result)
    entry = payload[result.findings[0].id]
    assert entry["model"]["provider"] == "template"
    assert entry["model"]["nondeterministic"] is False
