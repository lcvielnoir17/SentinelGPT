"""Unit tests for the report assembler and formatters (SRS Ch10).

The assembler is a pure read step over the database; the formatters
are pure functions over the assembler's output. Together they implement
the format-agnostic invariant: the JSON, CSV, and future PDF exports
of the same scan can never drift into showing inconsistent data.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from src.reporting.assembler import (
    REPORT_SCHEMA_VERSION,
    ReportAssessment,
    ReportDocument,
    ReportEngineSummary,
    ReportFinding,
    ReportScanMetadata,
)
from src.reporting.export_formatters.csv_formatter import (
    CSV_COLUMNS,
    render_csv_report,
)
from src.reporting.export_formatters.json_formatter import render_json_report


def _sample_document() -> ReportDocument:
    scan_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    initiated_by = uuid.UUID("00000000-0000-0000-0000-000000000002")
    finding_id = uuid.UUID("00000000-0000-0000-0000-000000000003")
    evidence_id = uuid.UUID("00000000-0000-0000-0000-000000000004")
    return ReportDocument(
        schema_version=REPORT_SCHEMA_VERSION,
        generated_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        scan=ReportScanMetadata(
            target_hostname="example.test",
            target_normalized_url="https://example.test/",
            scan_id=scan_id,
            scan_profile="standard",
            scan_status="REPORT_READY",
            initiated_by_user_id=initiated_by,
            queued_at=datetime(2026, 1, 1, 11, 0, 0, tzinfo=UTC),
            started_at=datetime(2026, 1, 1, 11, 1, 0, tzinfo=UTC),
            completed_at=datetime(2026, 1, 1, 11, 2, 0, tzinfo=UTC),
        ),
        engines=(
            ReportEngineSummary(
                engine_code="headers-analyzer",
                tool_version_snapshot="1",
                status="SUCCEEDED",
                started_at=datetime(2026, 1, 1, 11, 1, 0, tzinfo=UTC),
                completed_at=datetime(2026, 1, 1, 11, 2, 0, tzinfo=UTC),
                error_message=None,
            ),
        ),
        findings=(
            ReportFinding(
                id=finding_id,
                severity="HIGH",
                category="MISSING_SECURITY_HEADER",
                title="Missing HSTS",
                description="HSTS header is absent",
                evidence="Strict-Transport-Security: (absent)",
                location="https://example.test/",
                recommendation="Add HSTS",
                fingerprint="abc123",
                affected_asset="https://example.test/",
                source_engine_code="headers-analyzer",
                evidence_rows=(
                    {
                        "id": str(evidence_id),
                        "type": "RAW_HEADER",
                        "content": "Strict-Transport-Security: (absent)",
                    },
                ),
                explanation={
                    "finding_id": "abc",
                    "explanation_text": "HSTS is missing.",
                    "validation_status": "fallback_used",
                    "remediation": {
                        "summary": "Add HSTS",
                        "steps": ["Configure header"],
                    },
                },
            ),
        ),
        assessment=ReportAssessment(
            available=True,
            provider="google-genai",
            model="gemini-test",
            prompt_schema_version="v1",
            output_schema_version="v1",
            failure_kind=None,
            unsupported_claim_count=0,
            overall_summary="Scan summary",
            priority="high",
            payload={"findings": {"abc": "data"}},
        ),
        severity_counts={"HIGH": 1, "LOW": 0},
        lifecycle_counts={"NEW": 1},
    )


def test_report_document_to_dict_has_schema_version() -> None:
    """The canonical report carries the schema version in the payload."""
    doc = _sample_document()
    payload = doc.to_dict()
    assert payload["schema_version"] == REPORT_SCHEMA_VERSION
    assert payload["scan"]["target_hostname"] == "example.test"
    assert payload["severity_counts"] == {"HIGH": 1, "LOW": 0}


def test_json_formatter_is_deterministic() -> None:
    """Equal inputs → byte-identical output (checksum-friendly)."""
    a = render_json_report(_sample_document())
    b = render_json_report(_sample_document())
    assert a == b
    parsed = json.loads(a)
    assert parsed["schema_version"] == REPORT_SCHEMA_VERSION


def test_json_formatter_carries_all_findings() -> None:
    """Every finding is serialized; nothing is silently dropped."""
    doc = _sample_document()
    parsed = json.loads(render_json_report(doc))
    assert len(parsed["findings"]) == 1
    finding = parsed["findings"][0]
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "MISSING_SECURITY_HEADER"
    assert finding["explanation"]["validation_status"] == "fallback_used"


def test_csv_formatter_writes_header_and_rows() -> None:
    """CSV output has the fixed column order and one row per finding."""
    doc = _sample_document()
    csv_text = render_csv_report(doc)
    lines = csv_text.splitlines()
    assert lines[0].split(",")[:5] == ["scan_id", "scan_status", "scan_profile", "target_hostname", "finding_id"]
    assert len(lines) == 2  # header + one finding


def test_csv_formatter_columns_are_stable() -> None:
    """Downstream scripts can rely on the exact column order."""
    assert CSV_COLUMNS[:5] == (
        "scan_id",
        "scan_status",
        "scan_profile",
        "target_hostname",
        "finding_id",
    )
    assert "explanation_summary" in CSV_COLUMNS
    assert "remediation_summary" in CSV_COLUMNS


def test_csv_formatter_handles_multiple_findings() -> None:
    """One row per finding, including when explanations differ."""
    doc = _sample_document()
    extra = ReportFinding(
        id=uuid.uuid4(),
        severity="LOW",
        category="EXPOSED_ADMIN_PANEL",
        title="Admin panel at /admin",
        description="",
        evidence="",
        location="https://example.test/admin",
        recommendation="Restrict access",
        fingerprint="def456",
        affected_asset="https://example.test/admin",
        source_engine_code="headers-analyzer",
        evidence_rows=(),
        explanation=None,
    )
    doc = ReportDocument(
        schema_version=doc.schema_version,
        generated_at=doc.generated_at,
        scan=doc.scan,
        engines=doc.engines,
        findings=doc.findings + (extra,),
        assessment=doc.assessment,
        severity_counts=doc.severity_counts,
        lifecycle_counts=doc.lifecycle_counts,
    )
    csv_text = render_csv_report(doc)
    lines = csv_text.splitlines()
    assert len(lines) == 3  # header + two findings
    assert "EXPOSED_ADMIN_PANEL" in csv_text


def test_assessment_can_be_none() -> None:
    """A scan without an AI assessment serializes cleanly to None."""
    doc = ReportDocument(
        schema_version=REPORT_SCHEMA_VERSION,
        generated_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        scan=_sample_document().scan,
        engines=(),
        findings=(),
        assessment=None,
        severity_counts={},
        lifecycle_counts={},
    )
    parsed = json.loads(render_json_report(doc))
    assert parsed["assessment"] is None
    assert parsed["findings"] == []
