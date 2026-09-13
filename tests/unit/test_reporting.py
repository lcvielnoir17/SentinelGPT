"""Unit tests for the report assembler and formatters (SRS Ch10).

The assembler is a pure read step over the database; the formatters
are pure functions over the assembler's output. Together they implement
the format-agnostic invariant: the JSON, CSV, and PDF exports
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
    assert lines[0].split(",")[:5] == [
        "scan_id",
        "scan_status",
        "scan_profile",
        "target_hostname",
        "finding_id",
    ]
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


def test_csv_neutralizes_formula_cells() -> None:
    """Hostile field content must not survive as executable spreadsheet formulas."""
    import csv as csv_module
    import io

    from src.reporting.assembler import ReportScanMetadata
    from src.reporting.export_formatters.csv_formatter import _neutralize_formula

    assert _neutralize_formula('=HYPERLINK("http://evil")') == '\'=HYPERLINK("http://evil")'
    assert _neutralize_formula("+2+3") == "'+2+3"
    assert _neutralize_formula("-2+3") == "'-2+3"
    assert _neutralize_formula("@SUM(A1:A2)") == "'@SUM(A1:A2)"
    assert _neutralize_formula("\tINDIRECT(A1)") == "'\tINDIRECT(A1)"
    # Benign content passes through untouched.
    assert _neutralize_formula("Missing HSTS") == "Missing HSTS"
    assert _neutralize_formula("") == ""
    assert _neutralize_formula("https://example.test/") == "https://example.test/"

    base = _sample_document()
    hostile = ReportDocument(
        schema_version=base.schema_version,
        generated_at=base.generated_at,
        scan=ReportScanMetadata(
            target_hostname="-2+3",
            target_normalized_url=base.scan.target_normalized_url,
            scan_id=base.scan.scan_id,
            scan_profile=base.scan.scan_profile,
            scan_status=base.scan.scan_status,
            initiated_by_user_id=base.scan.initiated_by_user_id,
            queued_at=base.scan.queued_at,
            started_at=base.scan.started_at,
            completed_at=base.scan.completed_at,
        ),
        engines=base.engines,
        findings=base.findings,
        assessment=base.assessment,
        severity_counts=base.severity_counts,
        lifecycle_counts=base.lifecycle_counts,
    )
    rows = list(csv_module.DictReader(io.StringIO(render_csv_report(hostile))))
    assert rows[0]["target_hostname"] == "'-2+3"


def _pdf_text(pdf: bytes) -> str:
    """Decompress page content streams so assertions read actual content.

    Reportlab applies ASCII85 + Flate filters to page streams; metadata
    stays plaintext. Streams are located via the byte offset of their
    ``stream`` opener combined with the preceding /Length (binary payloads
    can contain the words "stream"/"endstream", so delimiter scanning is
    unreliable).
    """
    import re

    parts: list[str] = []
    for opener in re.finditer(rb"\nstream\n", pdf):
        header = pdf[max(0, opener.start() - 120) : opener.start()]
        length = re.search(rb"/Length (\d+)", header)
        if length is None:
            continue
        blob = pdf[opener.end() : opener.end() + int(length.group(1))]
        parts.append(_decode_stream(blob))
    return "\n".join(parts)


def _decode_stream(blob: bytes) -> str:
    """Decode one content stream (raw Flate or Adobe ASCII85 + Flate)."""
    import base64
    import zlib

    try:
        return zlib.decompress(blob).decode("latin-1")
    except Exception:  # noqa: BLE001 - fall through to the ASCII85 variant
        pass
    try:
        return zlib.decompress(base64.a85decode(blob, adobe=True)).decode("latin-1")
    except Exception:  # noqa: BLE001 - non-content streams are skipped
        return ""


def test_pdf_renders_canonical_content() -> None:
    """The PDF carries branding, scan identity, and every finding."""
    from src.reporting.pdf_generator import render_pdf_report

    pdf = render_pdf_report(_sample_document())
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 2000
    text = _pdf_text(pdf)
    assert "SentinelGPT" in text
    assert "Missing HSTS" in text
    assert "example.test" in text
    assert "HIGH" in text


def test_pdf_empty_scan_renders_honestly() -> None:
    """Zero findings produce a valid report stating so — never an error."""
    from src.reporting.pdf_generator import render_pdf_report

    base = _sample_document()
    empty = ReportDocument(
        schema_version=base.schema_version,
        generated_at=base.generated_at,
        scan=base.scan,
        engines=(),
        findings=(),
        assessment=None,
        severity_counts={},
        lifecycle_counts={},
    )
    pdf = render_pdf_report(empty)
    assert pdf.startswith(b"%PDF")
    assert "No findings" in _pdf_text(pdf)


def test_pdf_escapes_hostile_markup_and_truncates_huge_evidence() -> None:
    """Attacker-controlled finding text cannot break PDF structure, and a
    huge evidence blob is truncated with a marker instead of ballooning."""
    from src.reporting.pdf_generator import render_pdf_report

    base = _sample_document()
    hostile_finding = ReportFinding(
        id=base.findings[0].id,
        severity="CRITICAL",
        category="X",
        title='<b>& "quoted"</b>',
        description="desc",
        evidence="E" * 10_000,
        location="https://example.test/",
        recommendation="fix",
        fingerprint="fp",
        affected_asset=None,
        source_engine_code=None,
        evidence_rows=(),
        explanation=None,
    )
    hostile = ReportDocument(
        schema_version=base.schema_version,
        generated_at=base.generated_at,
        scan=base.scan,
        engines=(),
        findings=(hostile_finding,),
        assessment=None,
        severity_counts={"CRITICAL": 1},
        lifecycle_counts={},
    )
    pdf = render_pdf_report(hostile)
    assert pdf.startswith(b"%PDF")
    text = _pdf_text(pdf)
    # The markup survived as literal text: reportlab fragments runs into
    # separate Tj segments, so the tag characters appear as text runs
    # ("(b)", "(>)") instead of being consumed as bold markup (which
    # would emit neither). "quoted" must render, not vanish.
    assert "quoted" in text
    assert "(b)" in text and "(>)" in text
    assert "truncated after 4000 characters" in text
    assert len(pdf) < 200_000  # bounded despite 10k input


def test_pdf_orders_findings_by_severity() -> None:
    """Critical findings appear before low ones regardless of input order."""
    from src.reporting.pdf_generator import render_pdf_report

    base = _sample_document()
    low = ReportFinding(
        id=uuid.UUID("00000000-0000-0000-0000-000000000010"),
        severity="LOW",
        category="C",
        title="Low finding",
        description="d",
        evidence="",
        location="",
        recommendation="r",
        fingerprint=None,
        affected_asset=None,
        source_engine_code=None,
    )
    critical = ReportFinding(
        id=uuid.UUID("00000000-0000-0000-0000-000000000011"),
        severity="CRITICAL",
        category="C",
        title="Critical finding",
        description="d",
        evidence="",
        location="",
        recommendation="r",
        fingerprint=None,
        affected_asset=None,
        source_engine_code=None,
    )
    doc = ReportDocument(
        schema_version=base.schema_version,
        generated_at=base.generated_at,
        scan=base.scan,
        engines=(),
        findings=(low, critical),
        assessment=None,
        severity_counts={"LOW": 1, "CRITICAL": 1},
        lifecycle_counts={},
    )
    text = _pdf_text(render_pdf_report(doc))
    assert text.index("Critical finding") < text.index("Low finding")


def test_csv_carries_per_finding_lifecycle_status() -> None:
    """lifecycle_status comes from the assembled document, not a guess."""
    import csv as csv_module
    import io

    base = _sample_document()
    finding = ReportFinding(
        id=base.findings[0].id,
        severity=base.findings[0].severity,
        category=base.findings[0].category,
        title=base.findings[0].title,
        description=base.findings[0].description,
        evidence=base.findings[0].evidence,
        location=base.findings[0].location,
        recommendation=base.findings[0].recommendation,
        fingerprint=base.findings[0].fingerprint,
        affected_asset=base.findings[0].affected_asset,
        source_engine_code=base.findings[0].source_engine_code,
        evidence_rows=base.findings[0].evidence_rows,
        explanation=base.findings[0].explanation,
        lifecycle_status="PERSISTENT",
    )
    doc = ReportDocument(
        schema_version=base.schema_version,
        generated_at=base.generated_at,
        scan=base.scan,
        engines=base.engines,
        findings=(finding,),
        assessment=base.assessment,
        severity_counts=base.severity_counts,
        lifecycle_counts={"PERSISTENT": 1},
    )
    rows = list(csv_module.DictReader(io.StringIO(render_csv_report(doc))))
    assert rows[0]["lifecycle_status"] == "PERSISTENT"
    assert json.loads(render_json_report(doc))["findings"][0]["lifecycle_status"] == "PERSISTENT"


def test_large_finding_set_renders_all_formats() -> None:
    """300 findings: every format completes, rows are complete, PDF bounded."""
    import csv as csv_module
    import io

    base = _sample_document()
    severities = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    findings = tuple(
        ReportFinding(
            id=uuid.UUID(int=i + 100),
            severity=severities[i % len(severities)],
            category="C",
            title=f"Finding {i:03d} with special chars <>&\"' =HYPERLINK",
            description="d",
            evidence="e" * 500,
            location="https://example.test/",
            recommendation="r",
            fingerprint=f"fp-{i}",
            affected_asset=None,
            source_engine_code=None,
            evidence_rows=({"id": f"ev-{i}", "type": "t", "content": "c"},),
            explanation=None,
        )
        for i in range(300)
    )
    doc = ReportDocument(
        schema_version=base.schema_version,
        generated_at=base.generated_at,
        scan=base.scan,
        engines=(),
        findings=findings,
        assessment=None,
        severity_counts={},
        lifecycle_counts={},
    )
    assert len(json.loads(render_json_report(doc))["findings"]) == 300
    assert len(list(csv_module.DictReader(io.StringIO(render_csv_report(doc))))) == 300
    from src.reporting.pdf_generator import render_pdf_report

    pdf = render_pdf_report(doc)
    assert pdf.startswith(b"%PDF")
    text = _pdf_text(pdf)
    assert "Finding 000" in text and "Finding 299" in text


def test_failed_scan_report_uses_engine_status() -> None:
    """A REJECTED scan still renders: engines carry the failure, findings
    are empty, and the PDF states the outcome honestly."""
    from src.reporting.pdf_generator import render_pdf_report

    base = _sample_document()
    doc = ReportDocument(
        schema_version=base.schema_version,
        generated_at=base.generated_at,
        scan=ReportScanMetadata(
            target_hostname=base.scan.target_hostname,
            target_normalized_url=base.scan.target_normalized_url,
            scan_id=base.scan.scan_id,
            scan_profile=base.scan.scan_profile,
            scan_status="REJECTED",
            initiated_by_user_id=base.scan.initiated_by_user_id,
            queued_at=base.scan.queued_at,
            started_at=base.scan.started_at,
            completed_at=base.scan.completed_at,
        ),
        engines=(
            ReportEngineSummary(
                engine_code="headers-analyzer",
                tool_version_snapshot="1",
                status="FAILED",
                started_at=None,
                completed_at=None,
                error_message="sandbox unavailable",
            ),
        ),
        findings=(),
        assessment=None,
        severity_counts={},
        lifecycle_counts={},
    )
    assert json.loads(render_json_report(doc))["scan"]["status"] == "REJECTED"
    pdf = render_pdf_report(doc)
    assert pdf.startswith(b"%PDF")
    assert "REJECTED" in _pdf_text(pdf)
