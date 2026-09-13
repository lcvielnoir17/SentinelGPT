"""PDF report renderer (SRS Ch10 §4).

Renders the SAME canonical :class:`ReportDocument` the JSON and CSV
exporters consume, so the three formats can never disagree. Nothing is
recomputed or reinterpreted: severity, lifecycle status, fingerprints,
and evidence are reproduced verbatim from the scan pipeline's persisted
output. AI-generated text appears only inside clearly labeled
"AI explanation" blocks bound to their finding; the canonical finding
fields are never modified by it.

Large-scan safety: every finding is included (no sampling — the report is
a complete record), but free-text evidence fields are truncated per field
with an explicit "[truncated]" marker so hostile or huge inputs cannot
balloon the document.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, Any
from xml.sax.saxutils import escape as _xml_escape

if TYPE_CHECKING:
    from src.reporting.assembler import ReportDocument, ReportFinding

# Severity presentation order (unknown codes sort last, stable by title).
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Per-field evidence cap: keeps hostile/huge inputs bounded while the
# finding itself (title/severity/recommendation) is always complete.
_MAX_EVIDENCE_CHARS = 4_000
_MAX_ROWS_PER_FINDING = 50


def _truncate(text: str, limit: int = _MAX_EVIDENCE_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n… [truncated after {limit} characters]"


def _para(text: str) -> str:
    """Escape user content for reportlab Paragraph XML."""
    return _xml_escape(text or "", {'"': "&quot;"})


def _finding_sort_key(finding: ReportFinding) -> tuple[int, str]:
    return (_SEVERITY_ORDER.get((finding.severity or "").upper(), 5), finding.title)


def render_pdf_report(document: ReportDocument) -> bytes:
    """Render the canonical report to PDF bytes (deterministic content)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        Preformatted,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("SgptTitle", parent=styles["Title"], fontSize=22, spaceAfter=4)
    subtitle_style = ParagraphStyle(
        "SgptSubtitle", parent=styles["Normal"], fontSize=11, textColor=colors.HexColor("#444444")
    )
    h1 = ParagraphStyle("SgptH1", parent=styles["Heading1"], fontSize=14, spaceBefore=14)
    h2 = ParagraphStyle("SgptH2", parent=styles["Heading2"], fontSize=12, spaceBefore=10)
    body = ParagraphStyle("SgptBody", parent=styles["Normal"], fontSize=9.5, leading=13)
    small = ParagraphStyle("SgptSmall", parent=styles["Normal"], fontSize=8.5, leading=11)
    mono = ParagraphStyle(
        "SgptMono", parent=styles["Code"], fontSize=7.5, leading=10, wordWrap="CJK"
    )
    label = ParagraphStyle("SgptLabel", parent=styles["Normal"], fontSize=9.5, leading=13)

    generated = document.generated_at.isoformat()
    scan = document.scan

    def _footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(15 * mm, 12 * mm, f"SentinelGPT · confidential · generated {generated}")
        canvas.drawRightString(A4[0] - 15 * mm, 12 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"SentinelGPT security report — {scan.target_hostname}",
        author="SentinelGPT",
        subject=f"Scan {scan.scan_id}",
    )
    story: list[Any] = []

    # ---- cover -------------------------------------------------------
    story.append(Paragraph("SentinelGPT", title_style))
    story.append(Paragraph("Security Scan Report", subtitle_style))
    story.append(Spacer(1, 8))
    meta_rows = [
        ("Target", scan.target_hostname or "—"),
        ("Target URL", scan.target_normalized_url or "—"),
        ("Scan ID", str(scan.scan_id)),
        ("Profile", scan.scan_profile),
        ("Status", scan.scan_status),
        ("Queued", scan.queued_at.isoformat() if scan.queued_at else "—"),
        ("Started", scan.started_at.isoformat() if scan.started_at else "—"),
        ("Completed", scan.completed_at.isoformat() if scan.completed_at else "—"),
        ("Report generated", generated),
    ]
    meta_table = Table(
        [
            [Paragraph(f"<b>{_para(k)}</b>", small), Paragraph(_para(v), small)]
            for k, v in meta_rows
        ],
        colWidths=[38 * mm, 130 * mm],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(meta_table)

    # ---- executive summary -------------------------------------------
    story.append(Paragraph("Executive summary", h1))
    total = len(document.findings)
    if total == 0:
        story.append(
            Paragraph(
                "This scan produced no findings. The target presented no issues "
                "detectable by the configured engines at scan time.",
                body,
            )
        )
    else:
        ordered = sorted(document.findings, key=_finding_sort_key)
        worst = ordered[0].severity
        story.append(
            Paragraph(
                f"This scan produced <b>{total}</b> finding(s). "
                f"Highest severity observed: <b>{_para(worst)}</b>. "
                "Findings below are ordered by severity; each entry carries "
                "its supporting evidence and remediation guidance.",
                body,
            )
        )
        if document.assessment is not None and document.assessment.available:
            story.append(Spacer(1, 4))
            story.append(
                Paragraph(
                    f"<b>AI assessment</b> ({_para(document.assessment.provider)} / "
                    f"{_para(document.assessment.model)}): "
                    f"{_para(document.assessment.overall_summary)}",
                    body,
                )
            )
        elif document.assessment is not None:
            story.append(Spacer(1, 4))
            story.append(
                Paragraph(
                    "AI assessment was unavailable for this scan "
                    f"(reason: {_para(document.assessment.failure_kind or 'unknown')}); "
                    "findings below use deterministic scanner output only.",
                    body,
                )
            )

    # ---- severity distribution ----------------------------------------
    story.append(Paragraph("Severity distribution", h2))
    if document.severity_counts:
        sev_rows = [(sev, str(count)) for sev, count in sorted(document.severity_counts.items())]
        sev_table = Table(
            [[Paragraph("<b>Severity</b>", small), Paragraph("<b>Count</b>", small)]]
            + [[Paragraph(_para(s), small), Paragraph(_para(c), small)] for s, c in sev_rows],
            colWidths=[60 * mm, 40 * mm],
        )
        sev_table.setStyle(
            TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc"))])
        )
        story.append(sev_table)
    else:
        story.append(Paragraph("No findings — nothing to distribute.", body))
    if document.lifecycle_counts:
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                "Lifecycle: "
                + ", ".join(
                    f"{_para(code)}: {count}"
                    for code, count in sorted(document.lifecycle_counts.items())
                ),
                body,
            )
        )

    # ---- findings ------------------------------------------------------
    # Findings start on a fresh page so the cover + summary read as an
    # executive front section regardless of finding count.
    if document.findings:
        story.append(PageBreak())
    story.append(Paragraph("Findings", h1))
    if not document.findings:
        story.append(Paragraph("No findings were produced by this scan.", body))
    for index, finding in enumerate(sorted(document.findings, key=_finding_sort_key), start=1):
        story.append(Paragraph(f"{index}. {_para(finding.title)}", h2))
        story.append(
            Paragraph(
                f"<b>Severity:</b> {_para(finding.severity)} &nbsp; "
                f"<b>Category:</b> {_para(finding.category)} &nbsp; "
                f"<b>Lifecycle:</b> {_para(finding.lifecycle_status or '—')}",
                label,
            )
        )
        if finding.priority is not None:
            story.append(
                Paragraph(
                    f"<b>Priority:</b> {_para(finding.priority.level)} "
                    f"({_para(str(finding.priority.score))}; "
                    f"{_para(', '.join(finding.priority.factors))})",
                    label,
                )
            )
        story.append(
            Paragraph(
                f"<b>Affected asset:</b> {_para(finding.affected_asset or finding.location or '—')} &nbsp; "
                f"<b>Source:</b> {_para(finding.source_engine_code or '—')}",
                label,
            )
        )
        if finding.fingerprint:
            story.append(
                Paragraph(f"<b>Fingerprint:</b> {_para(finding.fingerprint[:16])}…", label)
            )
        story.append(Spacer(1, 3))
        story.append(Paragraph("<b>What was detected</b>", label))
        story.append(Paragraph(_para(finding.description) or "—", body))
        if finding.location:
            story.append(Paragraph(f"<b>Location:</b> {_para(finding.location)}", body))
        if finding.evidence:
            story.append(Paragraph("<b>Evidence</b>", label))
            story.append(Preformatted(_truncate(finding.evidence), mono))
        for row in finding.evidence_rows[:_MAX_ROWS_PER_FINDING]:
            row_type = str(row.get("type", ""))
            row_content = str(row.get("content", ""))
            story.append(Paragraph(f"<b>Evidence [{_para(row_type)}]</b>", label))
            story.append(Preformatted(_truncate(row_content), mono))
        if len(finding.evidence_rows) > _MAX_ROWS_PER_FINDING:
            story.append(
                Paragraph(
                    f"… [{len(finding.evidence_rows) - _MAX_ROWS_PER_FINDING} further "
                    "evidence row(s) omitted; see JSON export]",
                    small,
                )
            )
        story.append(Paragraph("<b>Remediation</b>", label))
        story.append(Paragraph(_para(finding.recommendation) or "—", body))
        explanation = finding.explanation or {}
        if explanation:
            story.append(
                Paragraph(
                    f"<b>AI explanation</b> (validation: "
                    f"{_para(str(explanation.get('validation_status', 'unknown')))}; "
                    "advisory only — the canonical fields above are authoritative):",
                    label,
                )
            )
            story.append(
                Paragraph(_para(str(explanation.get("explanation_text", ""))) or "—", body)
            )

    # ---- methodology / limitations --------------------------------------
    story.append(Paragraph("Methodology", h1))
    story.append(
        Paragraph(
            "Findings are produced deterministically by the configured scan "
            "engines against an explicitly authorized target. Each finding "
            "carries a stable fingerprint so recurrence across scans is "
            "tracked without reinterpretation. AI output, where present, is "
            "evidence-grounded interpretation only and never creates, "
            "re-scores, or closes findings.",
            body,
        )
    )
    if document.engines:
        story.append(Paragraph("Engines executed", h2))
        for engine in document.engines:
            story.append(
                Paragraph(
                    f"{_para(engine.engine_code)} — {_para(engine.status)} "
                    f"(tool: {_para(engine.tool_version_snapshot)})",
                    body,
                )
            )
    story.append(Paragraph("Limitations", h1))
    story.append(
        Paragraph(
            "This report reflects the target's observable state at scan time "
            "only. It cannot prove the absence of issues the engines do not "
            "check for, issues requiring authentication, or issues introduced "
            "after the scan completed. Findings should be re-validated before "
            "remediation is closed.",
            body,
        )
    )

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


__all__ = ["render_pdf_report"]
