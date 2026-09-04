"""CSV report formatter (SRS Ch10 §4).

The CSV export is a flattened, one-row-per-finding table suitable for
import into spreadsheets or ticket-tracking tools. Long-form prose
(explanation text, remediation steps) is summarized to a single line
per field; the full text is available via the JSON export.

Column order is fixed so downstream scripts can rely on the shape.
"""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.reporting.assembler import ReportDocument


CSV_COLUMNS: tuple[str, ...] = (
    "scan_id",
    "scan_status",
    "scan_profile",
    "target_hostname",
    "finding_id",
    "severity",
    "category",
    "title",
    "affected_asset",
    "source_engine",
    "fingerprint",
    "lifecycle_status",
    "explanation_validation_status",
    "explanation_summary",
    "remediation_summary",
)

# Spreadsheet formula prefixes (OWASP CSV Injection). Cells starting with
# these run as formulas when the export is opened in Excel/Sheets — and
# finding/target fields can carry attacker-controlled text (hostnames,
# paths, header values), so every free-text cell is neutralized below.
# Prefixing with a single quote keeps the visible content identical
# while forcing text interpretation.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _neutralize_formula(value: str) -> str:
    """Prefix spreadsheet-formula triggers so exports open as plain text."""
    if value and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _explanation_summary(finding_explanation: dict[str, object] | None) -> str:
    if not finding_explanation:
        return ""
    text = finding_explanation.get("explanation_text", "")
    if isinstance(text, str):
        return text.replace("\n", " ").replace("\r", " ").strip()
    return ""


def _remediation_summary(finding_explanation: dict[str, object] | None) -> str:
    if not finding_explanation:
        return ""
    remediation = finding_explanation.get("remediation")
    if not isinstance(remediation, dict):
        return ""
    summary = remediation.get("summary", "")
    steps = remediation.get("steps") or []
    pieces: list[str] = []
    if isinstance(summary, str) and summary:
        pieces.append(summary)
    if isinstance(steps, list):
        pieces.extend(str(s) for s in steps if isinstance(s, str))
    return " | ".join(pieces).replace("\n", " ").strip()


def _lifecycle_status(fingerprint: str | None, lifecycle_counts: dict[str, int]) -> str:
    """The lifecycle status is fingerprint-specific, not scan-wide.

    The lifecycle_counts dict is a scan-wide summary; the per-finding
    status requires the per-fingerprint history. We default to an empty
    string when the caller did not enrich the document.
    """
    del fingerprint, lifecycle_counts
    return ""


def render_csv_report(document: ReportDocument) -> str:
    """Serialize the canonical report to a CSV string.

    The output uses CRLF line endings (RFC 4180) and quoting where
    needed, so a downstream tool like Excel or pandas reads it without
    preprocessing.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), dialect="excel")
    writer.writeheader()
    for finding in document.findings:
        writer.writerow(
            {
                "scan_id": str(document.scan.scan_id),
                "scan_status": document.scan.scan_status,
                "scan_profile": document.scan.scan_profile,
                "target_hostname": _neutralize_formula(document.scan.target_hostname),
                "finding_id": str(finding.id),
                "severity": finding.severity,
                "category": finding.category,
                "title": _neutralize_formula(finding.title),
                "affected_asset": _neutralize_formula(finding.affected_asset or ""),
                "source_engine": finding.source_engine_code or "",
                "fingerprint": _neutralize_formula(finding.fingerprint or ""),
                "lifecycle_status": _lifecycle_status(
                    finding.fingerprint, document.lifecycle_counts
                ),
                "explanation_validation_status": (
                    str(finding.explanation.get("validation_status", ""))
                    if finding.explanation
                    else ""
                ),
                "explanation_summary": _neutralize_formula(
                    _explanation_summary(finding.explanation)
                ),
                "remediation_summary": _neutralize_formula(
                    _remediation_summary(finding.explanation)
                ),
            }
        )
    return buffer.getvalue()


__all__ = ["CSV_COLUMNS", "render_csv_report"]
