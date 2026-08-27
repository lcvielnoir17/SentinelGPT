"""Reporting subsystem package (SRS Ch10).

Public surface:

* :class:`ReportAssembler` — format-agnostic, pure-read step that
  produces a canonical :class:`ReportDocument` for one scan.
* :func:`render_json_report` — JSON export.
* :func:`render_csv_report` — CSV export.

The PDF renderer (WeasyPrint, Ch10 §2) is not part of this MVP; the
assembler's :class:`ReportDocument` is the stable contract a future
PDF worker will consume.
"""

from src.reporting.assembler import (
    REPORT_SCHEMA_VERSION,
    ReportAssembler,
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

__all__ = [
    "CSV_COLUMNS",
    "REPORT_SCHEMA_VERSION",
    "ReportAssembler",
    "ReportAssessment",
    "ReportDocument",
    "ReportEngineSummary",
    "ReportFinding",
    "ReportScanMetadata",
    "render_csv_report",
    "render_json_report",
]
