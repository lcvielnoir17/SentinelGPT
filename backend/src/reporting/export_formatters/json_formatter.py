"""JSON report formatter (SRS Ch10 §4).

The JSON export is the canonical machine-readable view of a scan report.
It mirrors the live API response shapes (so a JSON export and a live
API call to the same scan cannot drift), plus a header carrying the
schema version so downstream tools can pin to a specific format.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.reporting.assembler import ReportDocument


def render_json_report(document: ReportDocument) -> str:
    """Serialize the canonical report to a deterministic JSON string.

    Output is byte-stable for equal inputs (sorted keys, compact
    separators) so checksum-based pipelines and regression snapshots
    work without false diffs.
    """
    payload = document.to_dict()
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


__all__ = ["render_json_report"]
