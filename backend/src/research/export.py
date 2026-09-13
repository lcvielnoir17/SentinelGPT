"""Research result artifacts: canonical JSON + CSV writers (M15).

Writers are pure functions over the evaluation structure — results
are generated from actual fixture execution, never fabricated. CSV
uses long format (one row per fixture/pipeline/metric, stable sort)
so diffs and spreadsheet pivots stay trivial. Cell sanitizing is a
local 5-line copy of the reporting neutralizer (deliberate: importing
the reporting package would breach the research isolation boundary
pinned by the static guard).
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _neutralize_cell(value: str) -> str:
    """Prefix spreadsheet-formula triggers so exports open as plain text."""
    if value and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def evaluation_to_json(result: dict[str, Any]) -> str:
    """Canonical JSON encoding (sorted keys: byte-deterministic reruns)."""
    return json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)


def evaluation_to_csv(result: dict[str, Any]) -> str:
    """Long-format CSV: fixture_id,pipeline,metric,value (stable order)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=["fixture_id", "pipeline", "metric", "value"], dialect="excel"
    )
    writer.writeheader()
    for fixture in sorted(result.get("fixtures", []), key=lambda f: str(f.get("fixture_id"))):
        pipelines = fixture.get("pipelines", {})
        for pipeline in sorted(pipelines):
            metrics_map = pipelines[pipeline].get("metrics", {})
            for metric in sorted(metrics_map):
                writer.writerow(
                    {
                        "fixture_id": _neutralize_cell(str(fixture.get("fixture_id", ""))),
                        "pipeline": _neutralize_cell(str(pipeline)),
                        "metric": _neutralize_cell(str(metric)),
                        "value": _format_value(metrics_map[metric]),
                    }
                )
    return buffer.getvalue()


def _format_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float):
        return repr(value)
    return str(value)


__all__ = ["evaluation_to_csv", "evaluation_to_json"]
