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
    """Long-format CSV: fixture_id,pipeline,metric,value (stable order).

    Metric rows carry per-fixture values; ``error:<kind>`` rows carry
    per-fixture mismatch-kind counts so error taxonomy stays
    machine-readable in the same neutral shape.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=["fixture_id", "pipeline", "metric", "value"], dialect="excel"
    )
    writer.writeheader()
    for fixture in sorted(result.get("fixtures", []), key=lambda f: str(f.get("fixture_id"))):
        pipelines = fixture.get("pipelines", {})
        for pipeline in sorted(pipelines):
            metrics_map = pipelines[pipeline].get("metrics", {})
            rows: list[tuple[str, str]] = [
                (str(metric), _format_value(metrics_map[metric])) for metric in metrics_map
            ]
            for kind, count in _error_kinds(pipelines[pipeline].get("mismatches", [])).items():
                rows.append((f"error:{kind}", str(count)))
            rows.sort(key=lambda row: row[0])
            for metric, value in rows:
                writer.writerow(
                    {
                        "fixture_id": _neutralize_cell(str(fixture.get("fixture_id", ""))),
                        "pipeline": _neutralize_cell(str(pipeline)),
                        "metric": _neutralize_cell(metric),
                        "value": value,
                    }
                )
    return buffer.getvalue()


def _error_kinds(mismatches: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    if isinstance(mismatches, list):
        for mismatch in mismatches:
            if isinstance(mismatch, dict):
                kind = str(mismatch.get("kind", "unknown"))
                counts[kind] = counts.get(kind, 0) + 1
    return counts


def _format_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float):
        return repr(value)
    return str(value)


__all__ = ["evaluation_to_csv", "evaluation_to_json"]
