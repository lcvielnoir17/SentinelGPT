"""Manual-review sheet generator (M19): automation prefilled, humans judge.

The sheet keeps automated results and human assessment in separate
columns by construction: automation fills identity, question,
provider, model, acceptance, and reasons; the reviewer fills
grounding, usefulness, misleading statements, and policy observations.
Review output never feeds back into metrics.
"""

from __future__ import annotations

import csv
import io
from typing import Any

REVIEW_COLUMNS = (
    "transcript_id",
    "question_id",
    "fixture_id",
    "provider",
    "model",
    "automated_accept",
    "automated_reason",
    "citation_check",
    "grounding_note",
    "useful_explanation",
    "misleading_statements",
    "policy_violations",
    "reviewer",
    "review_date",
)


def review_sheet_rows(
    transcripts: list[dict[str, Any]], replays: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """One review row per transcript (human columns left empty)."""
    by_fixture = {(r.get("fixture_id"), r.get("pipeline")): r for r in replays}
    rows: list[dict[str, str]] = []
    for index, transcript in enumerate(transcripts):
        replay = by_fixture.get((transcript.get("fixture_id"), transcript.get("pipeline")), {})
        rows.append(
            {
                "transcript_id": f"live-{index:03d}",
                "question_id": str(transcript.get("question_id", "")),
                "fixture_id": str(transcript.get("fixture_id", "")),
                "provider": str(transcript.get("provider", "")),
                "model": str(transcript.get("model", "")),
                "automated_accept": str(bool(replay.get("accepted"))),
                "automated_reason": str(replay.get("reason", "")),
                "citation_check": "",
                "grounding_note": "",
                "useful_explanation": "",
                "misleading_statements": "",
                "policy_violations": "",
                "reviewer": "",
                "review_date": "",
            }
        )
    return rows


def review_sheet_csv(rows: list[dict[str, str]]) -> str:
    """CSV sheet with a fixed column contract (stable order)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(REVIEW_COLUMNS), dialect="excel")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column, "") for column in REVIEW_COLUMNS})
    return buffer.getvalue()


def review_completion(text: str) -> tuple[int, int]:
    """Count completed transcript sections in a human-review document.

    Returns ``(completed, total)`` where a ``## `` section counts as
    completed when its reviewer/date line carries a real judgment
    instead of the pending marker. Pure parsing only; entering
    judgments is always a human act.
    """
    total = 0
    completed = 0
    in_section = False
    section_done = False
    for line in text.splitlines():
        if line.startswith("## "):
            if in_section:
                total += 1
                completed += 1 if section_done else 0
            in_section = True
            section_done = False
        elif in_section and line.startswith("- Reviewer/date:"):
            if "PENDING" not in line:
                section_done = True
    if in_section:
        total += 1
        completed += 1 if section_done else 0
    return completed, total


__all__ = ["REVIEW_COLUMNS", "review_completion", "review_sheet_csv", "review_sheet_rows"]
