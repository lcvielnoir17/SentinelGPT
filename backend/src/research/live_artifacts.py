"""Live artifact writers (M19): machine-readable, secret-free outputs.

Five files, all derived from recorded attempts and transcripts —
never from live secrets (which never enter this layer at all):

* ``live-transcripts.json`` — stored transcripts verbatim
* ``live-transcripts.csv`` — flat per-transcript index
* ``live-evaluation.json`` — metrics + configuration + sample method
* ``live-manual-review.csv`` — review template (automation prefilled)
* ``live-metadata.json`` — versions, dates, opt-in proof, limitations
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


def write_artifacts(
    out_dir: Path,
    *,
    transcripts: list[dict[str, Any]],
    replays: list[dict[str, Any]],
    metrics: dict[str, Any],
    metadata: dict[str, Any],
) -> list[str]:
    """Write the five artifacts; return the filenames written."""
    from src.research.live_review import review_sheet_csv, review_sheet_rows
    from src.research.schema import DATASET_VERSION

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "live-transcripts.json").write_text(
        json.dumps(transcripts, indent=2, sort_keys=True) + "\n"
    )
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "transcript_id",
            "question_id",
            "fixture_id",
            "provider",
            "model",
            "accepted",
            "reason",
        ],
        dialect="excel",
    )
    writer.writeheader()
    by_fixture = {(r.get("fixture_id"), r.get("pipeline")): r for r in replays}
    for index, transcript in enumerate(transcripts):
        replay = by_fixture.get((transcript.get("fixture_id"), transcript.get("pipeline")), {})
        writer.writerow(
            {
                "transcript_id": f"live-{index:03d}",
                "question_id": str(transcript.get("question_id", "")),
                "fixture_id": str(transcript.get("fixture_id", "")),
                "provider": str(transcript.get("provider", "")),
                "model": str(transcript.get("model", "")),
                "accepted": str(bool(replay.get("accepted"))),
                "reason": str(replay.get("reason", "")),
            }
        )
    (out_dir / "live-transcripts.csv").write_text(buffer.getvalue())
    (out_dir / "live-evaluation.json").write_text(
        json.dumps(metrics, indent=2, sort_keys=True, default=str) + "\n"
    )
    (out_dir / "live-manual-review.csv").write_text(
        review_sheet_csv(review_sheet_rows(transcripts, replays))
    )
    (out_dir / "live-metadata.json").write_text(
        json.dumps(
            {
                **metadata,
                "dataset_version": DATASET_VERSION,
                "generated_at": datetime.now(UTC).isoformat(),
                "synthetic_only": False,
            },
            indent=2,
            sort_keys=True,
            default=str,
        )
        + "\n"
    )
    return [
        "live-transcripts.json",
        "live-transcripts.csv",
        "live-evaluation.json",
        "live-manual-review.csv",
        "live-metadata.json",
    ]


__all__ = ["write_artifacts"]
