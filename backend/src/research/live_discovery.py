"""Current-run transcript discovery (M19): per-question files only.

``collect_transcripts()`` writes one file per frozen prompt —
``{question_id}.json`` — into the quarantine directory. This helper reads
back exactly those files, in frozen prompt order, and validates each one
with the real transcript schema.

It never reads aggregate artifacts (``live-transcripts.json``,
``live-transcripts.csv``, ``live-evaluation.json``,
``live-manual-review.csv``, ``live-metadata.json``). Those are written
*later* by ``write_artifacts()``, so reading them here would yield
nothing on a fresh run and stale previous-run data on a reused
quarantine directory. The allowlist is the frozen prompt set itself:
any other file in the directory — stale or foreign — is ignored.

Prompts with no file (provider failure, sanitizer rejection, empty
reply, timeout) are skipped; they stay accounted for in the attempts
summary. A file that exists but is unreadable or fails schema
validation raises ``TranscriptDiscoveryError`` naming the file — corrupt
evidence fails closed and is never silently dropped.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from src.research.live_prompts import get_prompt_set
from src.research.transcripts import TranscriptValidationError, validate_transcript

if TYPE_CHECKING:
    from pathlib import Path


class TranscriptDiscoveryError(ValueError):
    """A current-run transcript file is unreadable or schema-invalid."""


def discover_transcripts(out_dir: Path) -> list[dict[str, Any]]:
    """Read and validate the current run's per-question transcript files."""
    transcripts: list[dict[str, Any]] = []
    for prompt in get_prompt_set():
        candidate = out_dir / f"{prompt.question_id}.json"
        if not candidate.exists():
            continue
        try:
            raw: Any = json.loads(candidate.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise TranscriptDiscoveryError(
                f"{candidate.name}: unreadable transcript ({type(exc).__name__})"
            ) from exc
        try:
            clean = validate_transcript(raw)
        except TranscriptValidationError as exc:
            raise TranscriptDiscoveryError(f"{candidate.name}: invalid transcript ({exc})") from exc
        # The M16 schema carries no question_id; re-attach it from the
        # frozen prompt allowlist so review/CSV rows keep their identity.
        transcripts.append({**clean, "question_id": prompt.question_id})
    return transcripts


__all__ = ["TranscriptDiscoveryError", "discover_transcripts"]
