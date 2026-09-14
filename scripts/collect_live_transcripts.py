"""Live transcript collection entry point (M19, explicit opt-in only).

Collects genuine provider transcripts over the frozen M16 prompt set.
Nothing here runs by default: collection requires
``RESEARCH_LIVE_PROVIDER=1`` plus a usable ``GEMINI_API_KEY`` in the
environment, and credentials never reach logs, artifacts, or the
repository. Outputs land in a caller-chosen quarantine directory
(default: outside the repository, under the system temp dir).

    RESEARCH_LIVE_PROVIDER=1 GEMINI_API_KEY=<key> \\
        .venv/Scripts/python.exe scripts/collect_live_transcripts.py --out /tmp/sgpt-live

Without opt-in (or without a key) the script reports the clean
"not performed" outcome and exits 0 — normal test runs never touch
the network. Replay the captured transcripts offline with the M12
validator; see docs/research-evaluation.md.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for candidate in (REPO_ROOT / "backend", REPO_ROOT / "backend" / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from src.research.live_artifacts import write_artifacts  # noqa: E402
from src.research.live_collect import ProviderUnavailableError, collect_transcripts  # noqa: E402
from src.research.live_config import collection_status, resolve_config  # noqa: E402
from src.research.live_discovery import discover_transcripts  # noqa: E402
from src.research.live_metrics import evaluate_attempts  # noqa: E402
from src.research.schema import DATASET_VERSION, validate_dataset  # noqa: E402
from src.research.transcripts import replay_all  # noqa: E402


def default_provider_factory() -> object:
    """Build the shared conversation agent from the environment key."""
    from src.api.dependencies import get_conversation_agent

    agent = get_conversation_agent()
    if agent is None:
        raise ProviderUnavailableError("AI analyst is not configured")
    return agent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(Path(tempfile.gettempdir()) / "sgpt-live-transcripts"),
    )
    parser.add_argument(
        "--dataset", default=str(REPO_ROOT / "backend" / "src" / "research" / "dataset.json")
    )
    args = parser.parse_args(argv)

    status = collection_status(dict(os.environ))
    if not status.will_collect:
        print(f"live collection not performed: {status.reason}")
        return 0
    config = resolve_config(dict(os.environ))
    dataset = validate_dataset(json.loads(Path(args.dataset).read_text()))
    out_dir = Path(args.out)

    summary = collect_transcripts(
        dataset, out_dir=out_dir, provider_factory=default_provider_factory
    )
    # Current-run transcripts only: the per-question files written above.
    # live-transcripts.json is produced later by write_artifacts() and must
    # never be read here (absent on a fresh run, stale on a reused one).
    transcripts = discover_transcripts(out_dir)

    replays = replay_all(dataset, transcripts)
    metrics = evaluate_attempts(summary["attempts"], replays)
    metadata = {
        "provider": config.provider,
        "model": config.model,
        "temperature": config.temperature,
        "max_output_tokens": config.max_output_tokens,
        "prompt_version": "sgpt.live-prompts.v1",
        "validator": "M12 response validator",
        "collected_at": datetime.now(UTC).isoformat(),
        "opt_in": "RESEARCH_LIVE_PROVIDER=1 with environment key",
        "key_source": "environment only (never stored)",
        "limitations": [
            "Small exploratory sample; no statistical generalization.",
            "Provider-default generation settings (temperature unpinned).",
            "Synthetic fixtures only; no transfer claim to live targets.",
        ],
    }
    write_artifacts(
        out_dir,
        transcripts=transcripts,
        replays=replays,
        metrics=metrics,
        metadata=metadata,
    )
    print(f"dataset: {DATASET_VERSION} prompts=12 stored={summary['transcripts_stored']}")
    print(f"acceptance={metrics['validator_acceptance_rate']} attempts={metrics['attempts_total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
