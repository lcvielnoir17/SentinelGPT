"""Deterministic research evaluation runner (M15 reproducibility package).

A clean local checkout reproduces the evaluation with only a Python
interpreter and the repository — no database, network, cloud, targets,
or secrets:

    .venv/Scripts/python.exe scripts/run_research_evaluation.py
    .venv/Scripts/python.exe scripts/run_research_evaluation.py --out research-results

The runner loads the versioned dataset, evaluates every fixture
through all three pipelines, and writes ``evaluation.json`` (canonical
encoding) plus ``evaluation.csv`` (long format). Re-running produces
byte-identical artifacts; any divergence is a real behavioral change,
never noise. Exit 0 on success, exit 2 on dataset/usage errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for candidate in (REPO_ROOT / "backend", REPO_ROOT / "backend" / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from src.research.evaluate import evaluate_dataset  # noqa: E402
from src.research.export import evaluation_to_csv, evaluation_to_json  # noqa: E402
from src.research.schema import (  # noqa: E402
    DATASET_VERSION,
    FixtureValidationError,
    validate_dataset,
)

DEFAULT_DATASET = REPO_ROOT / "backend" / "src" / "research" / "dataset.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--out", default="research-results")
    args = parser.parse_args(argv)

    try:
        raw = json.loads(Path(args.dataset).read_text())
    except FileNotFoundError:
        print(f"error: dataset not found: {args.dataset}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: dataset is not valid JSON: {exc}", file=sys.stderr)
        return 2
    try:
        dataset = validate_dataset(raw)
    except FixtureValidationError as exc:
        print(f"error: invalid dataset: {exc}", file=sys.stderr)
        return 2

    result = evaluate_dataset(dataset)
    result["transcript_results"] = _replay_bundled_transcripts(dataset)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evaluation.json").write_text(evaluation_to_json(result) + "\n", newline="\n")
    (out_dir / "evaluation.csv").write_text(evaluation_to_csv(result), newline="\n")

    aggregate = result["aggregate"]
    print(f"dataset: {DATASET_VERSION} ({aggregate['sentinelgpt']['fixture_count']} fixtures)")
    for pipeline in ("baseline-a", "baseline-b", "sentinelgpt"):
        metrics = aggregate[pipeline]
        print(
            f"{pipeline}: f1={_show(metrics.get('grouping_f1'))} "
            f"severity={_show(metrics.get('severity_consistency'))} "
            f"priority={_show(metrics.get('priority_agreement'))}"
        )
    mismatches = sum(
        len(f["pipelines"][name]["mismatches"])
        for f in result["fixtures"]
        for name in ("baseline-a", "baseline-b", "sentinelgpt")
    )
    print(f"total mismatches listed: {mismatches}")
    replays = result.get("transcript_results", [])
    accepted = sum(1 for r in replays if isinstance(r, dict) and r.get("accepted"))
    print(f"transcript replays: {accepted}/{len(replays)} accepted (offline)")
    return 0


def _show(value: object) -> str:
    return f"{value:.3f}" if isinstance(value, float) else str(value)


def _replay_bundled_transcripts(dataset: dict) -> list[dict]:
    """Offline replay of committed seed transcripts (never calls a provider)."""
    from src.research.transcripts import replay_all, validate_transcript

    directory = REPO_ROOT / "backend" / "src" / "research" / "transcripts"
    transcripts = []
    for path in sorted(directory.glob("*.json")):
        try:
            transcripts.append(validate_transcript(json.loads(path.read_text())))
        except Exception as exc:  # noqa: BLE001 - a bad seed must fail loudly below
            raise SystemExit(f"error: invalid seed transcript {path.name}: {exc}") from exc
    return replay_all(dataset, transcripts)


if __name__ == "__main__":
    raise SystemExit(main())
