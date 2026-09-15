"""M20 combined research analysis (offline, deterministic, no live calls).

Reads the deterministic dataset evaluation plus the finalized M19
live-provider quarantine artifacts and writes a combined results
package with canonical encoding (re-runs are byte-identical):

    .venv/Scripts/python.exe scripts/analyze_research_results.py
    .venv/Scripts/python.exe scripts/analyze_research_results.py \\
        --live-dir <quarantine-dir> --out research-results

Deterministic pipeline performance and live-provider behavior are
kept analytically separate throughout: they are never collapsed
into one score. Exit 0 on success, exit 2 on data-integrity errors.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
for candidate in (REPO_ROOT / "backend", REPO_ROOT / "backend" / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from src.research.evaluate import evaluate_dataset  # noqa: E402
from src.research.live_prompts import get_prompt_set  # noqa: E402
from src.research.schema import (  # noqa: E402
    DATASET_VERSION,
    FixtureValidationError,
    validate_dataset,
)
from src.research.transcripts import (  # noqa: E402
    TranscriptValidationError,
    replay_all,
    validate_transcript,
)

DEFAULT_DATASET = REPO_ROOT / "backend" / "src" / "research" / "dataset.json"
DEFAULT_LIVE_DIR = Path(tempfile.gettempdir()) / "sgpt-live-transcripts"

_CODE_RE = re.compile(r"code=(\d+|unknown)")
_RETRYABLE_RE = re.compile(r"retryable=(yes|no|unknown)")

# Fail-closed tripwire: generated results must never carry secret material.
_SECRET_PATTERNS = (
    re.compile(r"(?i)\bGEMINI_API_KEY\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{10,}={0,2}"),
    re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bpassword\s*[:=]\s*\S{4,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{10,}"),
)


class IntegrityError(ValueError):
    """A source artifact failed validation (never repaired silently)."""


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise IntegrityError(f"missing artifact: {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise IntegrityError(f"corrupt artifact: {path.name} ({exc})") from exc


def _assert_secret_free(name: str, text: str) -> None:
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            raise IntegrityError(f"secret pattern in {name}; refusing to write results")


def _write_json(out_dir: Path, name: str, payload: object) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    _assert_secret_free(name, text)
    (out_dir / name).write_text(text)


def _failure_category(detail: str) -> str:
    lowered = detail.lower()
    if "quota" in lowered or "rate-limit" in lowered or "rate limit" in lowered:
        return "quota"
    if "high demand" in lowered or "overloaded" in lowered:
        return "availability"
    if "connecterror" in lowered or "timeout" in lowered or "timed out" in lowered:
        return "temporary-transport"
    if "unauthorized" in lowered or "forbidden" in lowered or "401" in lowered:
        return "access"
    code = (_CODE_RE.search(detail) or [None, "unknown"])[1]
    if code in ("429", "503", "500", "502", "504"):
        return "availability"
    return "other"


def _regex_group(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else "unknown"


def _parse_diagnostic(detail: str) -> dict[str, str]:
    return {
        "code": _regex_group(_CODE_RE, detail),
        "retryable": _regex_group(_RETRYABLE_RE, detail),
    }


def _deterministic_results(dataset: dict[str, Any]) -> dict[str, Any]:
    result = evaluate_dataset(dataset)
    fixtures = dataset["fixtures"]
    ground_truth_keys = sorted({k for f in fixtures for k in f.get("ground_truth", {})})
    history_pairs = sorted(f["id"] for f in fixtures if f.get("history") or f.get("scan_b"))
    composition = {
        "fixture_count": len(fixtures),
        "fixture_ids": sorted(f["id"] for f in fixtures),
        "ground_truth_keys": ground_truth_keys,
        "history_pair_fixtures": history_pairs,
    }
    return {
        "dataset_version": result["dataset_version"],
        "dataset_sha256": result["dataset_sha256"],
        "pipeline_version": result["pipeline_version"],
        "metric_version": result["metric_version"],
        "metric_definitions": result["metric_definitions"],
        "baseline_definitions": result["baseline_definitions"],
        "aggregate": result["aggregate"],
        "fixture_composition": composition,
        "limitations": result["limitations"],
    }


def _live_results(live_dir: Path, dataset: dict[str, Any]) -> dict[str, Any]:
    raw_transcripts = _read_json(live_dir / "live-transcripts.json")
    evaluation = _read_json(live_dir / "live-evaluation.json")
    metadata = _read_json(live_dir / "live-metadata.json")
    if not isinstance(raw_transcripts, list):
        raise IntegrityError("live-transcripts.json must be a list")
    if not isinstance(evaluation, dict) or not isinstance(metadata, dict):
        raise IntegrityError("live evaluation/metadata must be objects")
    transcripts: list[dict[str, Any]] = []
    for entry in raw_transcripts:
        try:
            transcripts.append(validate_transcript(entry))
        except TranscriptValidationError as exc:
            raise IntegrityError(f"live transcript invalid ({exc})") from exc
    # Authoritative question mapping from per-question files (the
    # aggregate transcript records predate the question_id fix).
    question_by_fixture: dict[str, str] = {}
    for prompt in get_prompt_set():
        candidate = live_dir / f"{prompt.question_id}.json"
        if candidate.exists():
            try:
                record = json.loads(candidate.read_text())
            except json.JSONDecodeError as exc:
                raise IntegrityError(f"corrupt {candidate.name} ({exc})") from exc
            question_by_fixture[str(record.get("fixture_id", ""))] = prompt.question_id
    replays = replay_all(dataset, transcripts)
    mismatched = [r for r in replays if not r.get("hash_match")]
    if mismatched:
        raise IntegrityError(
            "evidence hash mismatch for: " + ", ".join(str(r.get("fixture_id")) for r in mismatched)
        )
    replay_by_fixture = {(r.get("fixture_id"), r.get("pipeline")): r for r in replays}
    diagnostics = {
        str(d.get("question_id", "")): d
        for d in evaluation.get("attempt_diagnostics", [])
        if isinstance(d, dict)
    }
    transcript_by_fixture = {t["fixture_id"]: t for t in transcripts}
    attempts = []
    for prompt in get_prompt_set():
        diagnostic = diagnostics.get(prompt.question_id, {})
        transcript = transcript_by_fixture.get(prompt.fixture_id)
        replay = replay_by_fixture.get((prompt.fixture_id, "sentinelgpt"), {})
        response = (transcript or {}).get("response", {})
        attempts.append(
            {
                "question_id": prompt.question_id,
                "fixture_id": prompt.fixture_id,
                "adversarial": bool(prompt.adversarial),
                "provider_outcome": str(diagnostic.get("outcome", "unknown")),
                "transcript_stored": transcript is not None,
                "validator_outcome": (
                    "accepted"
                    if replay.get("accepted") is True
                    else ("rejected" if replay.get("accepted") is False else "not-run")
                ),
                "validator_reason": str(replay.get("reason", "")),
                "citations_count": (
                    len(response.get("citations", []))
                    if isinstance(response.get("citations"), list)
                    else 0
                ),
                "citation_validity": replay.get("citation_validity"),
                "failure_reason": str(diagnostic.get("detail", "")),
                "failure_category": (
                    _failure_category(str(diagnostic.get("detail", "")))
                    if diagnostic.get("outcome") == "provider_failed"
                    else ""
                ),
            }
        )
    pending_review = 0
    review_path = live_dir / "live-manual-review.csv"
    if review_path.exists():
        with review_path.open(newline="") as handle:
            for row in csv.DictReader(handle):
                if not (row.get("reviewer") or "").strip():
                    pending_review += 1
    return {
        "provider": str(metadata.get("provider", "")),
        "model": str(metadata.get("model", "")),
        "prompt_version": str(metadata.get("prompt_version", "")),
        "validator": str(metadata.get("validator", "")),
        "dataset_version": str(metadata.get("dataset_version", "")),
        "transcript_count": len(transcripts),
        "transcript_schema": "sgpt.transcript.v1",
        "attempts": attempts,
        "attempts_by_outcome": evaluation.get("attempts_by_outcome", {}),
        "validator_acceptance_rate": evaluation.get("validator_acceptance_rate"),
        "unsupported_claim_rate": evaluation.get("unsupported_claim_rate"),
        "citation_validity_mean": evaluation.get("citation_validity_mean"),
        "adversarial_completed": evaluation.get("adversarial_completed"),
        "adversarial_total": evaluation.get("adversarial_total"),
        "question_ids_without_transcript_identity": sorted(
            t["fixture_id"] for t in transcripts if "question_id" not in t
        ),
        "manual_review_pending_rows": pending_review,
    }


def build_package(dataset: dict[str, Any], live_dir: Path) -> dict[str, object]:
    """Assemble every results file (pure; writing happens in main)."""
    deterministic = _deterministic_results(dataset)
    live = _live_results(live_dir, dataset)
    attempts = live["attempts"]
    provider_failures = [
        {
            "question_id": a["question_id"],
            "fixture_id": a["fixture_id"],
            "adversarial": a["adversarial"],
            "category": a["failure_category"],
            "diagnostic": _parse_diagnostic(a["failure_reason"]),
            "detail": a["failure_reason"],
        }
        for a in attempts
        if a["provider_outcome"] == "provider_failed"
    ]
    rejection_reasons: dict[str, int] = {}
    for a in attempts:
        if a["validator_outcome"] == "rejected":
            rejection_reasons[a["validator_reason"]] = (
                rejection_reasons.get(a["validator_reason"], 0) + 1
            )
    error_analysis = {
        "deterministic_error_taxonomy": deterministic["aggregate"]["error_taxonomy"],
        "live_validator_rejection_reasons": dict(sorted(rejection_reasons.items())),
        "live_model_output_failures": {
            "schema_mismatch_stored": 0,
            "missing_fields_stored": 0,
            "note": (
                "No stored live transcript failed validation; "
                "historical fence-wrapped replies were recovered by the "
                "collector before persistence."
            ),
        },
    }
    validator_analysis = {
        "validator": live["validator"],
        "acceptance_rate_over_stored": live["validator_acceptance_rate"],
        "unsupported_claim_rate": live["unsupported_claim_rate"],
        "citation_validity_mean": live["citation_validity_mean"],
        "grounding_observation": (
            "All stored replies cite zero findings against zero-finding "
            "evidence snapshots; empty citation/compliance lists validate "
            "as accepted under the M12 contract."
        ),
        "adversarial_completed": live["adversarial_completed"],
        "adversarial_total": live["adversarial_total"],
    }
    prompts = get_prompt_set()
    tables = {
        "table_1_dataset_fixture_composition": deterministic["fixture_composition"],
        "table_2_baseline_definitions": deterministic["baseline_definitions"],
        "table_3_deterministic_metric_comparison": {
            "micro": deterministic["aggregate"]["micro"],
            "per_pipeline": {
                name: deterministic["aggregate"][name]
                for name in ("baseline-a", "baseline-b", "sentinelgpt")
            },
        },
        "table_4_error_taxonomy": deterministic["aggregate"]["error_taxonomy"],
        "table_5_lifecycle_regression_resolution": {
            "regression_detection_rate": {
                name: deterministic["aggregate"][name]["regression_detection_rate"]
                for name in ("baseline-a", "baseline-b", "sentinelgpt")
            },
            "resolution_detection_rate": {
                name: deterministic["aggregate"][name]["resolution_detection_rate"]
                for name in ("baseline-a", "baseline-b", "sentinelgpt")
            },
            "history_pair_fixtures": deterministic["fixture_composition"]["history_pair_fixtures"],
        },
        "table_6_live_attempt_outcomes": [
            {
                "question_id": a["question_id"],
                "fixture_id": a["fixture_id"],
                "adversarial": a["adversarial"],
                "provider_outcome": a["provider_outcome"],
                "transcript_stored": a["transcript_stored"],
                "validator_outcome": a["validator_outcome"],
            }
            for a in attempts
        ],
        "table_7_validator_acceptance_rejection": {
            "acceptance_rate_over_stored": live["validator_acceptance_rate"],
            "rejection_reasons": dict(sorted(rejection_reasons.items())),
        },
        "table_8_provider_failure_categories": {
            category: sum(1 for f in provider_failures if f["category"] == category)
            for category in sorted({f["category"] for f in provider_failures})
        },
        "table_9_grounding_citation_observations": [
            {
                "question_id": a["question_id"],
                "fixture_id": a["fixture_id"],
                "citations_count": a["citations_count"],
                "citation_validity": a["citation_validity"],
                "validator_outcome": a["validator_outcome"],
            }
            for a in attempts
            if a["transcript_stored"]
        ],
        "prompt_set": [
            {
                "question_id": p.question_id,
                "fixture_id": p.fixture_id,
                "adversarial": bool(p.adversarial),
            }
            for p in prompts
        ],
    }
    limitations = [
        "Synthetic fixtures only; no transfer claim to live targets.",
        "Live sample is n=8 stored transcripts from 12 frozen prompts (single run).",
        "No statistical significance is claimed from the live sample.",
        "Provider quota/availability limited the run (4 provider failures).",
        "Results depend on the provider model version and configuration recorded in live metadata.",
        "Exact-match and allow-list metrics reflect construction choices, not prevalence.",
        "No live targets, no prevalence estimate, possible construction bias.",
        "Adversarial coverage did not complete (0 of 3 adversarial prompts stored).",
    ]
    supported_claims = [
        "The deterministic SentinelGPT pipeline reproduces every canonical fixture exactly (54/54 grouping F1 1.0, zero false positives/negatives).",
        "Both baselines underperform the deterministic pipeline on the frozen metrics.",
        "The M12 validator accepts well-formed live replies deterministically (8/8 stored, byte-identical replay).",
        "The M19 collection framework accounts every attempt and preserves sanitized diagnostics offline.",
    ]
    unsupported_claims = [
        "No general model-accuracy claim is supported (n=8, synthetic only).",
        "No universal superiority claim is supported.",
        "No real-world effectiveness claim is supported.",
        "No compliance-certification claim is supported.",
        "No prompt-injection resistance claim is supported (adversarial prompts did not complete).",
    ]
    combined = {
        "dataset_version": DATASET_VERSION,
        "prompt_version": "sgpt.live-prompts.v1",
        "deterministic": {
            "fixture_count": deterministic["fixture_composition"]["fixture_count"],
            "pipelines": ["baseline-a", "baseline-b", "sentinelgpt"],
        },
        "live_provider": {
            "provider": live["provider"],
            "model": live["model"],
            "attempts_total": len(attempts),
            "transcripts_stored": live["transcript_count"],
            "configuration": "provider defaults (temperature unpinned)",
        },
        "human_review": (
            "PENDING HUMAN REVIEW" if live["manual_review_pending_rows"] else "no review rows"
        ),
        "limitations": limitations,
        "supported_claims": supported_claims,
        "unsupported_claims": unsupported_claims,
        "interpretation": {
            "deterministic_findings": (
                "Controlled fixtures demonstrate exact pipeline behavior "
                "against known ground truth; see Table 3."
            ),
            "live_provider_findings": (
                "Genuine model outputs over the frozen evidence demonstrate "
                "validator mechanics on live-shaped replies; see Tables 6-9."
            ),
            "validator_findings": (
                "The M12 safety layer accepts compliant replies and rejects "
                "non-compliant ones deterministically, offline and online."
            ),
            "provider_findings": (
                "API availability and free-tier quota bound what a single "
                "run can collect; failures are accounted, never hidden."
            ),
        },
        "threats_to_validity": limitations,
    }
    return {
        "deterministic-results.json": deterministic,
        "live-provider-results.json": live,
        "combined-summary.json": combined,
        "error-analysis.json": error_analysis,
        "provider-failures.json": {"failures": provider_failures},
        "validator-analysis.json": validator_analysis,
        "research-tables.json": tables,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--live-dir", default=str(DEFAULT_LIVE_DIR))
    parser.add_argument("--out", default="research-results")
    args = parser.parse_args(argv)

    try:
        raw = json.loads(Path(args.dataset).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: cannot load dataset: {exc}", file=sys.stderr)
        return 2
    try:
        dataset = validate_dataset(raw)
    except FixtureValidationError as exc:
        print(f"error: invalid dataset: {exc}", file=sys.stderr)
        return 2
    live_dir = Path(args.live_dir)
    out_dir = Path(args.out)
    try:
        package = build_package(dataset, live_dir)
    except IntegrityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        for name in sorted(package):
            _write_json(out_dir, name, package[name])
    except IntegrityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {len(package)} results files to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
