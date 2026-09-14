"""Live collection runner (M19): opt-in provider calls with full accounting.

Every prompt attempt is recorded — completed, rejected, failed, or
timed out — and nothing is ever deleted. The provider is injected
(default: the shared conversation agent built from the environment
key); replay and metrics never touch it. Collection writes only to
the caller-chosen quarantine directory, never into the repository or
the deterministic dataset.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.domain.investigation.prompts import build_evidence_block, build_system_instructions
from src.domain.investigation.validator import validate_investigation_response
from src.research.live_config import LiveConfig, resolve_config
from src.research.live_evidence import build_live_evidence
from src.research.live_prompts import get_prompt_set
from src.research.live_sanitize import scan_response
from src.research.pipeline import run_sentinelgpt

if TYPE_CHECKING:
    from pathlib import Path

ProviderFactory = Callable[[], Any]


class ProviderUnavailableError(Exception):
    """The provider could not be constructed or reached."""


def collect_transcripts(
    dataset: dict[str, Any],
    *,
    out_dir: Path,
    provider_factory: ProviderFactory | None = None,
    environment: dict[str, str] | None = None,
    agent: Any | None = None,
) -> dict[str, Any]:
    """Collect one transcript per prompt (all attempts accounted).

    ``agent`` injects a test double directly (bypassing the gate is
    impossible: doubles are explicit, never silent). Returns a run
    summary; transcripts land as individual JSON files in ``out_dir``.
    """
    from src.research.schema import DATASET_VERSION

    config = resolve_config(environment)
    out_dir.mkdir(parents=True, exist_ok=True)
    by_id = {f["id"]: f for f in dataset["fixtures"]}
    attempts: list[dict[str, Any]] = []
    stored = 0
    provider = agent
    if provider is None:
        if provider_factory is None:
            return _aborted_run(
                config, dataset, "no provider factory supplied (opt-in agent required)"
            )
        try:
            provider = provider_factory()
        except Exception as exc:  # noqa: BLE001 - accounted, not raised
            return _aborted_run(config, dataset, f"provider unavailable: {type(exc).__name__}")
    for prompt in get_prompt_set():
        attempts.append(_collect_one(by_id, prompt, provider, config, out_dir))
        stored += 1 if attempts[-1]["transcript_file"] is not None else 0
    return {
        "collection": "live-provider",
        "dataset_version": dataset.get("dataset_version", DATASET_VERSION),
        "provider": config.provider,
        "model": _model_of(provider),
        "prompt_version": "sgpt.live-prompts.v1",
        "attempts": attempts,
        "transcripts_stored": stored,
    }


def _aborted_run(config: LiveConfig, dataset: dict[str, Any], reason: str) -> dict[str, Any]:
    from src.research.schema import DATASET_VERSION

    return {
        "collection": "live-provider",
        "dataset_version": dataset.get("dataset_version", DATASET_VERSION),
        "provider": config.provider,
        "model": config.model,
        "prompt_version": "sgpt.live-prompts.v1",
        "attempts": [],
        "transcripts_stored": 0,
        "aborted": reason,
    }


def _collect_one(
    by_id: dict[str, dict[str, Any]],
    prompt: Any,
    provider: Any,
    config: LiveConfig,
    out_dir: Path,
) -> dict[str, Any]:
    """One prompt attempt: call, sanitize, validate, store, account."""
    from src.research.transcripts import TRANSCRIPT_VERSION, evidence_hash

    fixture = by_id.get(prompt.fixture_id)
    if fixture is None:
        return _attempt(prompt, "failed", "unknown fixture", None)
    output = run_sentinelgpt(fixture)
    evidence = build_live_evidence(output["groups"])
    block = build_evidence_block(evidence, question=prompt.question)
    try:
        raw = provider.respond(
            system_instructions=build_system_instructions(),
            history=[],
            user_message=prompt.question,
            context_block=block,
        )
    except Exception as exc:  # noqa: BLE001 - every failure is data
        name = type(exc).__name__
        if "timeout" in name.lower() or "Timeout" in str(exc):
            return _attempt(prompt, "timeout", name, None)
        return _attempt(prompt, "provider_failed", name, None)
    if not isinstance(raw, str) or not raw.strip():
        return _attempt(prompt, "empty_response", "empty reply", None)
    hits = scan_response(raw)
    if hits:
        return _attempt(prompt, "rejected_sanitization", f"credential patterns: {hits}", None)
    from src.research.transcripts import canonical_evidence_views

    views = canonical_evidence_views(output["groups"])
    filename = f"{prompt.question_id}.json"
    transcript = {
        "transcript_version": TRANSCRIPT_VERSION,
        "provider": config.provider,
        "model": _model_of(provider),
        "model_version": None,
        "evaluated_at": datetime.now(UTC).isoformat(),
        "question_id": prompt.question_id,
        "question": prompt.question,
        "fixture_id": prompt.fixture_id,
        "pipeline": "sentinelgpt",
        "evidence_hash": evidence_hash(views),
        "response": _coerce_response(raw),
    }
    (out_dir / filename).write_text(json.dumps(transcript, indent=2) + "\n")
    checked = validate_investigation_response(transcript["response"], evidence)
    outcome = "completed_accepted" if checked.accepted else "completed_rejected"
    return _attempt(prompt, outcome, "; ".join(checked.errors) if checked.errors else "", filename)


def _attempt(prompt: Any, outcome: str, detail: str, transcript_file: str | None) -> dict[str, Any]:
    return {
        "question_id": prompt.question_id,
        "fixture_id": prompt.fixture_id,
        "adversarial": bool(prompt.adversarial),
        "outcome": outcome,
        "detail": detail[:500],
        "transcript_file": transcript_file,
    }


def _coerce_response(raw: str) -> dict[str, Any]:
    """Best-effort JSON decode; malformed stays a dict for the validator."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"__malformed__": raw[:2000]}
    return parsed if isinstance(parsed, dict) else {"__malformed__": str(parsed)[:2000]}


def _model_of(provider: Any) -> str:
    model = getattr(provider, "model", None)
    return str(model) if isinstance(model, str) and model else "unknown"


__all__ = [
    "ProviderUnavailableError",
    "collect_transcripts",
]
