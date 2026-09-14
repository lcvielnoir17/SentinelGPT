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
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.domain.investigation.prompts import build_evidence_block, build_system_instructions
from src.domain.investigation.validator import validate_investigation_response
from src.research.live_config import LiveConfig, resolve_config
from src.research.live_errors import is_retryable_provider_error, sanitize_provider_error
from src.research.live_evidence import build_live_evidence
from src.research.live_prompts import get_prompt_set
from src.research.live_sanitize import scan_response
from src.research.pipeline import run_sentinelgpt

if TYPE_CHECKING:
    from pathlib import Path

ProviderFactory = Callable[[], Any]
Sleeper = Callable[[float], None]

# Pacing between provider calls (seconds): keeps a 12-prompt run under
# free-tier request rates. One bounded retry per prompt on retryable
# transport errors, honoring the server's retry-after hint when present
# (capped); every prompt still yields exactly one attempt row.
PACING_DELAY_S = 12.0
RETRY_AFTER_CAP_S = 120.0
MAX_CALL_RETRIES = 1

_FENCE_RE = re.compile(r"\A\s*```(?:json)?[ \t]*\r?\n?(.*?)\r?\n?\s*```\s*\Z", re.DOTALL)
_RETRY_AFTER_RE = re.compile(r"retry in ([\d.]+)\s*s", re.IGNORECASE)


class ProviderUnavailableError(Exception):
    """The provider could not be constructed or reached."""


def collect_transcripts(
    dataset: dict[str, Any],
    *,
    out_dir: Path,
    provider_factory: ProviderFactory | None = None,
    environment: dict[str, str] | None = None,
    agent: Any | None = None,
    pace_seconds: float = 0,
    sleeper: Sleeper | None = None,
) -> dict[str, Any]:
    """Collect one transcript per prompt (all attempts accounted).

    ``agent`` injects a test double directly (bypassing the gate is
    impossible: doubles are explicit, never silent). Returns a run
    summary; transcripts land as individual JSON files in ``out_dir``.
    Stale per-question files from a previous run are removed first so a
    rerun can never silently reuse them. ``pace_seconds`` spaces
    provider calls (the live entry point passes ``PACING_DELAY_S``);
    at most one bounded retry per prompt applies to retryable
    transport errors only — every prompt still yields exactly one
    attempt row, so there is never a retry storm.
    """
    from src.research.schema import DATASET_VERSION

    config = resolve_config(environment)
    out_dir.mkdir(parents=True, exist_ok=True)
    _clear_stale_transcripts(out_dir)
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
    sleep = sleeper or time.sleep
    for index, prompt in enumerate(get_prompt_set()):
        if index > 0 and pace_seconds > 0:
            sleep(pace_seconds)
        attempts.append(_collect_one(by_id, prompt, provider, config, out_dir, pace_seconds, sleep))
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


def _clear_stale_transcripts(out_dir: Path) -> None:
    """Remove previous-run per-question files (frozen names only).

    Only the 12 ``{question_id}.json`` files the collector itself
    writes are touched; aggregates, foreign files, and anything else
    in the directory are left alone.
    """
    for prompt in get_prompt_set():
        try:
            (out_dir / f"{prompt.question_id}.json").unlink(missing_ok=True)
        except OSError:
            continue


def _retry_delay_s(exc: BaseException, pace_seconds: float) -> float:
    """Bounded wait before the single retry (server hint wins, capped)."""
    try:
        match = _RETRY_AFTER_RE.search(str(exc))
        hinted = float(match.group(1)) if match else 0
    except (ValueError, TypeError):
        hinted = 0
    if hinted > 0:
        return min(hinted, RETRY_AFTER_CAP_S)
    return pace_seconds if pace_seconds > 0 else 0


def _collect_one(
    by_id: dict[str, dict[str, Any]],
    prompt: Any,
    provider: Any,
    config: LiveConfig,
    out_dir: Path,
    pace_seconds: float = 0,
    sleeper: Sleeper | None = None,
) -> dict[str, Any]:
    """One prompt attempt: call, sanitize, validate, store, account."""
    from src.research.transcripts import TRANSCRIPT_VERSION, evidence_hash

    fixture = by_id.get(prompt.fixture_id)
    if fixture is None:
        return _attempt(prompt, "failed", "unknown fixture", None)
    output = run_sentinelgpt(fixture)
    evidence = build_live_evidence(output["groups"])
    block = build_evidence_block(evidence, question=prompt.question)
    sleep = sleeper or time.sleep
    retries_left = MAX_CALL_RETRIES
    retried = False
    while True:
        try:
            raw = provider.respond(
                system_instructions=build_system_instructions(),
                history=[],
                user_message=prompt.question,
                context_block=block,
            )
            break
        except Exception as exc:  # noqa: BLE001 - every failure is data
            name = type(exc).__name__
            if "timeout" in name.lower() or "Timeout" in str(exc):
                return _attempt(prompt, "timeout", sanitize_provider_error(exc), None)
            if retries_left > 0 and is_retryable_provider_error(exc):
                retries_left -= 1
                retried = True
                delay = _retry_delay_s(exc, pace_seconds)
                if delay > 0:
                    sleep(delay)
                continue
            detail = sanitize_provider_error(exc)
            if retried:
                detail = f"retried once; {detail}"[:500]
            return _attempt(prompt, "provider_failed", detail, None)
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
    """Best-effort JSON decode; malformed stays a dict for the validator.

    A surrounding markdown fence (```json ... ```) is transport
    formatting, not content: it is unwrapped before parsing so a
    schema-shaped reply is not misrecorded as malformed. Anything
    else unparseable still fails closed for the validator.
    """
    text = raw.strip()
    fenced = _FENCE_RE.match(text)
    if fenced:
        text = fenced.group(1).strip()
    try:
        parsed = json.loads(text)
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
