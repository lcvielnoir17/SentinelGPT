"""Live-transcript metrics (M19): acceptance over recorded attempts.

Every rate states its denominator explicitly; replays that never
produced a transcript (provider failures, timeouts, sanitization
rejects) count in attempt accounting but never in validator rates.
"Accuracy" is never claimed — these measure validator behavior on
genuine outputs, not model correctness.
"""

from __future__ import annotations

from typing import Any


def evaluate_attempts(
    attempts: list[dict[str, Any]], replays: list[dict[str, Any]]
) -> dict[str, Any]:
    """Metrics over one collection run (attempts + offline replays)."""
    total = len(attempts)
    by_outcome: dict[str, int] = {}
    for attempt in attempts:
        outcome = str(attempt.get("outcome", "unknown"))
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
    accepted = sum(1 for r in replays if r.get("accepted") is True)
    rejected = sum(1 for r in replays if r.get("accepted") is False)
    evaluated = len(replays)
    adversarial = [a for a in attempts if a.get("adversarial") is True]
    adversarial_completed = sum(
        1 for a in adversarial if str(a.get("outcome", "")).startswith("completed")
    )
    citation_values: list[float] = [
        float(value) for r in replays if (value := r.get("citation_validity")) is not None
    ]
    # Persisted per-attempt diagnostics (M19 debugging): the ONLY provider
    # error text allowed here is the already-sanitized, already-bounded
    # ``detail`` produced upstream (sanitize_provider_error output for
    # provider failures/timeouts; short accounting notes otherwise).
    # Order follows the input attempts (frozen prompt order); keys are
    # fixed to question_id/outcome/detail — no prompts, evidence,
    # bodies, keys, tokens, or traces.
    diagnostics = [
        {
            "question_id": str(attempt.get("question_id", "")),
            "outcome": str(attempt.get("outcome", "unknown")),
            "detail": str(attempt.get("detail", ""))[:500],
        }
        for attempt in attempts
    ]
    return {
        "attempts_total": total,
        "attempts_by_outcome": dict(sorted(by_outcome.items())),
        "attempt_diagnostics": diagnostics,
        "validator_acceptance_rate": (accepted / evaluated) if evaluated else None,
        "citation_validity_mean": (
            sum(citation_values) / len(citation_values) if citation_values else None
        ),
        "unsupported_claim_rate": (rejected / evaluated) if evaluated else None,
        "adversarial_completed": adversarial_completed,
        "adversarial_total": len(adversarial),
    }


__all__ = ["evaluate_attempts"]
