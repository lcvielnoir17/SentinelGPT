"""Recorded AI transcript support: schema, hashing, offline replay (M16-G/H).

Transcripts are OPTIONAL evidence that a provider once answered a
question over a deterministic evidence view. Replay never calls a
provider: it re-derives the evidence view from the pinned fixture,
checks the recorded hash, and runs the SAME M12 response validator
production uses. A hash mismatch, unknown ID, or unsupported claim
fails the replay — recorded transcripts prove validator mechanics,
never live provider accuracy.

Transcript rules: no API keys, no credentials, no production data.
Seed transcripts use provider ``synthetic-test-double`` with model
``scripted-reply-v1`` — model metadata is never fabricated.
``evaluated_at`` is provenance metadata only and is EXCLUDED from
everything deterministic (hashes, metrics).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

TRANSCRIPT_VERSION = "sgpt.transcript.v1"


class TranscriptValidationError(ValueError):
    """A recorded transcript failed schema validation."""


_REQUIRED_FIELDS = (
    "transcript_version",
    "provider",
    "model",
    "question",
    "fixture_id",
    "pipeline",
    "evidence_hash",
    "response",
)


def validate_transcript(raw: object) -> dict[str, Any]:
    """Validate a decoded transcript document (raises on any problem)."""
    if not isinstance(raw, dict):
        raise TranscriptValidationError("transcript must be a JSON object")
    for field_name in _REQUIRED_FIELDS:
        if raw.get(field_name) in (None, ""):
            raise TranscriptValidationError(f"transcript missing {field_name!r}")
    if raw["transcript_version"] != TRANSCRIPT_VERSION:
        raise TranscriptValidationError(f"transcript_version must be {TRANSCRIPT_VERSION!r}")
    for field_name in ("provider", "model", "question", "fixture_id", "pipeline"):
        if not isinstance(raw[field_name], str):
            raise TranscriptValidationError(f"transcript {field_name!r} must be text")
    evidence_hash = raw["evidence_hash"]
    if (
        not isinstance(evidence_hash, str)
        or len(evidence_hash) != 64
        or any(c not in "0123456789abcdef" for c in evidence_hash)
    ):
        raise TranscriptValidationError("evidence_hash must be 64 lowercase hex chars")
    if not isinstance(raw["response"], dict):
        raise TranscriptValidationError("transcript response must be an object")
    if raw.get("model_version") is not None and not isinstance(raw["model_version"], str):
        raise TranscriptValidationError("model_version must be text or null")
    return {
        "transcript_version": TRANSCRIPT_VERSION,
        "provider": raw["provider"],
        "model": raw["model"],
        "model_version": raw.get("model_version"),
        "evaluated_at": raw.get("evaluated_at"),
        "question": raw["question"],
        "fixture_id": raw["fixture_id"],
        "pipeline": raw["pipeline"],
        "evidence_hash": evidence_hash,
        "response": dict(raw["response"]),
    }


def canonical_evidence_views(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic finding views a transcript hash covers.

    Only stable identity/state fields participate — volatile timestamps
    and free-text evidence bodies are excluded so the hash is stable
    across runs and environments.
    """
    views = [
        {
            "fingerprint": str(g.get("fingerprint", "")),
            "members": sorted(str(m) for m in g.get("members", [])),
            "severity": g.get("severity"),
            "category": g.get("category"),
            "lifecycle": g.get("lifecycle"),
            "priority_level": g.get("priority_level"),
            "remediation_status": g.get("remediation_status"),
            "cves": sorted(str(c) for c in g.get("cves", [])),
        }
        for g in groups
    ]
    views.sort(key=lambda v: (v["fingerprint"], str(v["members"])))
    return views


def evidence_hash(views: list[dict[str, Any]]) -> str:
    """Hex digest of the canonical evidence encoding."""
    canonical = json.dumps(views, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def replay_transcript(transcript: dict[str, Any], dataset: dict[str, Any]) -> dict[str, Any]:
    """Offline replay: hash check + M12 validation + grounding metrics.

    Never calls any provider. ``hash_match`` gates everything: a
    transcript evaluated against different evidence is rejected before
    the validator even runs. Returns validator acceptance plus a
    citation-validity style summary over the single reply.
    """
    from src.domain.investigation.evidence import InvestigationEvidence
    from src.domain.investigation.validator import validate_investigation_response
    from src.research.evaluate import PIPELINES

    clean = validate_transcript(transcript)
    fixture = next((f for f in dataset["fixtures"] if f["id"] == clean["fixture_id"]), None)
    if fixture is None:
        return _replay_result(clean, False, "unknown fixture", hash_match=False)
    runner = PIPELINES.get(clean["pipeline"])
    if runner is None:
        return _replay_result(clean, False, "unknown pipeline", hash_match=False)
    output = runner(fixture)
    views = canonical_evidence_views(output["groups"])
    digest = evidence_hash(views)
    if digest != clean["evidence_hash"]:
        return _replay_result(clean, False, "evidence hash mismatch", hash_match=False)
    registries = _registries(output["groups"], views)
    evidence = InvestigationEvidence(
        target_id=str(fixture.get("hostname", "")),
        scan_id=None,
        scan_status=None,
        generated_at="1970-01-01T00:00:00+00:00",
        finding_ids=registries["finding_ids"],
        evidence_ids=frozenset(),
        control_ids=registries["control_ids"],
        cve_set=registries["cves"],
    )
    result = validate_investigation_response(clean["response"], evidence)
    if not result.accepted or result.answer is None:
        return _replay_result(clean, False, "validator rejected reply", errors=list(result.errors))
    citations = result.answer.get("citations", [])
    valid = sum(
        1
        for c in citations
        if isinstance(c, dict) and c.get("finding_id") in registries["finding_ids"]
    )
    return _replay_result(
        clean,
        True,
        "accepted",
        citation_validity=(valid / len(citations) if citations else None),
    )


def _registries(
    groups: list[dict[str, Any]], views: list[dict[str, Any]]
) -> dict[str, frozenset[str]]:
    """Citation allow-lists: fingerprints act as finding IDs in research."""
    finding_ids = frozenset(v["fingerprint"] for v in views if v["fingerprint"])
    cves: set[str] = set()
    for group in groups:
        for cve in group.get("cves", []):
            cves.add(str(cve))
    controls: set[str] = set()
    for group in groups:
        for pair in group.get("compliance", []):
            if isinstance(pair, list) and len(pair) == 2:
                controls.add(str(pair[1]))
    return {"finding_ids": finding_ids, "cves": frozenset(cves), "control_ids": frozenset(controls)}


def _replay_result(
    transcript: dict[str, Any],
    accepted: bool,
    reason: str,
    *,
    hash_match: bool = True,
    errors: list[str] | None = None,
    citation_validity: float | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "transcript_version": TRANSCRIPT_VERSION,
        "provider": transcript["provider"],
        "model": transcript["model"],
        "model_version": transcript.get("model_version"),
        "fixture_id": transcript["fixture_id"],
        "pipeline": transcript["pipeline"],
        "hash_match": hash_match,
        "accepted": accepted,
        "reason": reason,
    }
    if errors:
        result["validation_errors"] = errors
    if citation_validity is not None:
        result["citation_validity"] = citation_validity
    return result


def replay_all(dataset: dict[str, Any], transcripts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replay every supplied transcript (deterministic, offline)."""
    return [replay_transcript(t, dataset) for t in transcripts]


__all__ = [
    "TRANSCRIPT_VERSION",
    "TranscriptValidationError",
    "canonical_evidence_views",
    "evidence_hash",
    "replay_all",
    "replay_transcript",
    "validate_transcript",
]
