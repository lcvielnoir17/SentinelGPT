"""Recorded AI transcripts (M16-G/H/I): schema, hashing, offline replay.

Proves transcripts validate strictly (version, hash shape, required
fields), replay re-derives evidence and verifies hashes before the
M12 validator runs, mismatched evidence fails closed, unknown IDs
and invented CVEs fail validation, model identity is recorded
without fabrication, and replay is byte-deterministic offline.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from src.research.schema import validate_dataset
from src.research.transcripts import (
    TRANSCRIPT_VERSION,
    TranscriptValidationError,
    evidence_hash,
    replay_all,
    replay_transcript,
    validate_transcript,
)

TRANSCRIPT_DIR = pathlib.Path("backend/src/research/transcripts")
DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")


def _dataset() -> dict:
    return validate_dataset(json.loads(DATASET_PATH.read_text()))


def _load(name: str) -> dict:
    return json.loads((TRANSCRIPT_DIR / name).read_text())


def _views() -> list[dict]:
    return [
        {
            "fingerprint": "fp",
            "members": ["o1"],
            "severity": "HIGH",
            "category": "MISSING_SECURITY_HEADER",
            "lifecycle": "NEW",
            "priority_level": "P2",
            "remediation_status": None,
            "cves": [],
        }
    ]


def _transcript(**overrides: object) -> dict:
    base: dict[str, object] = {
        "transcript_version": TRANSCRIPT_VERSION,
        "provider": "synthetic-test-double",
        "model": "scripted-reply-v1",
        "model_version": None,
        "evaluated_at": "2026-09-01T00:00:00+00:00",
        "question": "What is open?",
        "fixture_id": "dup-headers-01",
        "pipeline": "sentinelgpt",
        "evidence_hash": "0" * 64,
        "response": {
            "summary": "x",
            "key_points": [],
            "citations": [],
            "recommended_actions": [],
            "compliance_notes": [],
        },
    }
    base.update(overrides)
    return base  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Schema                                                                      #
# --------------------------------------------------------------------------- #


def test_transcript_schema() -> None:
    clean = validate_transcript(_transcript())
    assert clean["transcript_version"] == TRANSCRIPT_VERSION == "sgpt.transcript.v1"
    for bad in (
        {},
        [],
        {**_transcript(), "transcript_version": "v0"},
        {**_transcript(), "provider": ""},
        {**_transcript(), "evidence_hash": "xyz"},
        {**_transcript(), "evidence_hash": "A" * 64},
        {**_transcript(), "response": []},
        {**_transcript(), "model_version": 5},
    ):
        with pytest.raises(TranscriptValidationError):
            validate_transcript(bad)


def test_seed_transcripts_validate() -> None:
    names = sorted(p.name for p in TRANSCRIPT_DIR.glob("*.json"))
    assert names == ["dup-headers-01-unknown-citation.json", "dup-headers-01-valid.json"]
    for name in names:
        validate_transcript(_load(name))


def test_seed_models_not_fabricated() -> None:
    """Seeds identify as synthetic doubles — never a real model version."""
    for name in ("dup-headers-01-valid.json", "dup-headers-01-unknown-citation.json"):
        transcript = _load(name)
        assert transcript["provider"] == "synthetic-test-double"
        assert transcript["model"] == "scripted-reply-v1"
        assert transcript["model_version"] is None


# --------------------------------------------------------------------------- #
# Hashing                                                                     #
# --------------------------------------------------------------------------- #


def test_evidence_hash_stable_and_sensitive() -> None:
    first = evidence_hash(_views())
    assert first == evidence_hash(_views())
    assert len(first) == 64
    altered = [_views()[0] | {"severity": "LOW"}]
    assert evidence_hash(altered) != first
    reordered = sorted(_views(), key=lambda v: v["fingerprint"])
    assert evidence_hash(reordered) == first


# --------------------------------------------------------------------------- #
# Replay                                                                      #
# --------------------------------------------------------------------------- #


def test_replay_accepts_valid() -> None:
    result = replay_transcript(_load("dup-headers-01-valid.json"), _dataset())
    assert result["accepted"] is True and result["hash_match"] is True
    assert result["citation_validity"] == 1.0
    assert result["provider"] == "synthetic-test-double"


def test_replay_rejects_unknown_citation() -> None:
    result = replay_transcript(_load("dup-headers-01-unknown-citation.json"), _dataset())
    assert result["hash_match"] is True
    assert result["accepted"] is False
    assert result["reason"] == "validator rejected reply"


def test_replay_rejects_hash_mismatch() -> None:
    tampered = _load("dup-headers-01-valid.json")
    tampered["evidence_hash"] = "1" * 64
    result = replay_transcript(tampered, _dataset())
    assert result["accepted"] is False and result["hash_match"] is False
    assert result["reason"] == "evidence hash mismatch"


def test_replay_rejects_unknown_fixture_and_pipeline() -> None:
    base = _load("dup-headers-01-valid.json")
    ghost = dict(base, fixture_id="nope")
    assert replay_transcript(ghost, _dataset())["reason"] == "unknown fixture"
    bad_pipe = dict(base, pipeline="sentinelgpt-v9")
    assert replay_transcript(bad_pipe, _dataset())["reason"] == "unknown pipeline"


def test_replay_invalid_transcript() -> None:
    with pytest.raises(TranscriptValidationError):
        replay_transcript({"nope": True}, _dataset())


def test_replay_all_and_determinism() -> None:
    transcripts = [
        _load("dup-headers-01-valid.json"),
        _load("dup-headers-01-unknown-citation.json"),
    ]
    first = replay_all(_dataset(), transcripts)
    second = replay_all(_dataset(), transcripts)
    assert first == second
    assert [r["accepted"] for r in first] == [True, False]


def test_replay_contains_no_secrets_or_network() -> None:
    """Static pins mirror the package guard (imports + embedded values)."""
    import pathlib as _pathlib
    import re as _re

    network_imports = (
        "import socket",
        "import httpx",
        "from httpx",
        "import requests",
        "from requests",
        "import google",
        "from google",
    )
    secret_value = _re.compile(
        r"(?:KEY|SECRET|TOKEN|PASSWORD)\s*=\s*[\"']([A-Za-z0-9+/=_-]{20,})[\"']"
    )
    hits = []
    for path in sorted((_pathlib.Path("backend/src/research")).rglob("*.py")):
        if path.name == "__init__.py":
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            for token in network_imports:
                if stripped.startswith(token):
                    hits.append(f"{path.name}:{i}:{token}")
            if secret_value.search(line) and "getenv" not in line and "environ" not in line:
                hits.append(f"{path.name}:{i}:embedded-secret")
    assert hits == []
