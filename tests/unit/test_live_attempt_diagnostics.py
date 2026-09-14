"""Persisted attempt diagnostics (M19): sanitized detail reaches evaluation.

Every test here is offline: scripted doubles stand in for the provider,
no network call is made, and the suite exercises the shipped
``collect_transcripts()`` -> ``evaluate_attempts()`` -> ``main()``
path rather than re-implementing the mapping.
"""

from __future__ import annotations

import json
import pathlib

import pytest  # noqa: TC002 - runtime fixture/param use via pytest conventions
from scripts import collect_live_transcripts as collector_script

from src.research.live_metrics import evaluate_attempts
from src.research.live_prompts import get_prompt_set

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")
_FAKE_KEY = "k" * 30


def _dataset() -> dict:
    return json.loads(DATASET_PATH.read_text())


def _env() -> dict[str, str]:
    return {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": _FAKE_KEY}


class _FailingAgent:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.model = "fake-live-model"

    def respond(self, **_kwargs: object) -> str:
        raise self._exc


def test_provider_failure_diagnostic_persisted() -> None:
    from src.research.live_collect import collect_transcripts

    summary = collect_transcripts(
        _dataset(),
        out_dir=pathlib.Path(__import__("tempfile").mkdtemp()),
        agent=_FailingAgent(RuntimeError("gemini error 503: overloaded, try again")),
        environment=_env(),
    )
    metrics = evaluate_attempts(summary["attempts"], [])
    diagnostics = metrics["attempt_diagnostics"]
    assert len(diagnostics) == 12
    assert {d["outcome"] for d in diagnostics} == {"provider_failed"}
    assert all("RuntimeError" in d["detail"] and "code=503" in d["detail"] for d in diagnostics)


def test_diagnostic_only_carries_allowed_keys() -> None:
    metrics = evaluate_attempts(
        [
            {
                "question_id": "q01",
                "outcome": "completed_accepted",
                "detail": "",
                "extra": "must not leak",
            }
        ],
        [],
    )
    assert metrics["attempt_diagnostics"] == [
        {"question_id": "q01", "outcome": "completed_accepted", "detail": ""}
    ]


def test_diagnostic_sanitized_and_secret_free() -> None:
    from src.research.live_collect import collect_transcripts

    secret = "sk-abcdefghij1234567890"
    message = (
        f"gemini error 401: unauthorized; key {secret}; "
        "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig; password: hunter2-hunter; "
        "Cookie: session=abc123; postgres://user:pass@host/db; "
        "-----BEGIN PRIVATE KEY-----; https://user:s3cret@example.com/v1; "
        "GEMINI_API_KEY=supersecret123"
    )
    summary = collect_transcripts(
        _dataset(),
        out_dir=pathlib.Path(__import__("tempfile").mkdtemp()),
        agent=_FailingAgent(RuntimeError(message)),
        environment=_env(),
    )
    metrics = evaluate_attempts(summary["attempts"], [])
    blob = json.dumps(metrics["attempt_diagnostics"])
    for leaked in (
        secret,
        "eyJhbGciOiJIUzI1NiJ9",
        "hunter2-hunter",
        "session=abc123",
        "user:pass@host",
        "s3cret@example.com",
        "supersecret123",
        "PRIVATE KEY",
    ):
        assert leaked not in blob
    assert "[redacted" in blob


def test_request_and_evidence_text_absent() -> None:
    from src.research.live_collect import collect_transcripts

    class _RecordingAgent:
        model = "fake-live-model"

        def __init__(self) -> None:
            self.seen: dict = {}

        def respond(self, **kwargs: object) -> str:
            self.seen = dict(kwargs)
            raise RuntimeError("gemini error 500: boom")

    agent = _RecordingAgent()
    summary = collect_transcripts(
        _dataset(),
        out_dir=pathlib.Path(__import__("tempfile").mkdtemp()),
        agent=agent,
        environment=_env(),
    )
    metrics = evaluate_attempts(summary["attempts"], [])
    for diagnostic in metrics["attempt_diagnostics"]:
        assert agent.seen["context_block"] not in diagnostic["detail"]
        assert agent.seen["user_message"] not in diagnostic["detail"]


def test_diagnostics_bounded() -> None:
    metrics = evaluate_attempts(
        [{"question_id": "q01", "outcome": "provider_failed", "detail": "x" * 5000}],
        [],
    )
    assert len(metrics["attempt_diagnostics"]) == 1
    assert len(metrics["attempt_diagnostics"][0]["detail"]) <= 500


def test_diagnostics_follow_frozen_prompt_order() -> None:
    from src.research.live_collect import collect_transcripts

    summary = collect_transcripts(
        _dataset(),
        out_dir=pathlib.Path(__import__("tempfile").mkdtemp()),
        agent=_FailingAgent(RuntimeError("gemini error 500: boom")),
        environment=_env(),
    )
    metrics = evaluate_attempts(summary["attempts"], [])
    expected = [p.question_id for p in get_prompt_set()]
    assert [d["question_id"] for d in metrics["attempt_diagnostics"]] == expected


def test_all_outcome_kinds_preserved() -> None:
    attempts = [
        {"question_id": "q01", "outcome": "completed_accepted", "detail": ""},
        {"question_id": "q02", "outcome": "provider_failed", "detail": "E | code=500 | msg=boom"},
        {"question_id": "q03", "outcome": "timeout", "detail": "T | code=unknown | msg=timed out"},
        {
            "question_id": "q04",
            "outcome": "rejected_sanitization",
            "detail": "credential patterns: ['bearer-token']",
        },
        {"question_id": "q05", "outcome": "empty_response", "detail": "empty reply"},
    ]
    diagnostics = evaluate_attempts(attempts, [])["attempt_diagnostics"]
    assert [(d["question_id"], d["outcome"]) for d in diagnostics] == [
        ("q01", "completed_accepted"),
        ("q02", "provider_failed"),
        ("q03", "timeout"),
        ("q04", "rejected_sanitization"),
        ("q05", "empty_response"),
    ]
    assert diagnostics[1]["detail"] == "E | code=500 | msg=boom"


def test_empty_attempts() -> None:
    metrics = evaluate_attempts([], [])
    assert metrics["attempt_diagnostics"] == []
    assert metrics["attempts_total"] == 0
    assert metrics["validator_acceptance_rate"] is None
    assert metrics["citation_validity_mean"] is None


def test_existing_aggregate_fields_unchanged() -> None:
    attempts = [
        {"question_id": "q01", "outcome": "completed_accepted", "detail": "", "adversarial": False},
        {
            "question_id": "q02",
            "outcome": "completed_rejected",
            "detail": "bad",
            "adversarial": True,
        },
        {"question_id": "q03", "outcome": "timeout", "detail": "t", "adversarial": False},
    ]
    replays = [{"accepted": True, "citation_validity": 1.0}, {"accepted": False}]
    metrics = evaluate_attempts(attempts, replays)
    assert metrics["attempts_total"] == 3
    assert metrics["attempts_by_outcome"] == {
        "completed_accepted": 1,
        "completed_rejected": 1,
        "timeout": 1,
    }
    assert metrics["validator_acceptance_rate"] == 0.5
    assert metrics["citation_validity_mean"] == 1.0
    assert metrics["unsupported_claim_rate"] == 0.5
    assert metrics["adversarial_total"] == 1
    assert metrics["adversarial_completed"] == 1


def test_main_persists_diagnostics_through_real_path(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Real main() writes attempt_diagnostics into live-evaluation.json."""

    class _AlwaysFailing:
        def __init__(self, api_key: str = "", *, model: str = "") -> None:  # noqa: ARG002 - signature must match the real agent constructor
            self.model = model

        def respond(self, **_kwargs: object) -> str:
            raise RuntimeError("gemini error 503: overloaded, try again")

    monkeypatch.setattr(
        "src.infrastructure.ai.gemini_chat_agent.GeminiConversationAgent", _AlwaysFailing
    )
    monkeypatch.setattr("src.infrastructure.secrets.get_gemini_api_key", lambda: _FAKE_KEY)
    monkeypatch.setenv("RESEARCH_LIVE_PROVIDER", "1")
    monkeypatch.setenv("GEMINI_API_KEY", _FAKE_KEY)
    monkeypatch.setenv("LIVE_PROVIDER_MODEL", "diag-e2e-model")

    assert (
        collector_script.main(["--out", str(tmp_path), "--dataset", str(DATASET_PATH.resolve())])
        == 0
    )

    evaluation = json.loads((tmp_path / "live-evaluation.json").read_text())
    diagnostics = evaluation["attempt_diagnostics"]
    assert len(diagnostics) == 12
    assert {d["outcome"] for d in diagnostics} == {"provider_failed"}
    assert [d["question_id"] for d in diagnostics] == [p.question_id for p in get_prompt_set()]
    assert all(set(d) == {"question_id", "outcome", "detail"} for d in diagnostics)
    assert all("overloaded" in d["detail"] for d in diagnostics)
    assert evaluation["attempts_by_outcome"] == {"provider_failed": 12}
