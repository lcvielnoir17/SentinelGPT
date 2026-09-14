"""Safe provider-error diagnostics (M19 debugging, offline only).

All provider failures here are scripted doubles — no network, no key,
no live call. The suite proves the diagnostic keeps the actionable
signal (class, code, retryability) while redacting secret material.
"""

from __future__ import annotations

import json
import pathlib

from src.research.live_collect import collect_transcripts
from src.research.live_errors import sanitize_provider_error


def _dataset() -> dict:
    path = pathlib.Path("backend/src/research/dataset.json")
    return json.loads(path.read_text())


def _env() -> dict[str, str]:
    return {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "k" * 30}


class _FailingAgent:
    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.model = "fake-live-model"

    def respond(self, **_kwargs: object) -> str:
        raise self._exc


def test_diagnostic_keeps_class_code_and_retryability() -> None:
    err = RuntimeError("gemini error 404: NOT_FOUND model is not available")
    diagnostic = sanitize_provider_error(err)
    assert "RuntimeError" in diagnostic
    assert "code=404" in diagnostic
    assert "retryable=no" in diagnostic
    assert "NOT_FOUND" in diagnostic


def test_diagnostic_marks_rate_limit_retryable() -> None:
    err = RuntimeError("gemini error 429: quota exceeded, retry later")
    assert "retryable=yes" in sanitize_provider_error(err)


def test_diagnostic_timeout_retryable() -> None:
    err = TimeoutError("request timed out after 30s")
    diagnostic = sanitize_provider_error(err)
    assert "TimeoutError" in diagnostic
    assert "retryable=yes" in diagnostic


def test_diagnostic_redacts_secret_material() -> None:
    secret_key = "AIzaSyAbcdefghij1234567890"
    bearer = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    message = (
        f"gemini error 401: unauthorized; key {secret_key}; {bearer}; "
        "password: hunter2-hunter; Cookie: session=abc123; "
        "postgres://user:pass@host/db; -----BEGIN PRIVATE KEY-----; "
        "https://user:s3cret@example.com/v1; GEMINI_API_KEY=supersecret123"
    )
    diagnostic = sanitize_provider_error(RuntimeError(message))
    for leaked in (
        secret_key,
        "eyJhbGciOiJIUzI1NiJ9",
        "hunter2-hunter",
        "session=abc123",
        "user:pass@host",
        "s3cret@example.com",
        "supersecret123",
        "PRIVATE KEY",
    ):
        assert leaked not in diagnostic
    assert "[redacted" in diagnostic
    assert "code=401" in diagnostic


def test_diagnostic_never_exposes_evidence_or_request_body() -> None:
    """The diagnostic reads only the exception, never call arguments."""

    class _RecordingAgent:
        model = "fake-live-model"

        def __init__(self) -> None:
            self.seen: dict = {}

        def respond(self, **kwargs: object) -> str:
            self.seen = dict(kwargs)
            raise RuntimeError("gemini error 503: overloaded, try again")

    agent = _RecordingAgent()
    summary = collect_transcripts(
        _dataset(),
        out_dir=pathlib.Path(__import__("tempfile").mkdtemp()),
        agent=agent,
        environment=_env(),
    )
    assert {a["outcome"] for a in summary["attempts"]} == {"provider_failed"}
    for attempt in summary["attempts"]:
        detail = attempt["detail"]
        assert "overloaded" in detail
        assert "code=503" in detail
        # Request-side material never enters the diagnostic.
        assert "context_block" not in detail
        assert agent.seen["context_block"] not in detail
        assert agent.seen["user_message"] not in detail
        assert len(detail) <= 500


def test_collect_records_sanitized_detail_without_secret(tmp_path: pathlib.Path) -> None:
    secret = "sk-abcdefghij1234567890"
    agent = _FailingAgent(RuntimeError(f"gemini error 500: boom {secret}"))
    summary = collect_transcripts(_dataset(), out_dir=tmp_path, agent=agent, environment=_env())
    assert summary["transcripts_stored"] == 0
    assert {a["outcome"] for a in summary["attempts"]} == {"provider_failed"}
    for attempt in summary["attempts"]:
        assert secret not in attempt["detail"]
        assert "RuntimeError" in attempt["detail"]
        assert "code=500" in attempt["detail"]
