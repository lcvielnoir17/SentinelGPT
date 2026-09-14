"""Live-provider transcript collection (M19): framework verified offline.

Every test here runs without credentials, network, or provider: fake
agents stand in for Gemini, and the suite asserts the collection
machinery (opt-in gating, quarantine, sanitization, accounting,
replay, metrics, review sheets, artifacts) rather than any live
result. A separate live run — requiring RESEARCH_LIVE_PROVIDER=1
plus a real key — is the only path that ever touches the provider.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from src.research.live_collect import ProviderUnavailableError, collect_transcripts
from src.research.live_config import (
    DEFAULT_MODEL,
    MODEL_VARIABLE,
    CollectionNotEnabledError,
    collection_status,
    resolve_config,
)
from src.research.live_discovery import TranscriptDiscoveryError, discover_transcripts
from src.research.live_prompts import PROMPT_VERSION, get_prompt_set
from src.research.live_sanitize import scan_response
from src.research.schema import validate_dataset
from src.research.transcripts import validate_transcript

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")


def _dataset() -> dict:
    return validate_dataset(json.loads(DATASET_PATH.read_text()))


class FakeAgent:
    """Scripted provider double (explicit, never mistaken for live)."""

    def __init__(self, reply: object, *, model: str = "fake-live-model") -> None:
        self.reply = reply
        self.model = model
        self.calls: list[dict] = []

    def respond(self, **kwargs: object) -> object:
        self.calls.append(dict(kwargs))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def _answer(finding_id: str = "fp", control_id: str = "2.2") -> dict:
    return {
        "summary": "One open gap.",
        "key_points": ["note"],
        "citations": [{"finding_id": finding_id, "note": "open"}],
        "recommended_actions": ["Harden the header"],
        "compliance_notes": [{"control_id": control_id, "note": "gap"}],
    }


# --------------------------------------------------------------------------- #
# Opt-in gating                                                               #
# --------------------------------------------------------------------------- #


def test_collection_off_by_default() -> None:
    assert collection_status({}).will_collect is False
    assert collection_status({"RESEARCH_LIVE_PROVIDER": "0"}).will_collect is False
    assert (
        collection_status({"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": ""}).will_collect
        is False
    )
    assert (
        collection_status(
            {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "example-key"}
        ).will_collect
        is False
    )
    assert (
        collection_status(
            {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "real-secret-value-12345"}
        ).will_collect
        is True
    )
    with pytest.raises(CollectionNotEnabledError):
        resolve_config({})
    config = resolve_config(
        {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "real-secret-value-12345"}
    )
    assert config.provider == "google-genai" and config.enabled is True


# --------------------------------------------------------------------------- #
# Research model configuration (M19 only)                                     #
# --------------------------------------------------------------------------- #


def _opt_in_env() -> dict[str, str]:
    return {"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "real-secret-value-12345"}


def test_live_default_model_is_gemini_25_flash() -> None:
    """M19 default no longer points at the retired gemini-2.0-flash."""
    assert DEFAULT_MODEL == "gemini-2.5-flash"
    config = resolve_config(_opt_in_env())
    assert config.model == "gemini-2.5-flash"
    assert config.model != "gemini-2.0-flash"


def test_live_model_env_override() -> None:
    """LIVE_PROVIDER_MODEL selects the research model without touching opt-in."""
    env = _opt_in_env() | {MODEL_VARIABLE: "gemini-2.5-pro"}
    assert resolve_config(env).model == "gemini-2.5-pro"
    assert MODEL_VARIABLE == "LIVE_PROVIDER_MODEL"


def test_live_model_blank_falls_back_to_default() -> None:
    """Blank/whitespace override falls back to the safe default."""
    for blank in ("", "   "):
        env = _opt_in_env() | {MODEL_VARIABLE: blank}
        assert resolve_config(env).model == DEFAULT_MODEL


def test_live_model_config_never_holds_key_material() -> None:
    """Resolved config and gate reasons stay secret-free."""
    secret = "real-secret-value-12345"
    env = _opt_in_env() | {MODEL_VARIABLE: "gemini-2.5-flash"}
    config = resolve_config(env)
    assert secret not in repr(config)
    assert secret not in config.reason
    status = collection_status(env)
    assert secret not in status.reason


def test_live_selected_model_reaches_metadata(tmp_path: pathlib.Path) -> None:
    """The configured model is what the collector records in live metadata."""
    import json as _json

    from src.research.live_artifacts import write_artifacts

    config = resolve_config(_opt_in_env() | {MODEL_VARIABLE: "gemini-2.5-flash"})
    metadata = {"provider": config.provider, "model": config.model}
    names = write_artifacts(
        tmp_path,
        transcripts=[],
        replays=[],
        metrics={},
        metadata=metadata,
    )
    assert "live-metadata.json" in names
    stored = _json.loads((tmp_path / "live-metadata.json").read_text())
    assert stored["model"] == "gemini-2.5-flash"


# --------------------------------------------------------------------------- #
# Prompt set frozen                                                           #
# --------------------------------------------------------------------------- #


def test_prompt_set_predeclared_and_stable() -> None:
    prompts = get_prompt_set()
    assert len(prompts) == 12
    assert [p.question_id for p in prompts] == sorted(p.question_id for p in prompts)
    assert sum(1 for p in prompts if p.adversarial) == 3
    fixture_ids = {f["id"] for f in _dataset()["fixtures"]}
    for prompt in prompts:
        assert prompt.fixture_id in fixture_ids, prompt.question_id
        assert prompt.question and len(prompt.question) <= 2000
    assert PROMPT_VERSION == "sgpt.live-prompts.v1"


# --------------------------------------------------------------------------- #
# Sanitizer                                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text",
    [
        "sk-abcdefghij1234567890",
        "AIzaSyAbcdefghij1234567890",
        "-----BEGIN PRIVATE KEY-----",
        "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "password: hunter2-hunter",
        "postgres://user:pass@host/db",
        "Cookie: session=abc123",
        "firebase private_key: secret",
    ],
)
def test_sanitizer_rejects_credential_material(text: str) -> None:
    assert scan_response(text)


@pytest.mark.parametrize(
    "text",
    [
        "One open gap on the HSTS header.",
        "Recovery codes let users sign in without a TOTP device.",
        "Review the password policy with the team.",
        "CVE-2024-1234 appears in the evidence.",
        "Patch the header configuration.",
    ],
)
def test_sanitizer_passes_security_prose(text: str) -> None:
    assert scan_response(text) == []


def test_sanitizer_rejects_oversized_and_non_text() -> None:
    assert scan_response("x" * 131_073)
    assert scan_response(42)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Collection with doubles (no network, no key)                                #
# --------------------------------------------------------------------------- #


def test_collection_records_every_attempt(tmp_path: pathlib.Path) -> None:
    """Accepted, rejected, failed, and timed-out attempts are all kept."""
    from src.research.live_collect import ProviderUnavailableError as _Unavailable

    class FlakyAgent(FakeAgent):
        def __init__(self) -> None:
            super().__init__(None)
            self.n = 0

        def respond(self, **kwargs: object) -> object:
            self.calls.append(dict(kwargs))
            self.n += 1
            if self.n == 1:
                return json.dumps(_answer(finding_id="nope"))
            if self.n == 2:
                raise TimeoutError("slow provider")
            if self.n == 3:
                return "not json at all {{{"
            if self.n == 4:
                return json.dumps(_answer(finding_id="fp"))
            raise _Unavailable("down")

    agent = FlakyAgent()
    summary = collect_transcripts(
        _dataset(),
        out_dir=tmp_path,
        agent=agent,
        environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "k" * 30},
    )
    # Gate needs a usable key: 30-char key passes the length check.
    assert summary["transcripts_stored"] >= 1
    outcomes = [a["outcome"] for a in summary["attempts"]]
    assert len(outcomes) == 12  # every prompt accounted, none dropped
    assert "completed_rejected" in outcomes  # unknown citation
    assert "timeout" in outcomes
    assert set(outcomes) >= {"completed_rejected", "timeout"}
    # Sanitization rejects never reach disk either.
    assert summary["transcripts_stored"] <= 12


def test_collection_requires_opt_in_even_with_agent(tmp_path: pathlib.Path) -> None:
    agent = FakeAgent(json.dumps(_answer()))
    with pytest.raises(CollectionNotEnabledError):
        collect_transcripts(_dataset(), out_dir=tmp_path, agent=agent, environment={})
    assert list(tmp_path.iterdir()) == []  # quarantine untouched


def test_collection_aborts_cleanly_on_factory_failure(tmp_path: pathlib.Path) -> None:
    from src.research.live_collect import collect_transcripts as collect

    def broken() -> object:
        raise ProviderUnavailableError("no key")

    summary = collect(
        _dataset(),
        out_dir=tmp_path,
        provider_factory=broken,
        environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "k" * 30},
    )
    assert summary["transcripts_stored"] == 0
    assert summary["aborted"].startswith("provider unavailable")


def test_sanitization_reject_never_persisted(tmp_path: pathlib.Path) -> None:
    agent = FakeAgent(json.dumps(_answer()) + "\nBearer abcdefghij1234567890")
    summary = collect_transcripts(
        _dataset(),
        out_dir=tmp_path,
        agent=agent,
        environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "k" * 30},
    )
    assert all(a["outcome"] == "rejected_sanitization" for a in summary["attempts"])
    assert summary["transcripts_stored"] == 0
    assert list(tmp_path.iterdir()) == []


def test_malformed_and_empty_replies_recorded(tmp_path: pathlib.Path) -> None:
    for reply in ("{{{", ""):
        agent = FakeAgent(reply)
        summary = collect_transcripts(
            {"dataset_version": "sgpt.research.v1", "fixtures": []},
            out_dir=tmp_path,
            agent=agent,
            environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "k" * 30},
        )
        # Empty dataset: every prompt fails closed, all twelve accounted.
        assert len(summary["attempts"]) == 12
        assert {a["outcome"] for a in summary["attempts"]} == {"failed"}


def test_evidence_hash_mismatch_rejected() -> None:
    """Replay fixtures from M16 cover hash mismatch; live format matches."""
    assert (
        validate_transcript(
            {
                "transcript_version": "sgpt.transcript.v1",
                "provider": "synthetic-test-double",
                "model": "scripted-reply-v1",
                "question": "q",
                "fixture_id": "dup-headers-01",
                "pipeline": "sentinelgpt",
                "evidence_hash": "0" * 64,
                "response": _answer(),
            }
        )["question"]
        == "q"
    )


# --------------------------------------------------------------------------- #
# Current-run transcript discovery (M19 fix)                                   #
#                                                                              #
# Every test below executes the shipped code path: collect_transcripts()       #
# writes per-question files, discover_transcripts() reads them back, and      #
# main() wires the whole pipeline. Nothing here re-implements discovery.      #
# --------------------------------------------------------------------------- #


def _collect_success(tmp_path: pathlib.Path) -> dict[str, Any]:
    """Run a fully successful collection into tmp_path with a FakeAgent."""
    agent = FakeAgent(json.dumps(_answer()))
    return collect_transcripts(
        _dataset(),
        out_dir=tmp_path,
        agent=agent,
        environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "k" * 30},
    )


def test_discover_fresh_success(tmp_path: pathlib.Path) -> None:
    """Fresh successful run: all 12 current-run transcripts are discovered."""
    summary = _collect_success(tmp_path)
    assert summary["transcripts_stored"] == 12

    transcripts = discover_transcripts(tmp_path)

    prompts = get_prompt_set()
    assert len(transcripts) == 12
    assert [t["fixture_id"] for t in transcripts] == [p.fixture_id for p in prompts]
    assert [t["question"] for t in transcripts] == [p.question for p in prompts]
    for transcript in transcripts:
        validate_transcript(transcript)  # every record passes the real schema
        assert transcript["response"]["summary"] == "One open gap."


def test_discover_all_twelve_replayed(tmp_path: pathlib.Path) -> None:
    """Discovered current-run transcripts flow into replay_all()."""
    from src.research.transcripts import replay_all

    _collect_success(tmp_path)
    transcripts = discover_transcripts(tmp_path)

    replays = replay_all(_dataset(), transcripts)

    assert len(replays) == 12
    assert all("accepted" in replay for replay in replays)


def test_discover_ignores_stale_artifacts(tmp_path: pathlib.Path) -> None:
    """Stale previous-run artifacts never contaminate the current run."""
    stale = {
        "transcript_version": "sgpt.transcript.v1",
        "provider": "synthetic-test-double",
        "model": "scripted-reply-v1",
        "question": "Stale question from an old run.",
        "fixture_id": "stale-fixture-00",
        "pipeline": "sentinelgpt",
        "evidence_hash": "0" * 64,
        "response": _answer(),
    }
    (tmp_path / "live-transcripts.json").write_text(json.dumps([stale]))
    (tmp_path / "live-transcripts.csv").write_text("transcript_id,stale\n")
    (tmp_path / "live-evaluation.json").write_text(json.dumps({"metrics": {}}))
    (tmp_path / "live-manual-review.csv").write_text("reviewer,stale\n")
    (tmp_path / "live-metadata.json").write_text(json.dumps({"version": "old"}))
    (tmp_path / "notes.json").write_text(json.dumps({"foreign": True}))

    _collect_success(tmp_path)
    transcripts = discover_transcripts(tmp_path)

    assert len(transcripts) == 12
    assert all(t["fixture_id"] != "stale-fixture-00" for t in transcripts)
    assert all("Stale question" not in t["question"] for t in transcripts)


def test_discover_empty_run(tmp_path: pathlib.Path) -> None:
    """A directory with no per-question files yields a clean empty result."""
    assert discover_transcripts(tmp_path) == []


def test_discover_provider_failures(tmp_path: pathlib.Path) -> None:
    """Failed prompts write no transcript files and stay accounted for."""
    agent = FakeAgent(RuntimeError("provider down"))
    summary = collect_transcripts(
        _dataset(),
        out_dir=tmp_path,
        agent=agent,
        environment={"RESEARCH_LIVE_PROVIDER": "1", "GEMINI_API_KEY": "k" * 30},
    )

    assert len(summary["attempts"]) == 12
    assert {a["outcome"] for a in summary["attempts"]} == {"provider_failed"}
    assert summary["transcripts_stored"] == 0
    assert discover_transcripts(tmp_path) == []


def test_discover_malformed_file_raises(tmp_path: pathlib.Path) -> None:
    """Corrupt evidence fails closed: the shipped code raises, naming the file."""
    (tmp_path / "q01-priority.json").write_text("not json {{{")

    with pytest.raises(TranscriptDiscoveryError, match="q01-priority"):
        discover_transcripts(tmp_path)


def test_discover_schema_invalid_file_raises(tmp_path: pathlib.Path) -> None:
    """A schema-invalid per-question file raises, naming the file."""
    (tmp_path / "q02-regression.json").write_text(json.dumps({"bogus": True}))

    with pytest.raises(TranscriptDiscoveryError, match="q02-regression"):
        discover_transcripts(tmp_path)


def test_artifacts_after_discovery(tmp_path: pathlib.Path) -> None:
    """Discovery output flows through replay/metrics into write_artifacts()."""
    from src.research.live_artifacts import write_artifacts
    from src.research.live_metrics import evaluate_attempts
    from src.research.transcripts import replay_all

    summary = _collect_success(tmp_path)
    transcripts = discover_transcripts(tmp_path)
    replays = replay_all(_dataset(), transcripts)
    metrics = evaluate_attempts(summary["attempts"], replays)
    names = write_artifacts(
        tmp_path,
        transcripts=transcripts,
        replays=replays,
        metrics=metrics,
        metadata={"provider": "p", "model": "m"},
    )

    assert names == [
        "live-transcripts.json",
        "live-transcripts.csv",
        "live-evaluation.json",
        "live-manual-review.csv",
        "live-metadata.json",
    ]
    stored = json.loads((tmp_path / "live-transcripts.json").read_text())
    assert isinstance(stored, list) and len(stored) == 12
    evaluation = json.loads((tmp_path / "live-evaluation.json").read_text())
    assert evaluation["attempts_total"] == 12


def test_main_end_to_end_with_fake_factory(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute the real main(): collect -> discover -> replay -> artifacts."""
    from scripts import collect_live_transcripts as collector_script

    agent = FakeAgent(json.dumps(_answer()))
    monkeypatch.setenv("RESEARCH_LIVE_PROVIDER", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "k" * 30)
    monkeypatch.setattr(collector_script, "default_provider_factory", lambda *_a, **_k: agent)

    exit_code = collector_script.main(
        ["--out", str(tmp_path), "--dataset", str(DATASET_PATH.resolve())]
    )

    assert exit_code == 0
    assert len(agent.calls) == 12
    stored = json.loads((tmp_path / "live-transcripts.json").read_text())
    assert isinstance(stored, list) and len(stored) == 12
    evaluation = json.loads((tmp_path / "live-evaluation.json").read_text())
    assert evaluation["attempts_total"] == 12
    assert evaluation["attempts_by_outcome"] != {"provider_failed": 12}


# --------------------------------------------------------------------------- #
# Metrics / review / artifacts (offline)                                      #
# --------------------------------------------------------------------------- #


def test_live_metrics_denominators() -> None:
    from src.research.live_metrics import evaluate_attempts

    attempts = [
        {"outcome": "completed_accepted", "adversarial": False},
        {"outcome": "completed_rejected", "adversarial": True},
        {"outcome": "timeout", "adversarial": False},
    ]
    replays = [
        {"accepted": True, "citation_validity": 1.0},
        {"accepted": False},
    ]
    metrics = evaluate_attempts(attempts, replays)
    assert metrics["attempts_total"] == 3
    assert metrics["attempts_by_outcome"]["timeout"] == 1
    assert metrics["validator_acceptance_rate"] == 0.5
    assert metrics["citation_validity_mean"] == 1.0
    assert metrics["unsupported_claim_rate"] == 0.5
    assert metrics["adversarial_total"] == 1
    assert metrics["adversarial_completed"] == 1
    empty = evaluate_attempts([], [])
    assert empty["validator_acceptance_rate"] is None
    assert empty["citation_validity_mean"] is None


def test_review_sheet_contract() -> None:
    from src.research.live_review import REVIEW_COLUMNS, review_sheet_csv, review_sheet_rows

    rows = review_sheet_rows(
        [
            {
                "question_id": "q01",
                "fixture_id": "f",
                "pipeline": "sentinelgpt",
                "provider": "p",
                "model": "m",
            }
        ],
        [{"fixture_id": "f", "pipeline": "sentinelgpt", "accepted": True, "reason": "ok"}],
    )
    assert rows[0]["automated_accept"] == "True"
    assert rows[0]["reviewer"] == ""
    text = review_sheet_csv(rows)
    assert text.splitlines()[0].split(",") == list(REVIEW_COLUMNS)


def test_artifacts_secret_free(tmp_path: pathlib.Path) -> None:
    from src.research.live_artifacts import write_artifacts

    names = write_artifacts(
        tmp_path,
        transcripts=[
            {
                "question_id": "q01",
                "fixture_id": "f",
                "pipeline": "sentinelgpt",
                "provider": "p",
                "model": "m",
            }
        ],
        replays=[
            {"fixture_id": "f", "provider": "p", "model": "m", "accepted": True, "reason": "ok"}
        ],
        metrics={"validator_acceptance_rate": 1.0},
        metadata={"provider": "p", "model": "m"},
    )
    assert names == [
        "live-transcripts.json",
        "live-transcripts.csv",
        "live-evaluation.json",
        "live-manual-review.csv",
        "live-metadata.json",
    ]
    blob = "".join((tmp_path / name).read_text() for name in names)
    for banned in ("GEMINI_API_KEY", "Bearer ", "PRIVATE KEY", "password"):
        assert banned not in blob


def test_replay_never_calls_provider() -> None:
    """replay_all takes no factory: provider independence is structural."""
    from src.research.transcripts import replay_all

    transcripts = [
        {
            "transcript_version": "sgpt.transcript.v1",
            "provider": "synthetic-test-double",
            "model": "scripted-reply-v1",
            "question": "q",
            "fixture_id": "dup-headers-01",
            "pipeline": "sentinelgpt",
            "evidence_hash": "0" * 64,
            "response": _answer(),
        }
    ]
    results = replay_all(_dataset(), transcripts)
    assert results[0]["accepted"] is False  # hash mismatch, no provider involved
