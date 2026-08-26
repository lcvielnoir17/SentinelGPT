"""Unit tests for the Gemini adapter using a fake SDK client (no network)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from google.genai import errors as genai_errors

from src.domain.scanning.analysis.correlation import build_candidate_groups
from src.domain.scanning.analysis.evidence import EvidenceSet
from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    AnalysisProviderError,
)
from tests.unit.test_ai_service import _result as _engine_result

MAX_RESPONSE = 262_144


def _evidence() -> EvidenceSet:
    return EvidenceSet.from_result(_engine_result())


class FakeModels:
    def __init__(self, script: Any) -> None:
        self.script = script
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        outcome = self.script
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeResponse:
    def __init__(self, text: str | None) -> None:
        self._text = text

    @property
    def text(self) -> str:
        if self._text is None:
            raise ValueError("response has no parts")
        return self._text


class FakeGenaiClient:
    def __init__(self, script: Any) -> None:
        self.models = FakeModels(script)


def _analyzer(script: Any, *, api_key: str = "test-key", timeout_s: float = 20.0):
    from src.infrastructure.ai.gemini_provider import GeminiEvidenceAnalyzer

    created: dict[str, Any] = {}

    def factory(key: str, timeout: float) -> FakeGenaiClient:
        created["api_key"] = key
        created["timeout_s"] = timeout
        return FakeGenaiClient(script)

    analyzer = GeminiEvidenceAnalyzer(api_key=api_key, timeout_s=timeout_s, client_factory=factory)
    return analyzer, created


def _groups() -> tuple:
    evidence = _evidence()
    return build_candidate_groups(evidence), evidence


def test_request_construction_json_mode_and_identity() -> None:
    valid = {"overall_summary": "s", "priority": "low"}
    analyzer, created = _analyzer(FakeResponse(json.dumps(valid)))
    groups, evidence = _groups()

    payload = analyzer.analyze(evidence, groups, system_instructions="SYS", user_prompt="USER")

    assert payload == valid
    assert created["api_key"] == "test-key"
    assert created["timeout_s"] == 20.0

    models = analyzer._client.models  # noqa: SLF001 - unit inspection
    call = models.calls[0]
    assert call["model"] == "gemini-2.0-flash-lite"
    assert call["contents"] == "USER"
    config = call["config"]
    assert config.response_mime_type == "application/json"
    assert config.system_instruction == "SYS"


def test_missing_api_key_fails_authentication_at_construction() -> None:
    with pytest.raises(AnalysisProviderError) as err:
        _analyzer(None, api_key="")
    assert err.value.kind is AnalysisFailureKind.AUTHENTICATION_FAILED


def test_timeout_exception_maps_to_timeout_kind() -> None:
    analyzer, _ = _analyzer(TimeoutError("deadline"))
    groups, evidence = _groups()
    with pytest.raises(AnalysisProviderError) as err:
        analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
    assert err.value.kind is AnalysisFailureKind.TIMEOUT


def test_chained_httpx_timeout_is_recognized() -> None:
    inner = TimeoutError("timed out")

    class Wrapped(Exception):
        pass

    wrapped = Wrapped("request failed")
    wrapped.__cause__ = inner

    analyzer, _ = _analyzer(wrapped)
    groups, evidence = _groups()
    with pytest.raises(AnalysisProviderError) as err:
        analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
    assert err.value.kind is AnalysisFailureKind.TIMEOUT


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (401, AnalysisFailureKind.AUTHENTICATION_FAILED),
        (403, AnalysisFailureKind.AUTHENTICATION_FAILED),
        (408, AnalysisFailureKind.TIMEOUT),
        (504, AnalysisFailureKind.TIMEOUT),
        (500, AnalysisFailureKind.PROVIDER_UNAVAILABLE),
        (429, AnalysisFailureKind.PROVIDER_UNAVAILABLE),
    ],
)
def test_api_error_codes_map_to_typed_failures(code: int, expected: AnalysisFailureKind) -> None:
    analyzer, _ = _analyzer(genai_errors.APIError(code, {"error": {"message": "x"}}))
    groups, evidence = _groups()
    with pytest.raises(AnalysisProviderError) as err:
        analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
    assert err.value.kind is expected


def test_generic_sdk_failure_maps_to_provider_unavailable() -> None:
    class Exploded(Exception):
        pass

    analyzer, _ = _analyzer(Exploded("socket dust"))
    groups, evidence = _groups()
    with pytest.raises(AnalysisProviderError) as err:
        analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
    assert err.value.kind is AnalysisFailureKind.PROVIDER_UNAVAILABLE
    assert err.value.detail == "Exploded"


def test_empty_and_blocked_responses_are_malformed() -> None:
    for fake in (FakeResponse(""), FakeResponse(None)):
        analyzer, _ = _analyzer(fake)
        groups, evidence = _groups()
        with pytest.raises(AnalysisProviderError) as err:
            analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
        assert err.value.kind is AnalysisFailureKind.MALFORMED_RESPONSE


def test_non_json_text_is_malformed() -> None:
    analyzer, _ = _analyzer(FakeResponse("I am a helpful prose answer, not JSON."))
    groups, evidence = _groups()
    with pytest.raises(AnalysisProviderError) as err:
        analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
    assert err.value.kind is AnalysisFailureKind.MALFORMED_RESPONSE


def test_non_object_json_is_malformed() -> None:
    analyzer, _ = _analyzer(FakeResponse("[1,2,3]"))
    groups, evidence = _groups()
    with pytest.raises(AnalysisProviderError) as err:
        analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
    assert err.value.kind is AnalysisFailureKind.MALFORMED_RESPONSE


def test_oversized_response_hits_limit() -> None:
    analyzer, _ = _analyzer(FakeResponse(json.dumps({"pad": "x" * 300_000})))
    groups, evidence = _groups()
    with pytest.raises(AnalysisProviderError) as err:
        analyzer.analyze(evidence, groups, system_instructions="S", user_prompt="U")
    assert err.value.kind is AnalysisFailureKind.LIMIT_EXCEEDED


def test_max_response_constant_matches_validator_budget() -> None:
    from src.domain.scanning.analysis.validator import MAX_OUTPUT_JSON_BYTES
    from src.infrastructure.ai.gemini_provider import MAX_RESPONSE_CHARS

    assert MAX_RESPONSE_CHARS == MAX_OUTPUT_JSON_BYTES
