"""Gemini-backed EvidenceAnalyzer (ADR-0008).

Isolation contract:

* Receives ONLY serialized evidence strings — never scanner context,
  EngineServices, sandboxes, resolvers, or target handles.
* Uses the locked ``google-genai`` SDK in JSON mode with an explicit
  timeout; every SDK/network/auth failure maps onto the typed
  ``AnalysisFailureKind`` taxonomy via :class:`AnalysisProviderError`.
* Response size is bounded before parsing; non-JSON text is malformed.

Tests inject a fake client factory, so the normal suite never touches the
network. Live calls additionally require an API key at construction time.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from google.genai import errors as genai_errors
from google.genai import types as genai_types

from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    AnalysisProviderError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from src.domain.scanning.analysis.correlation import CandidateGroup
    from src.domain.scanning.analysis.evidence import EvidenceSet

MAX_RESPONSE_CHARS = 262_144


def _default_client_factory(api_key: str, timeout_s: float) -> Any:
    client = genai_types  # noqa: F841 - keeps types import meaningful for readers
    from google import genai as google_genai

    return google_genai.Client(
        api_key=api_key,
        http_options=google_genai.types.HttpOptions(timeout=int(timeout_s * 1000)),
    )


class GeminiEvidenceAnalyzer:
    """EvidenceAnalyzer over Google Gemini (JSON mode)."""

    provider = "google-genai"

    def __init__(
        self,
        api_key: str,
        *,
        model: str = "gemini-2.0-flash-lite",
        model_version: str | None = None,
        timeout_s: float = 20.0,
        client_factory: Callable[[str, float], Any] | None = None,
    ) -> None:
        if not api_key:
            raise AnalysisProviderError(
                AnalysisFailureKind.AUTHENTICATION_FAILED, "missing Gemini API key"
            )
        self.model = model
        self.model_version = model_version or model
        self._timeout_s = timeout_s
        self._client = (client_factory or _default_client_factory)(api_key, timeout_s)

    @classmethod
    def from_settings(cls) -> GeminiEvidenceAnalyzer:
        """Composition helper wiring key/model from existing Settings."""
        from src.config.settings import get_settings
        from src.infrastructure.secrets import get_gemini_api_key

        settings = get_settings()
        return cls(
            api_key=get_gemini_api_key(),
            model=settings.gemini_flash_model,
        )

    # ------------------------------------------------------------------ #
    # EvidenceAnalyzer protocol                                          #
    # ------------------------------------------------------------------ #

    def analyze(
        self,
        evidence_set: EvidenceSet,
        candidate_groups: tuple[CandidateGroup, ...],  # noqa: ARG002 - protocol shape
        *,
        system_instructions: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        del evidence_set  # payload already serialized inside user_prompt
        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=user_prompt,
                config=genai_types.GenerateContentConfig(
                    system_instruction=system_instructions,
                    response_mime_type="application/json",
                ),
            )
        except genai_errors.APIError as exc:
            raise _map_api_error(exc) from exc
        except TimeoutError as exc:
            raise AnalysisProviderError(
                AnalysisFailureKind.TIMEOUT, "gemini request timed out"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - mapped to typed failure below
            chained = _find_in_chain(exc, ("Timeout", "timed out"))
            if chained:
                raise AnalysisProviderError(
                    AnalysisFailureKind.TIMEOUT, "gemini request timed out"
                ) from exc
            raise AnalysisProviderError(
                AnalysisFailureKind.PROVIDER_UNAVAILABLE, type(exc).__name__
            ) from exc

        return _extract_json(response)


def _map_api_error(exc: genai_errors.APIError) -> AnalysisProviderError:
    code = getattr(exc, "code", None)
    message = str(getattr(exc, "message", "") or type(exc).__name__)
    if code in (401, 403):
        return AnalysisProviderError(AnalysisFailureKind.AUTHENTICATION_FAILED, message)
    if code in (408, 504):
        return AnalysisProviderError(AnalysisFailureKind.TIMEOUT, message)
    if isinstance(code, int) and code >= 500 or code == 429:
        return AnalysisProviderError(AnalysisFailureKind.PROVIDER_UNAVAILABLE, message)
    return AnalysisProviderError(AnalysisFailureKind.PROVIDER_UNAVAILABLE, f"gemini error {code}")


def _find_in_chain(exc: BaseException, needles: tuple[str, ...]) -> bool:
    current: BaseException | None = exc
    depth = 0
    while current is not None and depth < 6:
        if any(needle in str(current) for needle in needles):
            return True
        current = current.__cause__ or current.__context__
        depth += 1
    return False


def _extract_json(response: Any) -> dict[str, Any]:
    try:
        text = response.text
    except Exception as exc:  # noqa: BLE001 - blocked/empty responses surface here
        raise AnalysisProviderError(
            AnalysisFailureKind.MALFORMED_RESPONSE,
            f"no usable response text ({type(exc).__name__})",
        ) from exc
    if not text or not text.strip():
        raise AnalysisProviderError(AnalysisFailureKind.MALFORMED_RESPONSE, "empty response")
    if len(text) > MAX_RESPONSE_CHARS:
        raise AnalysisProviderError(AnalysisFailureKind.LIMIT_EXCEEDED, "response exceeds size cap")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisProviderError(
            AnalysisFailureKind.MALFORMED_RESPONSE, f"invalid JSON: {exc.msg}"
        ) from exc
    if not isinstance(parsed, dict):
        raise AnalysisProviderError(
            AnalysisFailureKind.MALFORMED_RESPONSE, "payload is not a JSON object"
        )
    return parsed
