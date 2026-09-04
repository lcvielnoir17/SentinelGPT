"""Canonical AI-analyzer construction (degrade-first policy).

Three call sites (scan API route, scan domain service, Celery worker) used
to repeat the same resolve-then-degrade sequence. This is the single
canonical implementation: resolve the key, build the evidence analyzer,
and return ``None`` for every failure mode — AI must degrade, never gate
or block scans.
"""

from __future__ import annotations

from typing import Any


def maybe_evidence_analyzer() -> Any | None:
    """Build a ``GeminiEvidenceAnalyzer`` or return ``None`` when unavailable."""
    from src.infrastructure.ai.gemini_provider import GeminiEvidenceAnalyzer
    from src.infrastructure.secrets import get_gemini_api_key

    if not get_gemini_api_key():
        return None
    try:
        return GeminiEvidenceAnalyzer.from_settings()
    except Exception:  # noqa: BLE001 - AI must degrade, never block scans
        return None
