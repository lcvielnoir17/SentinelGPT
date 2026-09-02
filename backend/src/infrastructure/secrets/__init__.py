"""Secret resolution infrastructure (ADR-0013).

Production secrets come from Google Cloud Secret Manager through
:mod:`.resolver`; local development keeps plain environment values. The
Gemini API key is the only secret-backed integration today.
"""

from __future__ import annotations

from src.infrastructure.secrets.resolver import (
    get_gemini_api_key,
    is_secret_resource_name,
    reset_cache,
)

__all__ = ["get_gemini_api_key", "is_secret_resource_name", "reset_cache"]
