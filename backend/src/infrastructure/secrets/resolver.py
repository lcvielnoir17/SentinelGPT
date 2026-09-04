"""Production secret resolution (Ideathon requirement 4, ADR-0013).

The platform's only secret-backed integration is the Gemini API key.
Resolution policy:

1. ``GEMINI_API_KEY_SECRET`` set to a Secret Manager resource name
   (``projects/{p}/secrets/{s}/versions/{v}``, ``latest`` allowed) and
   ``SECRET_MANAGER_ENABLED`` true → fetch the payload through the Secret
   Manager API using Application Default Credentials (on Cloud Run these
   come from the attached service account; locally from
   ``gcloud auth application-default login`` or
   ``GOOGLE_APPLICATION_CREDENTIALS``).
2. Otherwise → use the plain ``GEMINI_API_KEY`` environment value, which
   keeps local development fully functional without any Google project.

The fetched payload is cached in memory for a bounded TTL so request-time
callers do not hit the API on every turn, and a failed Secret Manager
lookup falls back to the environment value with a loud log — the scanner
platform must degrade, never block, on AI-secret problems. Failures are
also negatively cached briefly to avoid hammering a broken backend.

Secrets are never logged, never returned in API responses, and never
written to the readiness payload — only a boolean "configured" signal is.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any

import structlog

from src.config.settings import get_settings

_logger = structlog.get_logger(__name__)

SECRET_RESOURCE_PATTERN = re.compile(
    r"^projects/(?P<project>[a-zA-Z0-9._-]+)/secrets/(?P<secret>[a-zA-Z0-9._-]+)"
    r"/versions/(?P<version>[a-zA-Z0-9._-]+)$"
)
POSITIVE_TTL_SECONDS = 300
NEGATIVE_TTL_SECONDS = 30

_cache_lock = threading.Lock()
_cached_key: str | None = None
_cached_at: float = 0.0
_cached_is_secret: bool = False


class InvalidSecretResourceNameError(ValueError):
    """The configured Secret Manager resource name is malformed."""


def is_secret_resource_name(value: str) -> bool:
    """True when the value looks like a Secret Manager version resource."""
    return bool(SECRET_RESOURCE_PATTERN.match(value))


def reset_cache() -> None:
    """Clear the cached secret (tests and forced refresh)."""
    global _cached_key, _cached_at, _cached_is_secret
    with _cache_lock:
        _cached_key = None
        _cached_at = 0.0
        _cached_is_secret = False


def _client_factory() -> Any:
    """Build the Secret Manager client (patchable seam for tests)."""
    from google.cloud import secretmanager

    return secretmanager.SecretManagerServiceClient()


def _fetch_from_secret_manager(resource_name: str) -> str:
    """Synchronous Secret Manager access (callers run off the hot path)."""
    match = SECRET_RESOURCE_PATTERN.match(resource_name)
    if match is None:
        raise InvalidSecretResourceNameError(resource_name)
    client = _client_factory()
    response = client.access_secret_version(name=resource_name)
    payload: str = response.payload.data.decode("utf-8").strip()
    if not payload:
        raise InvalidSecretResourceNameError(f"empty secret payload: {resource_name}")
    return payload


def _cache_valid(now: float) -> bool:
    if _cached_key is None:
        return False
    ttl = POSITIVE_TTL_SECONDS if _cached_is_secret else NEGATIVE_TTL_SECONDS
    return (now - _cached_at) < ttl


def get_gemini_api_key() -> str:
    """Resolve the Gemini API key per the policy above (process-cached)."""
    global _cached_key, _cached_at, _cached_is_secret

    settings = get_settings()
    use_secret = settings.secret_manager_enabled and bool(settings.gemini_api_key_secret.strip())
    if not use_secret:
        return settings.gemini_api_key

    now = time.monotonic()
    with _cache_lock:
        if _cache_valid(now):
            assert _cached_key is not None
            return _cached_key

    resource = settings.gemini_api_key_secret.strip()
    try:
        key: str = _fetch_from_secret_manager(resource)
        is_secret = True
    except Exception as exc:  # noqa: BLE001 - degrade to env, never block
        _logger.error(
            "secret_manager_resolution_failed",
            resource=resource,
            error=type(exc).__name__,
            fallback="environment GEMINI_API_KEY",
        )
        key = settings.gemini_api_key
        is_secret = False

    with _cache_lock:
        _cached_key = key
        _cached_at = time.monotonic()
        _cached_is_secret = is_secret
    return key


def client_for_tests() -> Any:
    """Expose the (lazily imported) client type for test patching."""
    from google.cloud import secretmanager

    return secretmanager.SecretManagerServiceClient
