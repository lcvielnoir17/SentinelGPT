"""Live-provider collection configuration (M19, opt-in only).

Collection runs if and only if ``RESEARCH_LIVE_PROVIDER=1`` AND a
non-empty ``GEMINI_API_KEY`` is present in the environment. Anything
else yields a clean "not performed" outcome — normal test runs never
touch the network. Credentials come exclusively from the environment;
they are never printed, stored, or embedded in artifacts.

The research provider model is selected via ``LIVE_PROVIDER_MODEL``
(default ``gemini-2.5-flash``). This knob is M19-research only and does
not affect production configuration elsewhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

OPT_IN_VARIABLE = "RESEARCH_LIVE_PROVIDER"
OPT_IN_VALUE = "1"
KEY_VARIABLE = "GEMINI_API_KEY"
MIN_KEY_LENGTH = 20
MODEL_VARIABLE = "LIVE_PROVIDER_MODEL"
DEFAULT_MODEL = "gemini-2.5-flash"

_PLACEHOLDER_MARKERS = ("example", "changeme", "placeholder", "test-key", "xxx")


@dataclass(frozen=True)
class LiveConfig:
    """Resolved collection configuration (key material never retained)."""

    enabled: bool
    provider: str = "google-genai"
    model: str = DEFAULT_MODEL
    temperature: str = "provider-default (unpinned)"
    max_output_tokens: str = "provider-default (unpinned)"
    reason: str = ""


@dataclass(frozen=True)
class CollectionStatus:
    """Outcome of the availability gate (no secrets inside)."""

    will_collect: bool
    reason: str


def collection_status(environment: dict[str, str] | None = None) -> CollectionStatus:
    """Decide whether live collection may proceed (pure, testable)."""
    env = environment if environment is not None else dict(os.environ)
    if env.get(OPT_IN_VARIABLE) != OPT_IN_VALUE:
        return CollectionStatus(False, f"{OPT_IN_VARIABLE} != 1 (opt-in is OFF)")
    key = (env.get(KEY_VARIABLE) or "").strip()
    if len(key) < MIN_KEY_LENGTH or any(m in key.lower() for m in _PLACEHOLDER_MARKERS):
        return CollectionStatus(False, "no usable provider API key in environment")
    return CollectionStatus(True, "opt-in set with usable key")


def resolve_config(environment: dict[str, str] | None = None) -> LiveConfig:
    """Build the pinned configuration (raises when collection is off)."""
    env = environment if environment is not None else dict(os.environ)
    status = collection_status(env)
    if not status.will_collect:
        raise CollectionNotEnabledError(status.reason)
    raw_model = (env.get(MODEL_VARIABLE) or "").strip()
    model = raw_model if raw_model else DEFAULT_MODEL
    return LiveConfig(enabled=True, model=model, reason=status.reason)


class CollectionNotEnabledError(Exception):
    """Live collection was requested without opt-in or credentials."""


__all__ = [
    "DEFAULT_MODEL",
    "KEY_VARIABLE",
    "MODEL_VARIABLE",
    "OPT_IN_VALUE",
    "OPT_IN_VARIABLE",
    "CollectionNotEnabledError",
    "CollectionStatus",
    "LiveConfig",
    "collection_status",
    "resolve_config",
]
