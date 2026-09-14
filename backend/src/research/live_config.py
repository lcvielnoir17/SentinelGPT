"""Live-provider collection configuration (M19, opt-in only).

Collection runs if and only if ``RESEARCH_LIVE_PROVIDER=1`` AND a
non-empty ``GEMINI_API_KEY`` is present in the environment. Anything
else yields a clean "not performed" outcome — normal test runs never
touch the network. Credentials come exclusively from the environment;
they are never printed, stored, or embedded in artifacts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

OPT_IN_VARIABLE = "RESEARCH_LIVE_PROVIDER"
OPT_IN_VALUE = "1"
KEY_VARIABLE = "GEMINI_API_KEY"
MIN_KEY_LENGTH = 20

_PLACEHOLDER_MARKERS = ("example", "changeme", "placeholder", "test-key", "xxx")


@dataclass(frozen=True)
class LiveConfig:
    """Resolved collection configuration (key material never retained)."""

    enabled: bool
    provider: str = "google-genai"
    model: str = "gemini-2.0-flash"
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
    status = collection_status(environment)
    if not status.will_collect:
        raise CollectionNotEnabledError(status.reason)
    return LiveConfig(enabled=True, reason=status.reason)


class CollectionNotEnabledError(Exception):
    """Live collection was requested without opt-in or credentials."""


__all__ = [
    "KEY_VARIABLE",
    "OPT_IN_VALUE",
    "OPT_IN_VARIABLE",
    "CollectionNotEnabledError",
    "CollectionStatus",
    "LiveConfig",
    "collection_status",
    "resolve_config",
]
