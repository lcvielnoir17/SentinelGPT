"""Redirect revalidation policy (ADR-0002, SRS Chapter 11 Section 6 layer 4).

Contract for a future crawler/HTTP layer: EVERY redirect destination —
absolute URL or cross-host hop — must pass the full pipeline again:

    normalize -> classify hostname -> fresh resolve_all ->
    validate every A/AAAA -> new validated binding -> new scan context

A redirect is never followed on the strength of the original target's
validation. This module implements the policy and orchestration only; it
performs no HTTP I/O and no DNS I/O (resolution arrives via the injected
resolver). Synthetic destinations in tests exercise it offline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from src.domain.errors import (
    RedirectDestinationBlockedError,
    TargetResolutionBlockedError,
    TargetUnresolvedError,
)
from src.domain.scanning.egress import ScanNetworkContext

if TYPE_CHECKING:
    from datetime import datetime

    from src.domain.scanning.resolution import ScanTargetResolutionService

ALLOWED_REDIRECT_SCHEMES = frozenset({"http", "https"})


class RedirectValidationService:
    """Revalidate each redirect destination before it may be followed."""

    def __init__(self, resolution: ScanTargetResolutionService) -> None:
        self._resolution = resolution

    def evaluate(
        self,
        current_context: ScanNetworkContext,
        location: str,
        *,
        now: datetime | None = None,  # noqa: ARG002 - test seam, symmetric API
    ) -> ScanNetworkContext:
        """Return the NEW context for the redirect destination, or refuse.

        Relative locations stay on the already-validated origin host and
        inherit its context unchanged (no re-resolution needed for identity;
        the future HTTP layer still enforces the pinned destination).
        Absolute URLs must clear lexical normalization, fresh resolution, and
        full-record-set IP policy before a new context is issued.
        """
        parts = urlsplit(location)
        if not parts.scheme and not parts.netloc:
            # Same-origin relative path: identity unchanged.
            return current_context

        if parts.scheme.lower() not in ALLOWED_REDIRECT_SCHEMES:
            raise RedirectDestinationBlockedError()

        host = (parts.hostname or "").rstrip(".")
        if not host:
            raise RedirectDestinationBlockedError()
        if _is_prohibited_name(host):
            raise RedirectDestinationBlockedError()

        try:
            binding = self._resolution.resolve(host, now=now)
        except (TargetUnresolvedError, TargetResolutionBlockedError):
            # Fold both failure classes into the redirect-blocked envelope;
            # the underlying reason stays server-side.
            raise RedirectDestinationBlockedError() from None
        return ScanNetworkContext.create(binding)


def _is_prohibited_name(host: str) -> bool:
    """Lexical pre-filter mirroring registration-time rules for redirects.

    Reuses the shared normalization gate so redirect destinations obey the
    exact same hostname rules as registered targets (single source of truth,
    SRS Chapter 3 Section 18).
    """
    from src.domain.errors import InvalidTargetError
    from src.domain.targets.target_normalization import normalize_target

    try:
        normalize_target(host, f"https://{host}/")
    except InvalidTargetError:
        return True
    return False
