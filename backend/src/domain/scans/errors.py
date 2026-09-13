"""Scan domain errors mapped by the centralized error handlers."""

from __future__ import annotations

from src.domain.errors import DomainError


class ScanRateLimitedError(DomainError):
    """Too many scan creations in the current window (429).

    The scan was never persisted, so no quota was consumed — retrying
    after ``Retry-After`` seconds is safe and will not duplicate work.
    """

    status_code = 429
    code = "SCAN_RATE_LIMITED"
    message = "Too many scan requests; wait a minute and try again."
    retry_after: int | None = 60


class ScanQueueFullError(DomainError):
    """The user already holds too many active scans (429).

    QUEUED/RUNNING scans bound worker capacity, so creation is refused
    until earlier scans finish. Nothing was persisted; cancelling a
    queued scan or waiting frees capacity.
    """

    status_code = 429
    code = "SCAN_QUEUE_FULL"
    message = "Too many active scans; wait for earlier scans to finish or cancel a queued scan."
    retry_after: int | None = 60


class InvalidEnrichmentError(DomainError):
    """An enrichment payload failed deterministic validation (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid vulnerability enrichment payload."


class InvalidRemediationError(DomainError):
    """A remediation payload failed deterministic validation (400)."""

    status_code = 400
    code = "VALIDATION_ERROR"
    message = "Invalid finding remediation payload."
