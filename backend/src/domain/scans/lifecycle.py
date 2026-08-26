"""Scan lifecycle state machine (SRS Chapter 2, Section 10).

Transitions are explicit and validated; anything not listed here is an
invalid transition and raises :class:`InvalidScanStateError`. Terminal
states accept no further transitions.
"""

from __future__ import annotations

from src.config.constants import (
    SCAN_STATUS_AI_ANALYSIS,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_PARTIALLY_COMPLETE,
    SCAN_STATUS_PENDING_ATTESTATION,
    SCAN_STATUS_QUEUED,
    SCAN_STATUS_REJECTED,
    SCAN_STATUS_REPORT_READY,
    SCAN_STATUS_REPORT_READY_DEGRADED,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_SCAN_COMPLETE,
)
from src.domain.errors import InvalidScanStateError

_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    SCAN_STATUS_PENDING_ATTESTATION: frozenset(
        {SCAN_STATUS_QUEUED, SCAN_STATUS_REJECTED, SCAN_STATUS_CANCELLED}
    ),
    SCAN_STATUS_QUEUED: frozenset(
        {SCAN_STATUS_RUNNING, SCAN_STATUS_REJECTED, SCAN_STATUS_CANCELLED}
    ),
    # RUNNING is intentionally NOT cancellable: in-flight termination is not
    # supported yet (ADR-0009). Fail closed rather than fake CANCELLED.
    SCAN_STATUS_RUNNING: frozenset(
        {
            SCAN_STATUS_SCAN_COMPLETE,
            SCAN_STATUS_PARTIALLY_COMPLETE,
            SCAN_STATUS_REJECTED,
        }
    ),
    SCAN_STATUS_AI_ANALYSIS: frozenset(
        {SCAN_STATUS_REPORT_READY, SCAN_STATUS_REPORT_READY_DEGRADED}
    ),
    SCAN_STATUS_SCAN_COMPLETE: frozenset({SCAN_STATUS_AI_ANALYSIS}),
    SCAN_STATUS_PARTIALLY_COMPLETE: frozenset({SCAN_STATUS_AI_ANALYSIS}),
}

_TERMINAL_STATES = frozenset(
    {
        SCAN_STATUS_REPORT_READY,
        SCAN_STATUS_REPORT_READY_DEGRADED,
        SCAN_STATUS_REJECTED,
        SCAN_STATUS_CANCELLED,
    }
)


def can_transition(current: str, target: str) -> bool:
    """True when current→target is a valid state-machine edge."""
    allowed = _ALLOWED_TRANSITIONS.get(current)
    return allowed is not None and target in allowed


def assert_transition(current: str, target: str) -> None:
    """Raise :class:`InvalidScanStateError` when the edge is invalid."""
    if not can_transition(current, target):
        raise InvalidScanStateError()


def is_terminal(status: str) -> bool:
    return status in _TERMINAL_STATES
