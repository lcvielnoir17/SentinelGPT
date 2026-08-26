"""Unit tests for the scan lifecycle state machine (ADR-0009)."""

import pytest

from src.domain.errors import InvalidScanStateError
from src.domain.scans.lifecycle import assert_transition, can_transition, is_terminal


def test_happy_path_transitions_are_valid() -> None:
    path = [
        ("PENDING_ATTESTATION", "QUEUED"),
        ("QUEUED", "RUNNING"),
        ("RUNNING", "SCAN_COMPLETE"),
        ("SCAN_COMPLETE", "AI_ANALYSIS"),
        ("AI_ANALYSIS", "REPORT_READY"),
    ]
    for current, target in path:
        assert can_transition(current, target)


def test_degraded_path_is_valid() -> None:
    assert can_transition("RUNNING", "PARTIALLY_COMPLETE")
    assert can_transition("PARTIALLY_COMPLETE", "AI_ANALYSIS")
    assert can_transition("AI_ANALYSIS", "REPORT_READY_DEGRADED")


def test_authorization_rejection_edges_are_valid() -> None:
    assert can_transition("PENDING_ATTESTATION", "REJECTED")
    assert can_transition("QUEUED", "REJECTED")
    assert can_transition("RUNNING", "REJECTED")


def test_cancellation_only_before_running() -> None:
    assert can_transition("PENDING_ATTESTATION", "CANCELLED")
    assert can_transition("QUEUED", "CANCELLED")
    assert not can_transition("RUNNING", "CANCELLED")


def test_skipping_the_secure_chain_is_invalid() -> None:
    """A scan may never jump from creation toward execution/analytics."""
    assert not can_transition("PENDING_ATTESTATION", "RUNNING")
    assert not can_transition("PENDING_ATTESTATION", "AI_ANALYSIS")
    assert not can_transition("PENDING_ATTESTATION", "SCAN_COMPLETE")
    assert not can_transition("QUEUED", "AI_ANALYSIS")
    assert not can_transition("QUEUED", "SCAN_COMPLETE")


def test_terminal_states_accept_nothing() -> None:
    for terminal in ("REPORT_READY", "REPORT_READY_DEGRADED", "REJECTED", "CANCELLED"):
        assert is_terminal(terminal)
        assert not can_transition(terminal, "QUEUED")
        assert not can_transition(terminal, "RUNNING")
        assert not can_transition(terminal, "CANCELLED")


def test_completed_scans_cannot_be_cancelled() -> None:
    assert not can_transition("SCAN_COMPLETE", "CANCELLED")
    assert not can_transition("PARTIALLY_COMPLETE", "CANCELLED")


def test_assert_transition_raises_controlled_error() -> None:
    with pytest.raises(InvalidScanStateError):
        assert_transition("PENDING_ATTESTATION", "RUNNING")


def test_unknown_status_has_no_transitions() -> None:
    assert not can_transition("SOMETHING_ELSE", "QUEUED")
