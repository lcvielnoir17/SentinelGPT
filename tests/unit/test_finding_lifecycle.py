"""Lifecycle derivation tests (NEW/PERSISTENT/RESOLVED/REGRESSED)."""

from src.domain.scans.lifecycle_finding import derive_lifecycle_status


def test_first_occurrence_is_new() -> None:
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=True, in_previous=False, last_known_status=None
        )
        == "NEW"
    )


def test_present_in_both_is_persistent_not_regressed() -> None:
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=True, in_previous=True, last_known_status="NEW"
        )
        == "PERSISTENT"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=True, in_previous=True, last_known_status="RESOLVED"
        )
        == "PERSISTENT"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=True, in_previous=True, last_known_status=None
        )
        == "PERSISTENT"
    )


def test_absent_in_current_is_resolved() -> None:
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=False, in_previous=True, last_known_status="NEW"
        )
        == "RESOLVED"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=False, in_previous=True, last_known_status="PERSISTENT"
        )
        == "RESOLVED"
    )


def test_regressed_requires_prior_resolved() -> None:
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=True, in_previous=False, last_known_status="RESOLVED"
        )
        == "REGRESSED"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=True, in_previous=False, last_known_status="NEW"
        )
        == "NEW"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=True, in_previous=False, last_known_status=None
        )
        == "NEW"
    )


def test_no_history_no_previous_no_current_returns_none() -> None:
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=False, in_previous=False, last_known_status=None
        )
        is None
    )
    assert (
        derive_lifecycle_status(
            fingerprint="fp1", in_current=False, in_previous=False, last_known_status="RESOLVED"
        )
        is None
    )


def test_multiple_findings_independent() -> None:
    # Simulate scan with 3 findings: one persistent, one new, one resurrected
    assert (
        derive_lifecycle_status(
            fingerprint="a", in_current=True, in_previous=True, last_known_status="NEW"
        )
        == "PERSISTENT"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="b", in_current=True, in_previous=False, last_known_status=None
        )
        == "NEW"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="c", in_current=True, in_previous=False, last_known_status="RESOLVED"
        )
        == "REGRESSED"
    )
    assert (
        derive_lifecycle_status(
            fingerprint="d", in_current=False, in_previous=True, last_known_status="NEW"
        )
        == "RESOLVED"
    )
