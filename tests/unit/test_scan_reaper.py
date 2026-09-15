"""Stale RUNNING reaper: hard worker losses must not strand quota.

A SIGKILL/OOM/eviction runs no Python handler, so without reaping the
row would sit in RUNNING forever and permanently consume the owner's
running-scan quota. These tests pin the fail-closed reaper.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.domain.scans.lifecycle import can_transition, recovery_reject_sources
from src.domain.scans.scan_service import ScanService
from tests.unit.conftest import STATUS_IDS, FakeRow  # noqa: F401 - shared harness


def _running_row(env, *, started_at):  # type: ignore[no-untyped-def]
    row = FakeRow(user_id=env.owner.id, status_code="RUNNING")
    row.started_at = started_at
    env.repo.rows[row.id] = row
    return row


async def test_reaper_moves_only_stale_running_to_rejected(env) -> None:  # type: ignore[no-untyped-def]
    service = ScanService(env.session, env.owner)
    now = datetime.now(UTC)
    stale = _running_row(env, started_at=now - timedelta(seconds=3700))
    fresh = _running_row(env, started_at=now - timedelta(seconds=60))
    terminal = FakeRow(user_id=env.owner.id, status_code="REJECTED")
    env.repo.rows[terminal.id] = terminal
    ageless = _running_row(env, started_at=None)

    reaped = await service.reap_stale_running_scans(now=now)

    assert reaped == 1
    assert stale.status_code == "REJECTED"
    assert fresh.status_code == "RUNNING"
    assert terminal.status_code == "REJECTED"
    assert ageless.status_code == "RUNNING"


async def test_reaper_honors_custom_cutoff(env) -> None:  # type: ignore[no-untyped-def]
    service = ScanService(env.session, env.owner)
    now = datetime.now(UTC)
    row = _running_row(env, started_at=now - timedelta(seconds=100))

    assert await service.reap_stale_running_scans(stale_after_seconds=3600, now=now) == 0
    assert row.status_code == "RUNNING"
    assert await service.reap_stale_running_scans(stale_after_seconds=30, now=now) == 1
    assert row.status_code == "REJECTED"


async def test_reaper_loses_race_to_live_worker(env) -> None:  # type: ignore[no-untyped-def]
    """A still-running worker that advanced the row defeats the reaper."""
    service = ScanService(env.session, env.owner)
    now = datetime.now(UTC)
    row = _running_row(env, started_at=now - timedelta(seconds=3700))
    row.status_id = STATUS_IDS["SCAN_COMPLETE"]
    row.status_code = "SCAN_COMPLETE"

    assert await service.reap_stale_running_scans(now=now) == 0
    assert row.status_code == "SCAN_COMPLETE"


def test_recovery_edges_are_exact_and_fail_closed() -> None:
    assert recovery_reject_sources() == frozenset(
        {"RUNNING", "SCAN_COMPLETE", "PARTIALLY_COMPLETE", "AI_ANALYSIS"}
    )
    # Recovery targets the fail-closed terminal only; terminal states
    # accept nothing, and QUEUED still cannot jump to REJECTED via recovery.
    assert not can_transition("REJECTED", "REJECTED")
    assert can_transition("QUEUED", "RUNNING")
    assert can_transition("RUNNING", "REJECTED")
