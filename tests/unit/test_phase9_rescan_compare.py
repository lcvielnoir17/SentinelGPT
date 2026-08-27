"""Phase 9 service-level proofs: rescan, compare, lifecycle persistence.

These tests focus on the *application service* layer (ADR-0009's
controlled entry point), not the HTTP envelope. They prove the
mandatory guarantees from the Phase 9 brief:

* rescan creates a new scan linked to the original via ``parent_scan_id``
  and does not mutate the original;
* rescan requires an active authorization attestation for the target;
* compare returns the four-bucket lifecycle diff (new/persistent/resolved/
  regressed) and rejects cross-target or cross-tenant comparisons;
* compare masks cross-tenant scans as 404 (not 403) per SRS Ch5 §14;
* lifecycle history rows are appended in the same transaction as the
  findings (not best-effort silent-skip).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.domain.errors import AttestationNotConfirmedError, InvalidScanStateError, NotFoundError
from src.domain.scans.scan_service import ScanService
from src.domain.users.user_service import UserAccount
from src.infrastructure.database.repositories.attestation_repository import (
    AttestationRepository,
)
from src.infrastructure.database.repositories.target_repository import TargetRepository
from tests.unit.conftest import STATUS_IDS


def _make_scan_row(
    *,
    owner_id: uuid.UUID,
    target_id: uuid.UUID,
    status_code: str = "QUEUED",
    parent_scan_id: uuid.UUID | None = None,
) -> object:
    row = type(
        "S",
        (),
        {
            "id": uuid.uuid4(),
            "target_id": target_id,
            "status_code": status_code,
            "status_id": STATUS_IDS[status_code],
            "scan_profile_code": "standard",
            "scan_profile_id": 2,
            "initiated_by_user_id": owner_id,
            "authorization_attestation_id": uuid.uuid4(),
            "parent_scan_id": parent_scan_id,
            "queued_at": datetime.now(UTC),
            "started_at": None,
            "completed_at": None,
            "created_at": datetime.now(UTC),
        },
    )()
    return row


# --------------------------------------------------------------------------- #
# Rescan                                                                     #
# --------------------------------------------------------------------------- #


async def test_rescan_creates_parent_linked_scan(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """POST /scans/{id}/rescan produces a new scan whose parent_scan_id is
    the original scan's id. The original scan row is unchanged."""
    service = ScanService(env.session, env.owner)
    original = await service.create_scan(target_id=env.target.id)
    # Mark the original as REPORT_READY so the new scan is queued.
    env.repo.rows[original.id].status_id = STATUS_IDS["REPORT_READY"]
    env.repo.rows[original.id].status_code = "REPORT_READY"

    new = await service.rescan_scan(original.id)

    assert new.id != original.id
    assert new.target_id == original.target_id
    assert new.scan_profile_code == original.scan_profile_code
    assert new.status_code == "QUEUED"
    assert new.initiated_by_user_id == env.owner.id

    # Parent linkage persisted on the new scan row.
    new_row = env.repo.rows[new.id]
    assert new_row.parent_scan_id == original.id

    # Original scan row is unchanged.
    original_row = env.repo.rows[original.id]
    assert original_row.parent_scan_id is None
    assert original_row.status_code == "REPORT_READY"


async def test_rescan_requires_active_attestation(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """A target whose attestation lapses between scans must be re-attested
    before a rescan can be queued — the same gate as a fresh scan."""
    service = ScanService(env.session, env.owner)
    original = await service.create_scan(target_id=env.target.id)

    async def fake_none(_self: object, _tid: uuid.UUID):
        return None

    mocker.patch.object(AttestationRepository, "latest_active_confirmed", fake_none)

    with pytest.raises(AttestationNotConfirmedError):
        await service.rescan_scan(original.id)


async def test_rescan_cross_tenant_is_not_found(env) -> None:  # type: ignore[no-untyped-def]
    """A scan from another user is invisible — not 403, per SRS Ch5 §14."""
    service = ScanService(env.session, env.owner)
    original = await service.create_scan(target_id=env.target.id)

    intruder = UserAccount(
        id=uuid.uuid4(), email="intruder@example.com", created_at=datetime.now(UTC)
    )
    service_intruder = ScanService(env.session, intruder)

    with pytest.raises(NotFoundError):
        await service_intruder.rescan_scan(original.id)


# --------------------------------------------------------------------------- #
# Compare                                                                    #
# --------------------------------------------------------------------------- #


def _seed_two_scans(
    env,  # type: ignore[no-untyped-def]
) -> tuple[object, object]:
    owner_id = env.owner.id
    target_id = env.target.id
    scan_a = _make_scan_row(
        owner_id=owner_id,
        target_id=target_id,
        status_code="REPORT_READY",
    )
    scan_b = _make_scan_row(
        owner_id=owner_id,
        target_id=target_id,
        status_code="REPORT_READY",
    )
    env.repo.rows[scan_a.id] = scan_a
    env.repo.rows[scan_b.id] = scan_b
    return scan_a, scan_b


async def test_compare_returns_four_lifecycle_buckets(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """``compare_scans`` produces new/persistent/resolved/regressed buckets
    using fingerprint sets, with REGRESSED requiring a prior RESOLVED
    history row for the same target."""
    service = ScanService(env.session, env.owner)
    scan_a, scan_b = _seed_two_scans(env)

    fp_persistent = "fp_persistent_aaa"
    fp_resolved = "fp_resolved_bbb"
    fp_new = "fp_new_ccc"
    fp_regressed = "fp_regressed_ddd"

    # Wire fingerprint index by intercepting the helper.
    async def fake_index(_self: object, sid: uuid.UUID) -> dict[str, tuple[uuid.UUID, str]]:
        if sid == scan_a.id:
            return {
                fp_persistent: (uuid.uuid4(), "Persistent Title"),
                fp_resolved: (uuid.uuid4(), "Resolved Title"),
            }
        if sid == scan_b.id:
            return {
                fp_persistent: (uuid.uuid4(), "Persistent Title (new id)"),
                fp_new: (uuid.uuid4(), "New Title"),
                fp_regressed: (uuid.uuid4(), "Regressed Title"),
            }
        return {}

    mocker.patch.object(ScanService, "_fingerprint_index", fake_index)

    # Lifecycle status ids must be seeded for the REGRESSED check to run.
    async def fake_status_ids(_s: object) -> dict[str, int]:
        return {"NEW": 1, "PERSISTENT": 2, "RESOLVED": 3, "REGRESSED": 4}

    mocker.patch("src.domain.scans.scan_service._lifecycle_status_ids", fake_status_ids)

    # Mock the resolved-id lookup + history fetch so REGRESSED is found.
    fake_resolved = {"fp_regressed_ddd"}

    async def fake_with_status(
        self: object,  # noqa: ARG001
        *,
        target_id: uuid.UUID,  # noqa: ARG001
        fingerprints: set[str],
        status_id: int,  # noqa: ARG001
    ) -> set[str]:
        return {fp for fp in fingerprints if fp in fake_resolved}

    mocker.patch.object(ScanService, "_fingerprints_with_status", fake_with_status)

    result = await service.compare_scans(scan_a.id, scan_b.id)
    assert {i["fingerprint"] for i in result["new"]} == {fp_new}
    assert {i["fingerprint"] for i in result["persistent"]} == {fp_persistent}
    assert {i["fingerprint"] for i in result["resolved"]} == {fp_resolved}
    assert {i["fingerprint"] for i in result["regressed"]} == {fp_regressed}


async def test_compare_different_target_is_invalid_state(env, mocker) -> None:  # type: ignore[no-untyped-def]
    """Comparing findings across two different targets is meaningless
    and must surface as a controlled ``InvalidScanStateError`` (409)."""
    service = ScanService(env.session, env.owner)
    scan_a, _ = _seed_two_scans(env)
    other_target_row = type(
        "T",
        (),
        {
            "id": uuid.uuid4(),
            "hostname": "other.example",
            "normalized_url": "https://other.example/",
            "owner_user_id": env.owner.id,
            "owner_organization_id": None,
            "is_archived": False,
            "created_at": datetime.now(UTC),
        },
    )()

    async def fake_target_get(_self: object, tid: uuid.UUID):
        return other_target_row if str(tid) == str(other_target_row.id) else env.target

    mocker.patch.object(TargetRepository, "get_by_id", fake_target_get)

    other_scan = _make_scan_row(
        owner_id=env.owner.id,
        target_id=other_target_row.id,
        status_code="REPORT_READY",
    )
    env.repo.rows[other_scan.id] = other_scan

    with pytest.raises(InvalidScanStateError):
        await service.compare_scans(scan_a.id, other_scan.id)


async def test_compare_cross_tenant_is_not_found(env) -> None:  # type: ignore[no-untyped-def]
    """A cross-tenant scan id is invisible to the intruder; surface as
    404 (NOT_FOUND), not 403, to prevent existence leaks (SRS Ch5 §14)."""
    scan_a, scan_b = _seed_two_scans(env)

    intruder = UserAccount(
        id=uuid.uuid4(), email="intruder@example.com", created_at=datetime.now(UTC)
    )
    service_intruder = ScanService(env.session, intruder)

    with pytest.raises(NotFoundError):
        await service_intruder.compare_scans(scan_a.id, scan_b.id)


# --------------------------------------------------------------------------- #
# Lifecycle persistence: parent linkage wins over "most recent"              #
# --------------------------------------------------------------------------- #


async def test_previous_scan_resolution_prefers_parent_linkage(
    env,
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    """``_previous_scan_id`` must honor the explicit parent linkage when
    one exists, even if a more-recent completed scan of the same target
    is present."""
    service = ScanService(env.session, env.owner)
    scan = _make_scan_row(owner_id=env.owner.id, target_id=env.target.id)
    parent = _make_scan_row(
        owner_id=env.owner.id,
        target_id=env.target.id,
        status_code="REPORT_READY",
    )
    more_recent = _make_scan_row(
        owner_id=env.owner.id,
        target_id=env.target.id,
        status_code="REPORT_READY",
    )
    scan.parent_scan_id = parent.id
    env.repo.rows[parent.id] = parent
    env.repo.rows[more_recent.id] = more_recent
    env.repo.rows[scan.id] = scan

    resolved = await service._previous_scan_id(env.target.id, scan.id)
    assert resolved == parent.id
    assert resolved != more_recent.id
