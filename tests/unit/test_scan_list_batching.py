"""Batched scan-list hydration (optimization regression pins).

``list_scans`` must hydrate a page with exactly three queries (list + two
code maps) instead of two lookups per row, return correct codes, honor
limit/target scoping, hide other tenants' scans, and raise LookupError
(not raw KeyError) when a seed id is missing.
"""

import uuid

import pytest

from src.domain.scans.scan_service import ScanService
from tests.unit.conftest import _principal  # noqa: F401 - shared harness


async def _three_scans(env) -> list:  # type: ignore[no-untyped-def]
    service = ScanService(env.session, env.owner)
    return [await service.create_scan(target_id=env.target.id) for _ in range(3)]


async def test_list_hydrates_codes_without_per_row_lookups(env, mocker) -> None:  # type: ignore[no-untyped-def]
    await _three_scans(env)
    service = ScanService(env.session, env.owner)

    spy = mocker.patch.object(
        env.repo,
        "status_code_by_id",
        wraps=env.repo.status_code_by_id,
    )
    rows = await service.list_scans()

    assert len(rows) == 3
    assert {r.status_code for r in rows} == {"QUEUED"}
    assert {r.scan_profile_code for r in rows} == {"standard"}
    # One batched map fetch for the whole page — not one lookup per row.
    assert spy.call_count == 1


async def test_list_respects_limit_and_hides_other_tenants(env) -> None:  # type: ignore[no-untyped-def]
    await _three_scans(env)
    owner_service = ScanService(env.session, env.owner)
    assert len(await owner_service.list_scans(limit=2)) == 2

    stranger = ScanService(env.session, _principal())
    assert await stranger.list_scans() == []


async def test_list_missing_seed_raises_lookup_error(env) -> None:  # type: ignore[no-untyped-def]
    details = (await _three_scans(env))[0]
    # Corrupt the seed mapping (simulates an unseeded lookup id).
    env.repo.rows[details.id].status_id = 424242
    service = ScanService(env.session, env.owner)
    with pytest.raises(LookupError):
        await service.list_scans()


async def test_cancel_queued_scan_records_audited_cancel(env) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.database.models import AuditLogEntry

    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)
    cancelled = await service.cancel_scan(details.id)

    assert cancelled.status_code == "CANCELLED"
    cancels = [
        e
        for e in env.session.added
        if isinstance(e, AuditLogEntry) and e.action_code == "SCAN_STATE_TRANSITION"
    ]
    assert len(cancels) == 1
    assert cancels[0].metadata_json["from"] == "QUEUED"
    assert cancels[0].metadata_json["to"] == "CANCELLED"
    assert cancels[0].metadata_json["ownerUserId"] == str(env.owner.id)
    assert cancels[0].actor_user_id == env.owner.id


async def test_cancel_from_intermediate_state_is_rejected(env) -> None:  # type: ignore[no-untyped-def]
    from src.domain.errors import InvalidScanStateError

    from tests.unit.conftest import STATUS_IDS

    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)
    row = env.repo.rows[details.id]
    row.status_id = STATUS_IDS["SCAN_COMPLETE"]
    row.status_code = "SCAN_COMPLETE"

    with pytest.raises(InvalidScanStateError):
        await service.cancel_scan(details.id)
    # Failed cancel writes no audit row.
    from src.infrastructure.database.models import AuditLogEntry

    assert not [
        e for e in env.session.added if isinstance(e, AuditLogEntry) and e.action_code == "SCAN_STATE_TRANSITION"
    ]


async def test_cancel_loses_race_with_worker_stage(env) -> None:  # type: ignore[no-untyped-def]
    """Cancel winning mid-execution aborts the job instead of corrupting it."""
    from src.domain.errors import InvalidScanStateError

    from tests.unit.conftest import STATUS_IDS
    from tests.unit.test_scans_api import OkPipeline, _analysis_result

    service = ScanService(env.session, env.owner)
    details = await service.create_scan(target_id=env.target.id)

    class CancellingPipeline(OkPipeline):
        def run(self, **kwargs: object) -> object:  # type: ignore[no-untyped-def]
            row = env.repo.rows[details.id]
            row.status_id = STATUS_IDS["CANCELLED"]
            row.status_code = "CANCELLED"
            return super().run(**kwargs)

    with pytest.raises(InvalidScanStateError):
        await service.execute_scan_job(
            details.id, pipeline=CancellingPipeline(_analysis_result())
        )

    row = env.repo.rows[details.id]
    assert row.status_code == "CANCELLED"
    assert uuid.UUID(str(row.id)) == details.id
