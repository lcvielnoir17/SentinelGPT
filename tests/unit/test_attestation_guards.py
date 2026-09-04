"""Attestation creation/revocation guards (release audit P2 fixes).

- Expiry must be timezone-aware and in the future (naive datetimes crash
  comparisons with TypeError; past dates mint dead rows).
- Archived targets cannot be attested (no scan gate can ever use it).
- Revoke is idempotent: re-revoking neither rewrites history nor spams
  the audit log.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from src.domain.errors import InvalidAttestationError, NotFoundError
from src.domain.scans.attestation_service import AttestationService
from tests.unit.conftest import _principal  # noqa: F401 - shared harness


class _FakeSession:
    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        return None


def _target(owner_id: uuid.UUID, archived: bool = False) -> Any:
    row = type("T", (), {})()
    row.id = uuid.uuid4()
    row.owner_user_id = owner_id
    row.owner_organization_id = None
    row.is_archived = archived
    return row


def _attestation_row(target_id: uuid.UUID, status: str = "CONFIRMED") -> Any:
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    row = type("A", (), {})()
    row.id = uuid.uuid4()
    row.target_id = target_id
    row.method_id = 1
    row.status = status
    row.expires_at = None
    row.evidence_file_ref = None
    row.created_by_user_id = None
    row.revoked_at = None
    row.revoked_reason = None
    row.created_at = _dt.now(_UTC)
    return row


def _service(
    mocker: pytest.MonkeyPatch,  # type: ignore[no-untyped-def]
    *,
    principal: Any = None,
    target: Any = None,
    archived: bool = False,
    attestations: dict[uuid.UUID, Any] | None = None,
    audits: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any, dict[uuid.UUID, Any], list[dict[str, Any]]]:
    from tests.unit.conftest import _principal as _make_principal

    principal = principal if principal is not None else _make_principal()
    target = target if target is not None else _target(principal.id, archived)
    attestations = {} if attestations is None else attestations
    audits = [] if audits is None else audits
    from src.infrastructure.database.repositories.attestation_repository import (
        AttestationRepository,
    )
    from src.infrastructure.database.repositories.membership_repository import (
        MembershipRepository,
    )
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )

    async def fake_target_get(_self: object, tid: uuid.UUID) -> Any:
        return target if tid == target.id else None

    async def fake_att_get(_self: object, aid: uuid.UUID) -> Any:
        return attestations.get(aid)

    async def fake_method_map(_self: object) -> dict[int, str]:
        return {1: "SELF_ATTESTATION"}

    def fake_add(_self: object, row: Any) -> None:
        attestations[row.id] = row

    async def fake_flush(_self: object) -> None:
        return None

    async def fake_is_member(_self: object, _u: uuid.UUID, _o: uuid.UUID) -> bool:
        return True

    async def fake_record(_self: object, **kwargs: Any) -> Any:
        audits.append(kwargs)
        return None

    mocker.patch.object(TargetRepository, "get_by_id", fake_target_get)
    mocker.patch.object(AttestationRepository, "get_by_id", fake_att_get)
    mocker.patch.object(AttestationRepository, "method_code_map", fake_method_map)
    mocker.patch.object(AttestationRepository, "add", fake_add)
    mocker.patch.object(AttestationRepository, "flush", fake_flush)
    mocker.patch.object(MembershipRepository, "is_member", fake_is_member)
    mocker.patch("src.domain.audit.audit_service.AuditService.record", fake_record)

    session = _FakeSession()
    return AttestationService(session, principal), target, attestations, audits


async def test_naive_expiry_rejected(mocker) -> None:  # type: ignore[no-untyped-def]
    svc, target, _, _ = _service(mocker)
    with pytest.raises(InvalidAttestationError):
        await svc.create_self_attestation(target.id, expires_at=datetime(2030, 1, 1, 0, 0, 0))


async def test_past_expiry_rejected(mocker) -> None:  # type: ignore[no-untyped-def]
    svc, target, _, _ = _service(mocker)
    with pytest.raises(InvalidAttestationError):
        await svc.create_self_attestation(
            target.id, expires_at=datetime.now(UTC) - timedelta(seconds=1)
        )


async def test_archived_target_cannot_be_attested(mocker) -> None:  # type: ignore[no-untyped-def]
    svc, target, _, _ = _service(mocker, archived=True)
    with pytest.raises(NotFoundError):
        await svc.create_self_attestation(target.id)


async def test_revoke_is_idempotent(mocker) -> None:  # type: ignore[no-untyped-def]
    svc, target, attestations, audits = _service(mocker)
    row = _attestation_row(target.id)
    attestations[row.id] = row

    first = await svc.revoke(row.id, reason="no longer needed")
    assert first.status == "REVOKED"
    assert len(audits) == 1

    second = await svc.revoke(row.id, reason="again")
    assert second.status == "REVOKED"
    assert len(audits) == 1
    # History metadata untouched by the second call.
    assert row.revoked_reason == "no longer needed"


async def test_revoke_missing_is_404(mocker) -> None:  # type: ignore[no-untyped-def]
    svc, _, _, _ = _service(mocker)
    with pytest.raises(NotFoundError):
        await svc.revoke(uuid.uuid4(), reason="phantom")
