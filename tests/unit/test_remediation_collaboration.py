"""Collaborative remediation (M8): assignment, due dates, comments.

Proves the collaboration layer on top of the existing remediation
model without duplicating it: owner-controlled assignment (no
visibility granted), timezone-safe due dates with derived overdue,
append-only comments, audit history (no second history table),
permissive status transitions, verify-fix integration through the
normal rescan path, dashboard aggregates, filtered findings, and the
v2 report block. Remediation status NEVER equals lifecycle
resolution — DONE+PERSISTENT stays valid throughout.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from src.domain.errors import NotFoundError
from src.domain.scans.errors import InvalidRemediationError
from src.domain.scans.remediation import (
    CommentInput,
    RemediationInput,
    RemediationValidationError,
    is_overdue,
)
from src.domain.scans.scan_service import ScanService

SCAN = uuid.uuid4()
TARGET = uuid.uuid4()
FP = "fp-collab-aaa"
FP2 = "fp-collab-bbb"
FID = uuid.uuid4()
FID2 = uuid.uuid4()

OWNER_ID = uuid.uuid4()
TEAMMATE_ID = uuid.uuid4()
INACTIVE_ID = uuid.uuid4()
OUTSIDER_ID = uuid.uuid4()

FUTURE = (datetime.now(UTC) + timedelta(days=2)).isoformat()
PAST = (datetime.now(UTC) - timedelta(days=2)).isoformat()


def _finding(fid: uuid.UUID = FID, fingerprint: str | None = FP) -> object:
    return type(
        "F",
        (),
        {"id": fid, "scan_id": SCAN, "title": "Missing HSTS", "fingerprint": fingerprint},
    )()


class _Store:
    """In-memory doubles for remediation rows, comments, and users."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, object]] = {}
        self.comments: list[dict[str, object]] = []
        self.users = {
            str(OWNER_ID): {"email": "owner@example.com", "is_active": True},
            str(TEAMMATE_ID): {"email": "teammate@example.com", "is_active": True},
            str(INACTIVE_ID): {"email": "gone@example.com", "is_active": False},
        }

    # -- remediation rows -------------------------------------------------- #
    async def get_remediation(self, **kwargs: object) -> dict[str, object] | None:
        row = self.rows.get((str(kwargs["fingerprint"]), str(kwargs["target_id"])))
        return dict(row) if row is not None else None

    async def set_remediation(self, **kwargs: object) -> dict[str, object]:
        key = (str(kwargs["fingerprint"]), str(kwargs["target_id"]))
        now = datetime.now(UTC).isoformat()
        existing = self.rows.get(key)
        if existing is not None:
            existing["status"] = kwargs["status"]
            existing["notes"] = kwargs["notes"]
            existing["updated_by_user_id"] = (
                str(kwargs["updated_by_user_id"])
                if kwargs["updated_by_user_id"] is not None
                else None
            )
            if bool(kwargs.get("assignee_set")):
                raw = kwargs.get("assignee_user_id")
                existing["assignee_user_id"] = str(raw) if raw is not None else None
                if raw is None:
                    existing["assigned_at"] = None
                    existing["assigned_by_user_id"] = None
                else:
                    existing["assigned_at"] = now
                    by = kwargs.get("assigned_by_user_id")
                    existing["assigned_by_user_id"] = str(by) if by is not None else None
            if bool(kwargs.get("due_at_set")):
                raw_due = kwargs.get("due_at")
                existing["due_at"] = (
                    raw_due.isoformat()
                    if isinstance(raw_due, datetime)
                    else (str(raw_due) if raw_due is not None else None)
                )
            existing["updated_at"] = now
            return dict(existing)
        assignee_raw = kwargs.get("assignee_user_id") if kwargs.get("assignee_set") else None
        due_raw = kwargs.get("due_at") if kwargs.get("due_at_set") else None
        row: dict[str, object] = {
            "id": str(uuid.uuid4()),
            "fingerprint": kwargs["fingerprint"],
            "target_id": str(kwargs["target_id"]),
            "status": kwargs["status"],
            "notes": kwargs["notes"],
            "updated_by_user_id": (
                str(kwargs["updated_by_user_id"])
                if kwargs["updated_by_user_id"] is not None
                else None
            ),
            "assignee_user_id": str(assignee_raw) if assignee_raw is not None else None,
            "assigned_at": now if assignee_raw is not None else None,
            "assigned_by_user_id": (
                str(kwargs["assigned_by_user_id"])
                if assignee_raw is not None and kwargs.get("assigned_by_user_id") is not None
                else None
            ),
            "due_at": (
                due_raw.isoformat()
                if isinstance(due_raw, datetime)
                else (str(due_raw) if due_raw is not None else None)
            ),
            "verified_in_scan_id": None,
            "created_at": now,
            "updated_at": now,
        }
        self.rows[key] = row
        return dict(row)

    async def list_remediations_for_owner_targets(self, **kwargs: object) -> list[dict]:
        wanted = {str(t) for t in kwargs.get("target_ids", [])}  # type: ignore[union-attr]
        return sorted(
            (dict(r) for (fp, tid), r in self.rows.items() if tid in wanted),
            key=lambda r: (str(r["target_id"]), str(r["fingerprint"])),
        )

    # -- comments ---------------------------------------------------------- #
    async def add_comment(self, **kwargs: object) -> dict[str, object]:
        row: dict[str, object] = {
            "id": str(uuid.uuid4()),
            "fingerprint": kwargs["fingerprint"],
            "target_id": str(kwargs["target_id"]),
            "author_user_id": str(kwargs["author_user_id"]),
            "body": kwargs["body"],
            "created_at": datetime.now(UTC).isoformat(),
        }
        self.comments.append(row)
        return dict(row)

    async def list_comments(self, **kwargs: object) -> list[dict]:
        limit = int(kwargs.get("limit", 100))
        rows = [
            c
            for c in self.comments
            if c["fingerprint"] == kwargs["fingerprint"]
            and str(c["target_id"]) == str(kwargs["target_id"])
        ]
        rows.sort(key=lambda c: str(c["created_at"]))
        return [dict(c) for c in rows[:limit]]

    # -- users ------------------------------------------------------------- #
    async def get_user(self, user_id: uuid.UUID) -> object | None:
        entry = self.users.get(str(user_id))
        if entry is None:
            return None
        return SimpleNamespace(
            id=user_id,
            email=entry["email"],
            is_active=entry["is_active"],
            created_at=datetime.now(UTC),
            firebase_uid=None,
        )

    async def basic_by_ids(self, user_ids: list[uuid.UUID]) -> dict[str, dict[str, object]]:
        return {str(uid): dict(self.users[str(uid)]) for uid in user_ids if str(uid) in self.users}


def _principal(user_id: uuid.UUID = OWNER_ID) -> SimpleNamespace:
    return SimpleNamespace(id=user_id, email=f"{user_id}@x.test")


@pytest.fixture
def world(monkeypatch):  # type: ignore[no-untyped-def]
    """Service with every seam doubled; audits captured, not dropped."""
    from src.domain.audit.audit_service import AuditService
    from src.infrastructure.database.repositories.posture_repository import (
        PostureRepository,
    )
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )
    from src.infrastructure.database.repositories.user_repository import UserRepository

    store = _Store()
    audits: list[dict] = []
    history: list[dict] = []

    async def _visible(self: object, sid: uuid.UUID) -> object:
        # Owner-scoped like production: only the resource owner sees the scan.
        principal = getattr(self, "_principal", None)
        principal_id = getattr(principal, "id", None)
        if sid == SCAN and principal_id == OWNER_ID:
            return SimpleNamespace(id=SCAN, target_id=TARGET)
        raise NotFoundError()

    async def _finding_by_id(self: object, fid: uuid.UUID) -> object | None:
        if fid == FID:
            return _finding(FID, FP)
        if fid == FID2:
            return _finding(FID2, FP2)
        return None

    async def _record(self: object, **kwargs: object) -> None:
        audits.append(dict(kwargs))

    async def _owned_targets(self: object, user_id: uuid.UUID) -> list[dict]:
        if user_id == OWNER_ID:
            return [{"id": str(TARGET), "hostname": "example.com"}]
        return []

    async def _history(self: object, target_ids: object, **kwargs: object) -> list[dict]:
        return list(history)

    monkeypatch.setattr(ScanService, "_get_visible_scan", _visible)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_finding_by_id", _finding_by_id)
    monkeypatch.setattr(ScanEngineExecutionRepository, "get_remediation", store.get_remediation)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_remediation", store.set_remediation)
    monkeypatch.setattr(ScanEngineExecutionRepository, "add_comment", store.add_comment)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_comments", store.list_comments)
    monkeypatch.setattr(
        ScanEngineExecutionRepository,
        "list_remediations_for_owner_targets",
        store.list_remediations_for_owner_targets,
    )
    monkeypatch.setattr(UserRepository, "get_by_id", store.get_user)
    monkeypatch.setattr(UserRepository, "basic_by_ids", store.basic_by_ids)
    monkeypatch.setattr(AuditService, "record", _record)
    monkeypatch.setattr(PostureRepository, "list_owned_targets", _owned_targets)
    monkeypatch.setattr(PostureRepository, "history_events", _history)
    namespace = SimpleNamespace(store=store, audits=audits, history=history)
    namespace.service = lambda uid=OWNER_ID: ScanService(object(), _principal(uid))  # type: ignore[arg-type]
    return namespace


def _codes(world) -> list[str]:  # type: ignore[no-untyped-def]
    return [str(a["action_code"]) for a in world.audits]


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #


def test_assignee_parsed_and_cleared() -> None:
    assert RemediationInput.parse({}).assignee_user_id is None
    assert RemediationInput.parse({}).assignee_changed is False
    parsed = RemediationInput.parse({"assigneeUserId": str(TEAMMATE_ID)})
    assert parsed.assignee_user_id == str(TEAMMATE_ID)
    assert parsed.assignee_changed is True
    cleared = RemediationInput.parse({"assigneeUserId": None})
    assert cleared.assignee_user_id is None and cleared.assignee_changed is True


@pytest.mark.parametrize("bad", ["not-a-uuid", 123, "", "  "])
def test_assignee_malformed_rejected(bad: object) -> None:
    with pytest.raises(RemediationValidationError):
        RemediationInput.parse({"assigneeUserId": bad})


def test_due_at_requires_timezone() -> None:
    assert RemediationInput.parse({}).due_at is None
    parsed = RemediationInput.parse({"dueAt": FUTURE})
    assert parsed.due_at is not None and parsed.due_at.tzinfo is not None
    assert parsed.due_at_changed is True
    assert RemediationInput.parse({"dueAt": None}).due_at is None
    with pytest.raises(RemediationValidationError):
        RemediationInput.parse({"dueAt": "2030-05-01T12:00:00"})  # naive: rejected
    with pytest.raises(RemediationValidationError):
        RemediationInput.parse({"dueAt": "someday"})
    with pytest.raises(RemediationValidationError):
        RemediationInput.parse({"dueAt": 12345})


def test_comment_validation() -> None:
    assert CommentInput.parse({"body": "  handoff note  "}).body == "handoff note"
    for bad in ("", "   ", 5, None, "x" * 2001, "has\x00null"):
        with pytest.raises(RemediationValidationError):
            CommentInput.parse({"body": bad})
    assert CommentInput.parse({"body": "x" * 2000}).body is not None


def test_overdue_derivation() -> None:
    now = datetime.now(UTC)
    assert is_overdue(due_at=None, status="TODO") is False
    assert is_overdue(due_at=now + timedelta(hours=1), status="TODO", now=now) is False
    assert is_overdue(due_at=now - timedelta(hours=1), status="TODO", now=now) is True
    assert is_overdue(due_at=now - timedelta(hours=1), status="IN_PROGRESS", now=now) is True
    assert is_overdue(due_at=now - timedelta(hours=1), status="DEFERRED", now=now) is True
    # DONE is never overdue: the work is complete; only scan evidence
    # can say whether the vulnerability persists.
    assert is_overdue(due_at=now - timedelta(hours=1), status="DONE", now=now) is False


async def test_transition_policy_stays_permissive(world) -> None:  # type: ignore[no-untyped-def]
    """Reopening is legitimate: DONE may return to IN_PROGRESS or TODO."""
    service = world.service()
    row = await service.set_finding_remediation(SCAN, FID, {"status": "DONE"})
    assert row is not None and row["status"] == "DONE"
    reopened = await service.set_finding_remediation(SCAN, FID, {"status": "IN_PROGRESS"})
    assert reopened is not None and reopened["status"] == "IN_PROGRESS"
    assert reopened["id"] == row["id"]
    backlog = await service.set_finding_remediation(SCAN, FID, {"status": "TODO"})
    assert backlog is not None and backlog["status"] == "TODO"


# --------------------------------------------------------------------------- #
# Assignment                                                                  #
# --------------------------------------------------------------------------- #


async def test_assign_remediation(world) -> None:  # type: ignore[no-untyped-def]
    row = await world.service().set_finding_remediation(
        SCAN, FID, {"status": "IN_PROGRESS", "assigneeUserId": str(TEAMMATE_ID)}
    )
    assert row is not None
    assert row["assignee_user_id"] == str(TEAMMATE_ID)
    assert row["assigned_at"] is not None
    assert row["assigned_by_user_id"] == str(OWNER_ID)
    assert row["assignee_email"] == "teammate@example.com"
    assert row["overdue"] is False
    assert _codes(world) == ["REMEDIATION_UPDATED", "REMEDIATION_ASSIGNED"]
    assigned = world.audits[1]
    assert assigned["metadata_json"]["from"] is None
    assert assigned["metadata_json"]["to"] == str(TEAMMATE_ID)


async def test_reassign(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    await service.set_finding_remediation(SCAN, FID, {"assigneeUserId": str(TEAMMATE_ID)})
    row = await service.set_finding_remediation(SCAN, FID, {"assigneeUserId": str(OWNER_ID)})
    assert row is not None and row["assignee_user_id"] == str(OWNER_ID)
    assert _codes(world)[-1] == "REMEDIATION_REASSIGNED"
    assert world.audits[-1]["metadata_json"] == {
        "fingerprint": FP,
        "targetId": str(TARGET),
        "from": str(TEAMMATE_ID),
        "to": str(OWNER_ID),
    }


async def test_unassign_clears(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    await service.set_finding_remediation(SCAN, FID, {"assigneeUserId": str(TEAMMATE_ID)})
    row = await service.set_finding_remediation(SCAN, FID, {"assigneeUserId": None})
    assert row is not None
    assert row["assignee_user_id"] is None
    assert row["assigned_at"] is None
    assert row["assigned_by_user_id"] is None
    assert _codes(world)[-1] == "REMEDIATION_REASSIGNED"
    assert world.audits[-1]["metadata_json"]["to"] is None


async def test_same_assignee_reput_emits_no_assignment_audit(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    await service.set_finding_remediation(SCAN, FID, {"assigneeUserId": str(TEAMMATE_ID)})
    before = len(world.audits)
    await service.set_finding_remediation(SCAN, FID, {"assigneeUserId": str(TEAMMATE_ID)})
    assert [str(a["action_code"]) for a in world.audits[before:]] == ["REMEDIATION_UPDATED"]


async def test_unknown_assignee_is_404(world) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(NotFoundError):
        await world.service().set_finding_remediation(
            SCAN, FID, {"assigneeUserId": str(uuid.uuid4())}
        )


async def test_inactive_assignee_is_400(world) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidRemediationError):
        await world.service().set_finding_remediation(
            SCAN, FID, {"assigneeUserId": str(INACTIVE_ID)}
        )


async def test_malformed_assignee_is_400(world) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidRemediationError):
        await world.service().set_finding_remediation(SCAN, FID, {"assigneeUserId": "nope"})


async def test_cross_owner_assign_is_404(world) -> None:  # type: ignore[no-untyped-def]
    """Strict ownership: an outsider cannot touch (or see) the finding."""
    outsider = world.service(OUTSIDER_ID)
    with pytest.raises(NotFoundError):
        await outsider.set_finding_remediation(SCAN, FID, {"assigneeUserId": str(TEAMMATE_ID)})
    with pytest.raises(NotFoundError):
        await outsider.get_finding_remediation(SCAN, FID)


async def test_assignee_gets_no_visibility(world) -> None:  # type: ignore[no-untyped-def]
    """Assignment grants no read access: the assignee still sees 404."""
    await world.service().set_finding_remediation(SCAN, FID, {"assigneeUserId": str(TEAMMATE_ID)})
    teammate = world.service(TEAMMATE_ID)
    with pytest.raises(NotFoundError):
        await teammate.get_finding_remediation(SCAN, FID)
    with pytest.raises(NotFoundError):
        await teammate.add_remediation_comment(SCAN, FID, {"body": "working on it"})


# --------------------------------------------------------------------------- #
# Due dates                                                                   #
# --------------------------------------------------------------------------- #


async def test_due_date_create_update_clear(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    row = await service.set_finding_remediation(SCAN, FID, {"dueAt": FUTURE})
    assert row is not None and row["due_at"] is not None
    assert row["overdue"] is False
    assert _codes(world) == ["REMEDIATION_UPDATED", "REMEDIATION_DUE_DATE_CHANGED"]
    assert world.audits[1]["metadata_json"]["from"] is None

    past = await service.set_finding_remediation(SCAN, FID, {"dueAt": PAST})
    assert past is not None and past["overdue"] is True
    assert _codes(world)[-1] == "REMEDIATION_DUE_DATE_CHANGED"

    cleared = await service.set_finding_remediation(SCAN, FID, {"dueAt": None})
    assert cleared is not None and cleared["due_at"] is None
    assert cleared["overdue"] is False


async def test_same_due_date_reput_emits_no_due_audit(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    await service.set_finding_remediation(SCAN, FID, {"dueAt": FUTURE})
    before = len(world.audits)
    await service.set_finding_remediation(SCAN, FID, {"dueAt": FUTURE})
    assert [str(a["action_code"]) for a in world.audits[before:]] == ["REMEDIATION_UPDATED"]


async def test_absent_keys_leave_stored_values(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    await service.set_finding_remediation(
        SCAN, FID, {"assigneeUserId": str(TEAMMATE_ID), "dueAt": FUTURE}
    )
    row = await service.set_finding_remediation(SCAN, FID, {"status": "DONE"})
    assert row is not None
    assert row["assignee_user_id"] == str(TEAMMATE_ID)
    assert row["due_at"] is not None
    assert row["overdue"] is False  # DONE is never overdue


# --------------------------------------------------------------------------- #
# Comments                                                                    #
# --------------------------------------------------------------------------- #


async def test_comments_append_list_order(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    first = await service.add_remediation_comment(SCAN, FID, {"body": "first"})
    second = await service.add_remediation_comment(SCAN, FID, {"body": "second"})
    assert first is not None and second is not None
    assert first["author_user_id"] == str(OWNER_ID)
    assert first["author_email"] == "owner@example.com"
    rows = await service.list_remediation_comments(SCAN, FID)
    assert rows is not None and [r["body"] for r in rows] == ["first", "second"]
    assert _codes(world)[-2:] == ["REMEDIATION_COMMENT_ADDED", "REMEDIATION_COMMENT_ADDED"]
    # Audit references the comment id only — bodies stay out of the trail.
    assert set(world.audits[-1]["metadata_json"]) == {"fingerprint", "targetId"}


async def test_comment_on_foreign_finding_is_404(world) -> None:  # type: ignore[no-untyped-def]
    assert await world.service().add_remediation_comment(SCAN, uuid.uuid4(), {"body": "x"}) is None
    assert await world.service().list_remediation_comments(SCAN, uuid.uuid4()) is None


async def test_comment_malformed_is_400(world) -> None:  # type: ignore[no-untyped-def]
    for bad in ({}, {"body": ""}, {"body": "x" * 2001}, {"body": "a\x00b"}):
        with pytest.raises(InvalidRemediationError):
            await world.service().add_remediation_comment(SCAN, FID, bad)


async def test_comment_leaves_canonical_untouched(world) -> None:  # type: ignore[no-untyped-def]
    service = world.service()
    await service.set_finding_remediation(SCAN, FID, {"status": "TODO"})
    await service.add_remediation_comment(SCAN, FID, {"body": "note"})
    row = await service.get_finding_remediation(SCAN, FID)
    assert row is not None and row["status"] == "TODO"
    finding = _finding()
    assert (finding.title, finding.fingerprint) == ("Missing HSTS", FP)


# --------------------------------------------------------------------------- #
# Dashboard summary                                                           #
# --------------------------------------------------------------------------- #


def _seed(world, fingerprint: str, **fields: object) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC).isoformat()
    row: dict[str, object] = {
        "id": str(uuid.uuid4()),
        "fingerprint": fingerprint,
        "target_id": str(TARGET),
        "status": "TODO",
        "notes": None,
        "updated_by_user_id": str(OWNER_ID),
        "assignee_user_id": None,
        "assigned_at": None,
        "assigned_by_user_id": None,
        "due_at": None,
        "verified_in_scan_id": None,
        "created_at": now,
        "updated_at": now,
    }
    row.update(fields)
    world.store.rows[(fingerprint, str(TARGET))] = row


async def test_summary_aggregates(world) -> None:  # type: ignore[no-untyped-def]
    _seed(world, FP, status="IN_PROGRESS", assignee_user_id=str(TEAMMATE_ID), due_at=PAST)
    _seed(world, FP2, status="DONE", due_at=FUTURE)
    _seed(world, "fp-c", status="DEFERRED")
    world.history.extend(
        [
            {"target_id": str(TARGET), "fingerprint": FP, "status": "PERSISTENT"},
            {"target_id": str(TARGET), "fingerprint": FP2, "status": "RESOLVED"},
        ]
    )
    summary = await world.service().get_remediation_summary()
    assert summary["total"] == 3
    assert summary["by_status"] == {"DEFERRED": 1, "DONE": 1, "IN_PROGRESS": 1}
    assert summary["assigned"] == 1
    assert summary["unassigned"] == 2
    assert summary["overdue"] == 1
    assert summary["due_open"] == 1
    assert summary["no_due_date"] == 1
    assert summary["done_open"] == 0  # DONE row is RESOLVED, not open
    assert summary["resolved_after_remediation"] == 1
    assert summary["regressed_after_remediation"] == 0
    assert summary["lifecycle_unknown"] == 1
    assert summary["by_assignee"] == {str(TEAMMATE_ID): 1}
    assert [i["fingerprint"] for i in summary["overdue_items"]] == [FP]
    assert [i["fingerprint"] for i in summary["unassigned_items"]] == ["fp-c", FP2]
    # FP2 is DONE (never due-soon) and FP is already overdue: nothing due-soon.
    assert summary["due_soon_items"] == []


async def test_summary_done_open_and_regressed(world) -> None:  # type: ignore[no-untyped-def]
    """DONE+PERSISTENT stays valid and counts as done-open; REGRESSED counts too."""
    _seed(world, FP, status="DONE", due_at=PAST)  # DONE with past due: not overdue
    _seed(world, FP2, status="IN_PROGRESS")
    world.history.extend(
        [
            {"target_id": str(TARGET), "fingerprint": FP, "status": "PERSISTENT"},
            {"target_id": str(TARGET), "fingerprint": FP2, "status": "REGRESSED"},
        ]
    )
    summary = await world.service().get_remediation_summary()
    assert summary["done_open"] == 1
    assert summary["regressed_after_remediation"] == 1
    assert summary["overdue"] == 0


async def test_summary_empty(world) -> None:  # type: ignore[no-untyped-def]
    summary = await world.service().get_remediation_summary()
    assert summary["total"] == 0
    assert summary["overdue_items"] == []
    outsider_summary = await world.service(OUTSIDER_ID).get_remediation_summary()
    assert outsider_summary["total"] == 0


async def test_summary_ordering_deterministic(world) -> None:  # type: ignore[no-untyped-def]
    for fp in ("fp-z", "fp-a", "fp-m"):
        _seed(world, fp, status="TODO")
    summary = await world.service().get_remediation_summary()
    assert [i["fingerprint"] for i in summary["unassigned_items"]] == ["fp-a", "fp-m", "fp-z"]


# --------------------------------------------------------------------------- #
# Verify-fix integration                                                      #
# --------------------------------------------------------------------------- #


async def test_verify_fix_after_assignment_uses_normal_rescan(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Assigned → DONE → verify: rescan via the standard gated path, then link."""
    from src.domain.scans.errors import ScanRateLimitedError
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    service = world.service()
    await service.set_finding_remediation(
        SCAN, FID, {"status": "DONE", "assigneeUserId": str(TEAMMATE_ID)}
    )
    rescan_id = uuid.uuid4()
    calls: list[str] = []

    async def fake_rescan(_self: object, _sid: uuid.UUID) -> object:
        calls.append("rescan")
        return SimpleNamespace(id=rescan_id, status_code="QUEUED")

    async def fake_link(_self: object, **kwargs: object) -> dict:
        calls.append("link")
        assert kwargs["scan_id"] == rescan_id
        return {"linked": True}

    monkeypatch.setattr(ScanService, "rescan_scan", fake_rescan)
    monkeypatch.setattr(ScanEngineExecutionRepository, "set_verification_link", fake_link)
    outcome = await service.request_verify_fix(SCAN, FID)
    assert outcome is not None and outcome["rescan_id"] == str(rescan_id)
    assert calls == ["rescan", "link"]

    # Gates still propagate: a rate-limited rescan fails the same way.
    async def limited_rescan(_self: object, _sid: uuid.UUID) -> object:
        raise ScanRateLimitedError()

    monkeypatch.setattr(ScanService, "rescan_scan", limited_rescan)
    with pytest.raises(ScanRateLimitedError):
        await service.request_verify_fix(SCAN, FID)
    assert calls == ["rescan", "link"]  # no link attempted on gate failure


# --------------------------------------------------------------------------- #
# Report block                                                                #
# --------------------------------------------------------------------------- #


async def test_report_v2_remediation_block(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """v2 JSON exposes assignee/due/overdue; DONE+PERSISTENT stays coherent."""
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )
    from src.reporting.assembler import (
        ReportDocument,
        ReportEngineSummary,
        ReportFinding,
        ReportPriority,
        ReportScanMetadata,
    )

    created = datetime(2026, 5, 1, tzinfo=UTC)
    await world.service().set_finding_remediation(
        SCAN, FID, {"status": "DONE", "assigneeUserId": str(TEAMMATE_ID), "dueAt": PAST}
    )
    world.history.append({"target_id": str(TARGET), "fingerprint": FP, "status": "PERSISTENT"})

    async def fake_visible(_self: object, sid: uuid.UUID) -> object:
        return SimpleNamespace(id=SCAN, target_id=TARGET, created_at=created)

    async def fake_assemble(_self: object, sid: uuid.UUID) -> object:
        return ReportDocument(
            schema_version="x",
            generated_at=created,
            scan=ReportScanMetadata(
                target_hostname="example.com",
                target_normalized_url="https://example.com/",
                scan_id=SCAN,
                scan_profile="standard",
                scan_status="REPORT_READY",
                initiated_by_user_id=OWNER_ID,
                queued_at=created,
                started_at=created,
                completed_at=created,
            ),
            engines=(
                ReportEngineSummary(
                    engine_code="headers-analyzer",
                    tool_version_snapshot="1",
                    status="SUCCEEDED",
                    started_at=created,
                    completed_at=created,
                    error_message=None,
                ),
            ),
            findings=(
                ReportFinding(
                    id=FID,
                    severity="HIGH",
                    category="MISSING_SECURITY_HEADER",
                    title="t",
                    description="d",
                    evidence="e",
                    location="/",
                    recommendation="r",
                    fingerprint=FP,
                    affected_asset=None,
                    source_engine_code="headers-analyzer",
                    lifecycle_status="PERSISTENT",
                    priority=ReportPriority(
                        score=70, level="HIGH", version="v2", factors=("severity",)
                    ),
                ),
            ),
            assessment=None,
            severity_counts={"HIGH": 1},
            lifecycle_counts={"PERSISTENT": 1},
        )

    async def fake_list(_self: object, **kwargs: object) -> list:
        return []

    async def fake_tech(_self: object, target_id: uuid.UUID) -> list:
        return []

    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )
    from src.reporting.assembler import ReportAssembler

    async def fake_map(_self: object, **kwargs: object) -> dict:
        row = await world.store.get_remediation(fingerprint=FP, target_id=TARGET)
        return {FP: row} if row is not None else {}

    monkeypatch.setattr(ScanService, "_get_visible_scan", fake_visible)
    monkeypatch.setattr(ReportAssembler, "assemble", fake_assemble)
    monkeypatch.setattr(ScanService, "list_scans", fake_list)
    monkeypatch.setattr(TargetRepository, "list_technologies", fake_tech)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_remediations_for_target", fake_map)

    report = await world.service().get_scan_report_v2(SCAN)
    assert report is not None
    (finding,) = [f for f in report["findings"] if f["fingerprint"] == FP]
    assert finding["lifecycleStatus"] == "PERSISTENT"  # canonical truth untouched
    remediation = finding["remediation"]
    assert remediation["status"] == "DONE"  # operator intent coexists
    assert remediation["assigneeUserId"] == str(TEAMMATE_ID)
    assert remediation["assigneeEmail"] == "teammate@example.com"
    assert remediation["dueAt"] is not None
    assert remediation["overdue"] is False  # DONE is never overdue


# --------------------------------------------------------------------------- #
# Concurrency                                                               #
# --------------------------------------------------------------------------- #


async def test_concurrent_writes_never_duplicate_rows(world) -> None:  # type: ignore[no-untyped-def]
    """Ten racing upserts on one identity leave exactly one row (upsert keying)."""
    import asyncio

    service = world.service()
    results = await asyncio.gather(
        *(
            service.set_finding_remediation(SCAN, FID, {"status": status, "notes": f"writer-{i}"})
            for i, status in enumerate(
                [
                    "TODO",
                    "IN_PROGRESS",
                    "DONE",
                    "TODO",
                    "IN_PROGRESS",
                    "DONE",
                    "TODO",
                    "IN_PROGRESS",
                    "DONE",
                    "TODO",
                ]
            )
        )
    )
    assert all(r is not None for r in results)
    assert len(world.store.rows) == 1
    ids = {str(r["id"]) for r in results if r is not None}
    assert ids == {str(next(iter(world.store.rows.values()))["id"])}


# --------------------------------------------------------------------------- #
# Static AI guard                                                             #
# --------------------------------------------------------------------------- #


def test_gemini_cannot_drive_remediation_state() -> None:
    """STEP 13: no AI/conversation module may write remediation state."""
    import pathlib

    roots = [
        pathlib.Path("backend/src/domain/conversations"),
        pathlib.Path("backend/src/infrastructure/ai"),
    ]
    forbidden = (
        "set_remediation",
        "add_comment",
        "set_verification_link",
        "assigned_by_user_id",
        "assignee_user_id",
        "REMEDIATION_UPDATED",
    )
    hits = [
        f"{path}:{i}"
        for root in roots
        for path in sorted(root.rglob("*.py"))
        for i, line in enumerate(path.read_text().splitlines(), 1)
        if any(token in line for token in forbidden)
    ]
    assert hits == []


# --------------------------------------------------------------------------- #
# HTTP envelope                                                               #
# --------------------------------------------------------------------------- #


@pytest.fixture
def client(world, monkeypatch):  # type: ignore[no-untyped-def]
    from httpx import ASGITransport, AsyncClient

    from src.config.settings import get_settings
    from src.domain.users.token_service import create_access_token
    from src.infrastructure.database.connection import get_db_session
    from src.main import create_application

    application = create_application()

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield object()

    application.dependency_overrides[get_db_session] = _overridden_session
    settings = get_settings()

    def cookies(uid: uuid.UUID) -> dict[str, str]:
        return {
            "accessToken": create_access_token(
                user_id=uid,
                secret_key=settings.jwt_secret_key,
                algorithm=settings.jwt_algorithm,
                expires_in_minutes=settings.access_token_expire_minutes,
            )
        }

    transport = ASGITransport(app=application)
    return SimpleNamespace(
        client=AsyncClient(transport=transport, base_url="http://test"), cookies=cookies
    )


async def test_remediation_http_assign_and_due(client, world) -> None:  # type: ignore[no-untyped-def]
    """One payload sets status+assignee+due; response carries display fields."""
    response = await client.client.put(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation",
        json={
            "status": "IN_PROGRESS",
            "assigneeUserId": str(TEAMMATE_ID),
            "dueAt": FUTURE,
            "notes": "patch in progress",
        },
        cookies=client.cookies(OWNER_ID),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "IN_PROGRESS"
    assert body["assigneeUserId"] == str(TEAMMATE_ID)
    assert body["assigneeEmail"] == "teammate@example.com"
    assert body["assignedAt"] is not None
    assert body["assignedByUserId"] == str(OWNER_ID)
    assert body["dueAt"] is not None
    assert body["overdue"] is False

    fetched = await client.client.get(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation",
        cookies=client.cookies(OWNER_ID),
    )
    assert fetched.status_code == 200
    assert fetched.json()["assigneeUserId"] == str(TEAMMATE_ID)


async def test_remediation_http_validation(client, world) -> None:  # type: ignore[no-untyped-def]
    bad_payloads = [
        {"status": "RESOLVED"},
        {"assigneeUserId": "nope"},
        {"assigneeUserId": str(uuid.uuid4())},
        {"assigneeUserId": str(INACTIVE_ID)},
        {"dueAt": "2030-01-01T00:00:00"},
        {"dueAt": "tomorrow"},
    ]
    for payload in bad_payloads:
        response = await client.client.put(
            f"/api/v1/scans/{SCAN}/findings/{FID}/remediation",
            json=payload,
            cookies=client.cookies(OWNER_ID),
        )
        assert response.status_code in (400, 404), (payload, response.text)
    foreign = await client.client.put(
        f"/api/v1/scans/{uuid.uuid4()}/findings/{FID}/remediation",
        json={"status": "TODO"},
        cookies=client.cookies(OWNER_ID),
    )
    assert foreign.status_code == 404


async def test_comments_http_roundtrip(client, world) -> None:  # type: ignore[no-untyped-def]
    created = await client.client.post(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation/comments",
        json={"body": "handing to backend team"},
        cookies=client.cookies(OWNER_ID),
    )
    assert created.status_code == 201, created.text
    assert created.json()["authorUserId"] == str(OWNER_ID)
    listed = await client.client.get(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation/comments",
        cookies=client.cookies(OWNER_ID),
    )
    assert listed.status_code == 200
    assert [c["body"] for c in listed.json()] == ["handing to backend team"]
    # Cross-owner: invisible finding, not forbidden.
    outsider = await client.client.get(
        f"/api/v1/scans/{uuid.uuid4()}/findings/{FID}/remediation/comments",
        cookies=client.cookies(OWNER_ID),
    )
    assert outsider.status_code == 404
    empty = await client.client.post(
        f"/api/v1/scans/{SCAN}/findings/{FID}/remediation/comments",
        json={"body": "  "},
        cookies=client.cookies(OWNER_ID),
    )
    assert empty.status_code == 400


async def test_findings_filters_http(client, world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Status/assignee/overdue/severity filters compose; order is stable."""
    from src.infrastructure.database.repositories.scan_repository import (
        ScanEngineExecutionRepository,
    )

    async def fake_visible_scan(_self: object, sid: uuid.UUID) -> object:
        return SimpleNamespace(id=SCAN, target_id=TARGET, status_code="REPORT_READY")

    async def fake_dtos(_self: object, sid: uuid.UUID) -> list[dict]:
        return [
            {
                "id": str(uuid.uuid4()),
                "title": "b",
                "severity": "HIGH",
                "fingerprint": FP2,
                "description": "",
                "evidence": "",
                "location": "",
                "recommendation": "",
                "createdAt": "2026-01-01T00:00:00Z",
            },
            {
                "id": str(uuid.uuid4()),
                "title": "a",
                "severity": "LOW",
                "fingerprint": FP,
                "description": "",
                "evidence": "",
                "location": "",
                "recommendation": "",
                "createdAt": "2026-01-01T00:00:00Z",
            },
        ]

    async def fake_evidence(_self: object, ids: list[str]) -> dict:
        return {}

    async def fake_remediations(_self: object, **kwargs: object) -> dict:
        return {
            FP: {
                "status": "IN_PROGRESS",
                "assignee_user_id": str(TEAMMATE_ID),
                "due_at": PAST,
                "notes": None,
            },
            FP2: {"status": "TODO", "assignee_user_id": None, "due_at": None, "notes": None},
        }

    monkeypatch.setattr(ScanService, "get_scan", fake_visible_scan)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_finding_dtos", fake_dtos)
    monkeypatch.setattr(ScanEngineExecutionRepository, "list_evidence_for_findings", fake_evidence)
    monkeypatch.setattr(
        ScanEngineExecutionRepository, "list_remediations_for_target", fake_remediations
    )
    base = f"/api/v1/scans/{SCAN}/findings"
    all_rows = await client.client.get(base, cookies=client.cookies(OWNER_ID))
    assert all_rows.status_code == 200, all_rows.text
    assert [r["title"] for r in all_rows.json()] == ["b", "a"]

    done = await client.client.get(
        base, params={"remediationStatus": "done"}, cookies=client.cookies(OWNER_ID)
    )
    assert done.status_code == 200 and done.json() == []

    prog = await client.client.get(
        base, params={"remediationStatus": "IN_PROGRESS"}, cookies=client.cookies(OWNER_ID)
    )
    assert [r["title"] for r in prog.json()] == ["a"]

    mine = await client.client.get(
        base, params={"assignee": str(TEAMMATE_ID)}, cookies=client.cookies(OWNER_ID)
    )
    assert [r["title"] for r in mine.json()] == ["a"]

    unassigned = await client.client.get(
        base, params={"assignee": "unassigned"}, cookies=client.cookies(OWNER_ID)
    )
    assert [r["title"] for r in unassigned.json()] == ["b"]

    overdue = await client.client.get(
        base, params={"overdue": "true"}, cookies=client.cookies(OWNER_ID)
    )
    assert [r["title"] for r in overdue.json()] == ["a"]

    low = await client.client.get(
        base, params={"severity": "low"}, cookies=client.cookies(OWNER_ID)
    )
    assert [r["title"] for r in low.json()] == ["a"]

    combo = await client.client.get(
        base,
        params={"remediationStatus": "TODO", "severity": "HIGH"},
        cookies=client.cookies(OWNER_ID),
    )
    assert [r["title"] for r in combo.json()] == ["b"]

    bad_status = await client.client.get(
        base, params={"remediationStatus": "FIXED"}, cookies=client.cookies(OWNER_ID)
    )
    assert bad_status.status_code == 400
    bad_assignee = await client.client.get(
        base, params={"assignee": "nope"}, cookies=client.cookies(OWNER_ID)
    )
    assert bad_assignee.status_code == 400


async def test_dashboard_remediation_http(client, world) -> None:  # type: ignore[no-untyped-def]
    _seed(world, FP, status="IN_PROGRESS", assignee_user_id=str(TEAMMATE_ID), due_at=PAST)
    response = await client.client.get(
        "/api/v1/dashboard/remediation", cookies=client.cookies(OWNER_ID)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total"] == 1
    assert body["overdue"] == 1
    assert body["byAssignee"] == {str(TEAMMATE_ID): 1}
    assert body["overdueItems"][0]["assigneeEmail"] == "teammate@example.com"
