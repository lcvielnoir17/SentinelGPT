"""Unit tests for organization & membership RBAC (SRS Chapter 5 §3)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.domain.errors import ForbiddenError, NotFoundError
from src.domain.organizations.organization_service import OrganizationService
from src.domain.users.user_service import UserAccount
from src.infrastructure.database.models import Organization, OrganizationMembership

ADMIN = "ADMIN"
MEMBER = "MEMBER"


class FakeMembershipRepo:
    def __init__(self) -> None:
        self.memberships: dict[tuple[uuid.UUID, uuid.UUID], OrganizationMembership] = {}
        self.orgs: dict[uuid.UUID, Organization] = {}

    async def is_member(self, user_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        return (org_id, user_id) in self.memberships

    async def is_admin(self, user_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        m = self.memberships.get((org_id, user_id))
        return m is not None and m.role == ADMIN

    async def get_membership(
        self, org_id: uuid.UUID, user_id: uuid.UUID
    ) -> OrganizationMembership | None:
        return self.memberships.get((org_id, user_id))

    async def list_members(self, org_id: uuid.UUID) -> list:
        return [m for (o, _u), m in self.memberships.items() if o == org_id]

    def add_membership(self, membership: OrganizationMembership) -> None:
        self.memberships[(membership.organization_id, membership.user_id)] = membership

    async def flush(self) -> None:
        return None

    async def delete_membership(self, membership: OrganizationMembership) -> None:
        self.memberships.pop((membership.organization_id, membership.user_id), None)


class FakeSession:
    """Tracks organizations added via session.add (service contract)."""

    def __init__(self) -> None:
        self.orgs: dict[uuid.UUID, Organization] = {}

    def add(self, obj) -> None:  # type: ignore[no-untyped-def]
        if isinstance(obj, Organization):
            self.orgs[obj.id] = obj

    async def flush(self) -> None:
        return None

    async def rollback(self) -> None:
        return None

    async def execute(self, _stmt: object) -> None:
        class R:
            def __init__(self, rows: list) -> None:
                self._rows = rows

            def first(self):  # type: ignore[no-untyped-def]
                return self._rows[0] if self._rows else None

        # The only raw query the service may issue: email→user lookup.
        return R([(uuid.uuid4(),)])


def _principal() -> UserAccount:
    return UserAccount(id=uuid.uuid4(), email="a@example.com", created_at=datetime.now(UTC))


def _make(
    mocker, principal: UserAccount
) -> tuple[OrganizationService, FakeMembershipRepo, FakeSession]:
    repo = FakeMembershipRepo()
    mocker.patch(
        "src.domain.organizations.organization_service.MembershipRepository",
        lambda _s: repo,
    )
    return OrganizationService(FakeSession(), principal), repo


async def test_creator_becomes_admin_and_org_persists(mocker) -> None:  # type: ignore[no-untyped-def]
    owner = _principal()
    service, repo = _make(mocker, owner)

    details = await service.create_organization("Acme Security")

    assert details.name == "Acme Security"
    membership = repo.memberships[(details.id, owner.id)]
    assert membership.role == ADMIN


async def test_non_member_gets_404_not_403_for_reads(mocker) -> None:  # type: ignore[no-untyped-def]
    owner, outsider = _principal(), _principal()
    service_owner, _ = _make(mocker, owner)
    org = await service_owner.create_organization("Secret Org")

    with pytest.raises(NotFoundError):
        await OrganizationService(FakeSession(), outsider).get_organization(org.id)


async def test_member_cannot_mutate_admin_can(mocker) -> None:  # type: ignore[no-untyped-def]
    admin, member = _principal(), _principal()
    service_admin, repo = _make(mocker, admin)
    org = await service_admin.create_organization("Org")

    # Admin invites the member.
    added = await service_admin.add_member(org.id, user_id=member.id, role=MEMBER)
    assert added.role == MEMBER

    service_member = OrganizationService(FakeSession(), member)

    # Member attempts to invite → 403.
    with pytest.raises(ForbiddenError):
        await service_member.add_member(org.id, user_id=admin.id, role=ADMIN)
    # Member cannot change roles; admin can.
    with pytest.raises(ForbiddenError):
        await service_member.change_role(org.id, member.id, role=ADMIN)

    # Member cannot remove anyone; admin removes the member.
    with pytest.raises(ForbiddenError):
        await service_member.remove_member(org.id, member.id)
    changed = await service_admin.change_role(org.id, member.id, role=ADMIN)
    assert changed.role == ADMIN
    assert (org.id, member.id) in repo.memberships


async def test_unknown_member_removal_is_404(mocker) -> None:  # type: ignore[no-untyped-def]
    admin = _principal()
    stranger = _principal()
    service, _repo = _make(mocker, admin)
    org = await service.create_organization("Solo Org")

    with pytest.raises(NotFoundError):
        await service.remove_member(org.id, stranger.id)


async def test_last_admin_cannot_be_demoted_or_removed(mocker) -> None:  # type: ignore[no-untyped-def]
    """Sole ADMIN is protected: demotion/removal would orphan the tenant."""
    admin, member = _principal(), _principal()
    service, repo = _make(mocker, admin)
    org = await service.create_organization("Solo Org")
    await service.add_member(org.id, user_id=member.id, role=MEMBER)

    with pytest.raises(ForbiddenError):
        await service.change_role(org.id, admin.id, role=MEMBER)
    with pytest.raises(ForbiddenError):
        await service.remove_member(org.id, admin.id)
    # Guard refused before mutating: sole admin still present.
    assert repo.memberships[(org.id, admin.id)].role == ADMIN

    # With a second ADMIN present, demotion/removal of one is allowed.
    await service.change_role(org.id, member.id, role=ADMIN)
    changed = await service.change_role(org.id, admin.id, role=MEMBER)
    assert changed.role == MEMBER
    from src.domain.organizations.organization_service import OrganizationService

    service_member_admin = OrganizationService(FakeSession(), member)
    await service_member_admin.remove_member(org.id, admin.id)
    assert (org.id, admin.id) not in repo.memberships


async def test_concurrent_duplicate_invite_is_idempotent(mocker) -> None:  # type: ignore[no-untyped-def]
    """A racer committing between check and flush returns the row, not 500."""
    from sqlalchemy.exc import IntegrityError

    admin, member = _principal(), _principal()
    service, repo = _make(mocker, admin)
    org = await service.create_organization("Org")
    existing = OrganizationMembership(
        id=uuid.uuid4(),
        organization_id=org.id,
        user_id=member.id,
        role=MEMBER,
    )
    repo.add_membership(existing)

    calls = {"get": 0}
    real_get = repo.get_membership

    async def fake_get(org_id, user_id):  # type: ignore[no-untyped-def]
        calls["get"] += 1
        if calls["get"] == 1:
            return None  # racer has not committed yet (from our viewpoint)
        return await real_get(org_id, user_id)

    async def fake_flush_once() -> None:
        raise IntegrityError("INSERT INTO membership", {}, Exception("unique_violation"))

    mocker.patch.object(repo, "get_membership", fake_get)
    mocker.patch.object(repo, "flush", lambda: fake_flush_once())

    added = await service.add_member(org.id, user_id=member.id, role=MEMBER)
    assert added.user_id == member.id


async def test_invite_missing_user_is_404_not_500(mocker) -> None:  # type: ignore[no-untyped-def]
    """A dangling user reference maps to NOT_FOUND, not INTERNAL_ERROR."""
    from sqlalchemy.exc import IntegrityError

    admin, ghost = _principal(), _principal()
    service, repo = _make(mocker, admin)
    org = await service.create_organization("Org")

    async def fake_flush_once() -> None:
        # Simulate rollback discarding the staged row (a real session
        # drops the pending insert; the in-memory fake stages eagerly).
        repo.memberships.pop((org.id, ghost.id), None)
        raise IntegrityError("INSERT INTO membership", {}, Exception("fk_violation"))

    mocker.patch.object(repo, "flush", lambda: fake_flush_once())

    with pytest.raises(NotFoundError):
        await service.add_member(org.id, user_id=ghost.id, role=MEMBER)
