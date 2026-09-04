"""Unit tests for Phase 1 target endpoints and tenant isolation.

Follows the established unit-test conventions (no live database; repository
methods patched per test_auth.py) plus a static migration-chain check.
"""

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import get_settings
from src.domain.users.token_service import create_access_token
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import Target, User
from src.infrastructure.database.repositories.membership_repository import (
    MembershipRepository,
)
from src.infrastructure.database.repositories.target_repository import (
    TargetRepository,
)
from src.infrastructure.database.repositories.user_repository import UserRepository
from src.main import create_application

SETTINGS = get_settings()


def _make_user(email: str = "analyst@example.com") -> User:
    now = datetime.now(UTC)
    return User(
        id=uuid.uuid4(),
        email=email,
        password_hash="argon2id$fake",
        mfa_enabled=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def _make_target(
    owner_organization_id: uuid.UUID | None,
    owner_user_id: uuid.UUID | None,
    url: str,
    created_at: datetime | None = None,
    is_archived: bool = False,
) -> Target:
    return Target(
        id=uuid.uuid4(),
        owner_organization_id=owner_organization_id,
        owner_user_id=owner_user_id,
        hostname=url.split("//", 1)[1].rstrip("/"),
        normalized_url=url,
        is_archived=is_archived,
        created_at=created_at or datetime.now(UTC),
    )


@pytest.fixture
def state(mocker):
    """In-memory persistence + membership state shared by patched repos."""
    state: dict[str, object] = {
        "targets": [],  # all persisted/seeded Target rows
        "memberships": set(),  # {(user_id, organization_id)}
    }

    def _matches(row: Target, org_id, user_id) -> bool:
        ok_org = (
            row.owner_organization_id is None
            if org_id is None
            else row.owner_organization_id == org_id
        )
        ok_user = row.owner_user_id is None if user_id is None else row.owner_user_id == user_id
        return ok_org and ok_user

    async def fake_find_by_owner_and_url(
        _self, *, owner_organization_id, owner_user_id, normalized_url
    ):
        return next(
            (
                t
                for t in state["targets"]
                if _matches(t, owner_organization_id, owner_user_id)
                and t.normalized_url == normalized_url
            ),
            None,
        )

    async def fake_get_by_target_id(_self, target_id):
        return next((t for t in state["targets"] if t.id == target_id), None)

    async def fake_list_for_owner(
        _self,
        *,
        owner_organization_id,
        owner_user_id,
        include_archived,
        limit,
        cursor_created_at,
        cursor_id,
    ):
        rows = [
            t
            for t in state["targets"]
            if _matches(t, owner_organization_id, owner_user_id)
            and (include_archived or not t.is_archived)
        ]
        rows.sort(key=lambda t: (t.created_at, str(t.id)), reverse=True)
        if cursor_created_at is not None and cursor_id is not None:
            cursor_key = (cursor_created_at, str(cursor_id))
            rows = [t for t in rows if (t.created_at, str(t.id)) < cursor_key]
        return rows[:limit]

    def fake_add(_self, target: Target) -> None:
        state["targets"].append(target)

    async def fake_flush(_self) -> None:
        return None

    async def fake_is_member(_self, user_id, organization_id) -> bool:
        return (user_id, organization_id) in state["memberships"]

    mocker.patch.object(TargetRepository, "find_by_owner_and_url", fake_find_by_owner_and_url)
    mocker.patch.object(TargetRepository, "get_by_id", fake_get_by_target_id)
    mocker.patch.object(TargetRepository, "list_for_owner", fake_list_for_owner)
    mocker.patch.object(TargetRepository, "add", fake_add)
    mocker.patch.object(TargetRepository, "flush", fake_flush)
    mocker.patch.object(MembershipRepository, "is_member", fake_is_member)
    return state


@pytest.fixture
async def client(state, mocker) -> AsyncClient:
    application = create_application()

    # Unit tests must never open a real database connection.
    async def _overridden_session():
        yield object()

    application.dependency_overrides[get_db_session] = _overridden_session

    # Auth dependency resolves the principal through UserRepository.get_by_id;
    # patch it to return the seeded principal without touching the database.
    principal = _make_user()
    state["principal_row"] = principal

    async def fake_get_by_user_id(_self, user_id):
        found: User | None = state["principal_row"]
        if found is not None and found.id == user_id:
            return found
        return None

    mocker.patch.object(UserRepository, "get_by_id", fake_get_by_user_id)

    transport = ASGITransport(app=application)
    return AsyncClient(transport=transport, base_url="http://test")


def _auth_cookies(user: User) -> dict[str, str]:
    token = create_access_token(
        user_id=user.id,
        secret_key=SETTINGS.jwt_secret_key,
        algorithm=SETTINGS.jwt_algorithm,
        expires_in_minutes=SETTINGS.access_token_expire_minutes,
    )
    return {"accessToken": token}


# ---------------------------------------------------------------------------
# Authentication requirements
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_create_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/targets",
        json={"hostname": "example.com", "url": "https://example.com"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.asyncio
async def test_invalid_token_cookie_is_rejected(client: AsyncClient) -> None:
    response = await client.get("/api/v1/targets", cookies={"accessToken": "garbage"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


# ---------------------------------------------------------------------------
# POST /api/v1/targets — creation & validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authenticated_personal_creation_persists(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    response = await client.post(
        "/api/v1/targets",
        json={"hostname": "Example.COM", "url": "https://Example.COM"},
        cookies=_auth_cookies(principal),
    )

    assert response.status_code == 201
    body = response.json()
    assert uuid.UUID(body["id"])
    assert body["hostname"] == "example.com"
    assert body["url"] == "https://example.com/"
    assert body["ownerUserId"] == str(principal.id)
    assert body["ownerOrganizationId"] is None
    assert body["isArchived"] is False
    assert body["status"] == "PENDING_ATTESTATION"
    assert "createdAt" in body

    # Database persistence: exactly one fully-populated ORM row was staged.
    staged: list[Target] = [
        t for t in state["targets"] if t.normalized_url == "https://example.com/"
    ]
    assert len(staged) == 1
    assert staged[0].hostname == "example.com"
    assert staged[0].created_at.tzinfo is not None


@pytest.mark.asyncio
async def test_create_in_member_organization(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    org_id = uuid.uuid4()
    state["memberships"].add((principal.id, org_id))

    response = await client.post(
        "/api/v1/targets",
        json={
            "hostname": "example.com",
            "url": "https://example.com",
            "ownerOrganizationId": str(org_id),
        },
        cookies=_auth_cookies(principal),
    )

    assert response.status_code == 201
    body = response.json()
    assert body["ownerOrganizationId"] == str(org_id)
    assert body["ownerUserId"] is None


@pytest.mark.asyncio
async def test_create_in_non_member_organization_forbidden(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    response = await client.post(
        "/api/v1/targets",
        json={
            "hostname": "example.com",
            "url": "https://example.com",
            "ownerOrganizationId": str(uuid.uuid4()),
        },
        cookies=_auth_cookies(principal),
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_duplicate_target_conflict(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    state["targets"].append(
        _make_target(
            owner_organization_id=None,
            owner_user_id=principal.id,
            url="https://example.com/",
        )
    )

    response = await client.post(
        "/api/v1/targets",
        json={"hostname": "example.com", "url": "https://example.com"},
        cookies=_auth_cookies(principal),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_trailing_dot_form_conflicts_with_canonical_target(
    client: AsyncClient, state
) -> None:
    """FQDN trailing dot is canonicalized — no second registration (audit M-1)."""
    principal: User = state["principal_row"]
    state["targets"].append(
        _make_target(
            owner_organization_id=None,
            owner_user_id=principal.id,
            url="https://example.com/",
        )
    )

    response = await client.post(
        "/api/v1/targets",
        json={"hostname": "example.com.", "url": "https://Example.COM./"},
        cookies=_auth_cookies(principal),
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"


@pytest.mark.parametrize(
    ("hostname", "url"),
    [
        ("localhost", "http://localhost"),
        ("127.0.0.1", "http://127.0.0.1"),
        ("169.254.169.254", "http://169.254.169.254/latest/meta-data/"),
        ("example.com", "ftp://example.com"),
        ("mismatch.com", "https://example.com"),
    ],
)
@pytest.mark.asyncio
async def test_ssrf_and_validation_failures_are_unprocessable_target(
    client: AsyncClient, state, hostname: str, url: str
) -> None:
    principal: User = state["principal_row"]
    response = await client.post(
        "/api/v1/targets",
        json={"hostname": hostname, "url": url},
        cookies=_auth_cookies(principal),
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "UNPROCESSABLE_TARGET"
    # Nothing was persisted for rejected targets.
    assert not state["targets"]


# ---------------------------------------------------------------------------
# GET — retrieval, isolation, listing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_own_target(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    target = _make_target(
        owner_organization_id=None, owner_user_id=principal.id, url="https://example.com/"
    )
    state["targets"].append(target)

    response = await client.get(f"/api/v1/targets/{target.id}", cookies=_auth_cookies(principal))

    assert response.status_code == 200
    assert response.json()["id"] == str(target.id)


@pytest.mark.asyncio
async def test_other_users_personal_target_is_not_found(client: AsyncClient, state) -> None:
    """No cross-tenant leakage: foreign resources look identical to missing."""
    principal: User = state["principal_row"]
    other = _make_target(
        owner_organization_id=None, owner_user_id=uuid.uuid4(), url="https://secret.example/"
    )
    state["targets"].append(other)

    response = await client.get(f"/api/v1/targets/{other.id}", cookies=_auth_cookies(principal))

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_org_target_hidden_from_non_member(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    org_target = _make_target(
        owner_organization_id=uuid.uuid4(), owner_user_id=None, url="https://corp.example/"
    )
    state["targets"].append(org_target)

    response = await client.get(
        f"/api/v1/targets/{org_target.id}", cookies=_auth_cookies(principal)
    )
    assert response.status_code == 404

    # ...but visible to an actual member of that organization.
    state["memberships"].add((principal.id, org_target.owner_organization_id))
    member_response = await client.get(
        f"/api/v1/targets/{org_target.id}", cookies=_auth_cookies(principal)
    )
    assert member_response.status_code == 200


@pytest.mark.asyncio
async def test_listing_scopes_personal_targets_only(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    old = datetime.now(UTC) - timedelta(hours=2)
    mine_old = _make_target(None, principal.id, "https://old.example/", created_at=old)
    mine_new = _make_target(None, principal.id, "https://new.example/")
    theirs = _make_target(None, uuid.uuid4(), "https://theirs.example/")
    org_target = _make_target(uuid.uuid4(), None, "https://corp.example/")
    state["targets"] += [mine_old, mine_new, theirs, org_target]

    response = await client.get("/api/v1/targets", cookies=_auth_cookies(principal))

    assert response.status_code == 200
    body = response.json()
    assert [item["id"] for item in body["items"]] == [str(mine_new.id), str(mine_old.id)]
    assert body["pageInfo"]["hasNextPage"] is False
    assert body["pageInfo"]["nextCursor"] is None


@pytest.mark.asyncio
async def test_listing_by_organization_membership(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    org_id = uuid.uuid4()
    state["memberships"].add((principal.id, org_id))
    org_target = _make_target(org_id, None, "https://corp.example/")
    personal = _make_target(None, principal.id, "https://personal.example/")
    state["targets"] += [org_target, personal]

    listed = await client.get(
        f"/api/v1/targets?organizationId={org_id}", cookies=_auth_cookies(principal)
    )
    assert [i["id"] for i in listed.json()["items"]] == [str(org_target.id)]


@pytest.mark.asyncio
async def test_listing_foreign_organization_forbidden(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    response = await client.get(
        f"/api/v1/targets?organizationId={uuid.uuid4()}",
        cookies=_auth_cookies(principal),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_include_archived_filter(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    archived = _make_target(None, principal.id, "https://gone.example/", is_archived=True)
    active = _make_target(None, principal.id, "https://live.example/")
    state["targets"] += [archived, active]

    default_list = await client.get("/api/v1/targets", cookies=_auth_cookies(principal))
    assert [i["id"] for i in default_list.json()["items"]] == [str(active.id)]

    with_archived = await client.get(
        "/api/v1/targets?includeArchived=true", cookies=_auth_cookies(principal)
    )
    assert {i["id"] for i in with_archived.json()["items"]} == {
        str(active.id),
        str(archived.id),
    }


@pytest.mark.asyncio
async def test_keyset_pagination_walks_all_pages(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    first = _make_target(None, principal.id, "https://first.example/")
    second = _make_target(None, principal.id, "https://second.example/")
    state["targets"] += [second, first]  # insertion order != sort order

    page_one = await client.get("/api/v1/targets?limit=1", cookies=_auth_cookies(principal))
    body_one = page_one.json()
    assert len(body_one["items"]) == 1
    assert body_one["pageInfo"]["hasNextPage"] is True
    cursor = body_one["pageInfo"]["nextCursor"]
    assert cursor

    page_two = await client.get(
        f"/api/v1/targets?limit=1&cursor={cursor}",
        cookies=_auth_cookies(principal),
    )
    body_two = page_two.json()
    assert len(body_two["items"]) == 1
    assert body_two["pageInfo"]["hasNextPage"] is False
    assert {body_one["items"][0]["id"], body_two["items"][0]["id"]} == {
        str(first.id),
        str(second.id),
    }


@pytest.mark.asyncio
async def test_malformed_cursor_is_validation_error(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    response = await client.get(
        "/api/v1/targets?cursor=%%%bad%%%", cookies=_auth_cookies(principal)
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# ---------------------------------------------------------------------------
# PATCH / DELETE — metadata update & soft delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_archive_flag(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    target = _make_target(None, principal.id, "https://example.com/")
    state["targets"].append(target)

    response = await client.patch(
        f"/api/v1/targets/{target.id}",
        json={"isArchived": True},
        cookies=_auth_cookies(principal),
    )
    assert response.status_code == 200
    assert response.json()["isArchived"] is True
    assert target.is_archived is True


@pytest.mark.asyncio
async def test_patch_rejects_immutable_fields(client: AsyncClient, state) -> None:
    """hostname/URL are immutable — a URL change is a new target (Ch5 §4)."""
    principal: User = state["principal_row"]
    target = _make_target(None, principal.id, "https://example.com/")
    state["targets"].append(target)

    response = await client.patch(
        f"/api/v1/targets/{target.id}",
        json={"isArchived": False, "url": "https://changed.example"},
        cookies=_auth_cookies(principal),
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"
    assert target.normalized_url == "https://example.com/"


@pytest.mark.asyncio
async def test_delete_soft_deletes_own_target(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    target = _make_target(None, principal.id, "https://example.com/")
    state["targets"].append(target)

    response = await client.delete(f"/api/v1/targets/{target.id}", cookies=_auth_cookies(principal))
    assert response.status_code == 204
    assert target.is_archived is True  # soft-delete, row retained


@pytest.mark.asyncio
async def test_delete_foreign_target_is_not_found(client: AsyncClient, state) -> None:
    principal: User = state["principal_row"]
    other = _make_target(None, uuid.uuid4(), "https://secret.example/")
    state["targets"].append(other)

    response = await client.delete(f"/api/v1/targets/{other.id}", cookies=_auth_cookies(principal))
    assert response.status_code == 404
    assert other.is_archived is False


# ---------------------------------------------------------------------------
# Migration compatibility (static chain check; live up/down verified manually)
# ---------------------------------------------------------------------------


def test_migration_chain_links_target_table_to_baseline() -> None:
    from importlib import import_module

    baseline = import_module(
        "src.infrastructure.database.migrations.versions.0001_phase0_lookup_and_identity_tables"
    )
    current = import_module(
        "src.infrastructure.database.migrations.versions.0002_phase1_target_table"
    )
    assert current.revision == "0002"
    assert current.down_revision == baseline.revision == "0001"

    from src.infrastructure.database.models import Base

    assert "target" in Base.metadata.tables


def test_cursor_round_trip_matches_service_ordering() -> None:
    """Cursor payload encodes (created_at, id) — the keyset ordering key."""
    from src.api.routes.target_routes import _decode_cursor, _encode_cursor

    created = datetime.now(UTC)
    target_id = uuid.uuid4()
    decoded_created, decoded_id = _decode_cursor(_encode_cursor(created, target_id))
    assert decoded_created == created
    assert decoded_id == target_id


def test_base64_cursor_payload_shape() -> None:
    from src.api.routes.target_routes import _encode_cursor

    raw = json.loads(
        base64.urlsafe_b64decode(
            _encode_cursor(datetime(2026, 8, 25, tzinfo=UTC), uuid.UUID(int=7))
        )
    )
    assert set(raw) == {"c", "i"}


def test_migration_chain_has_single_head_at_0008() -> None:
    """The linear chain must extend to the tenant/audit index revision."""
    from importlib import import_module

    head = import_module(
        "src.infrastructure.database.migrations.versions.0008_tenant_audit_indexes"
    )
    assert head.revision == "0008"
    assert head.down_revision == "0007"

    prev = import_module("src.infrastructure.database.migrations.versions.0007_firebase_identity")
    assert prev.revision == "0007"


@pytest.mark.asyncio
async def test_concurrent_duplicate_target_returns_409_not_500(mocker) -> None:
    """A racer committing between check and flush maps to 409, not 500."""
    from sqlalchemy.exc import IntegrityError

    from src.domain.errors import DuplicateTargetError
    from src.domain.targets.target_service import TargetService
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )
    from tests.unit.conftest import FakeSession, _principal

    owner = _principal()
    session = FakeSession()
    raced_row = object()
    calls = {"find": 0}

    async def fake_find(_self, **kwargs):  # type: ignore[no-untyped-def]
        calls["find"] += 1
        return None if calls["find"] == 1 else raced_row

    async def fake_flush_once(_self) -> None:
        raise IntegrityError("INSERT INTO target", {}, Exception("unique_violation"))

    mocker.patch.object(TargetRepository, "find_by_owner_and_url", fake_find)
    mocker.patch.object(TargetRepository, "flush", fake_flush_once)
    mocker.patch.object(TargetRepository, "add", lambda _self, _t: None)

    service = TargetService(session, owner)
    with pytest.raises(DuplicateTargetError):
        await service.register_target(
            hostname="example.com",
            url="https://example.com/",
            owner_organization_id=None,
        )
    assert calls["find"] == 2
