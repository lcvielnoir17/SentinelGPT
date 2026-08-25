"""Unit tests for the Phase 1 refresh/session lifecycle (SRS Ch2 §9, Ch5 §2).

Covers: login issuing the cookie pair, rotation, reuse detection with family
revocation, logout/revocation, CSRF header enforcement, token-type separation,
and inactive-user handling. Follows existing conventions — repositories are
patched; no live database is touched.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.constants import REFRESH_COOKIE_PATH
from src.config.settings import get_settings
from src.domain.users.password_hasher import hash_password
from src.domain.users.refresh_service import (
    RefreshRejection,
    RefreshService,
    generate_raw_refresh_token,
    hash_refresh_token,
)
from src.domain.users.token_service import create_access_token
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import RefreshSession, User
from src.infrastructure.database.models.refresh_session_models import (
    SESSION_ACTIVE,
    SESSION_REVOKED,
    SESSION_ROTATED,
)
from src.infrastructure.database.repositories.refresh_session_repository import (
    RefreshSessionRepository,
)
from src.infrastructure.database.repositories.target_repository import TargetRepository
from src.infrastructure.database.repositories.user_repository import UserRepository
from src.main import create_application

SETTINGS = get_settings()
NOW = datetime.now(UTC)


def _make_user(is_active: bool = True) -> User:
    return User(
        id=uuid.uuid4(),
        email="session@example.com",
        # Real Argon2id hash so login's credential verification succeeds.
        password_hash=hash_password("correct-horse-battery"),
        mfa_enabled=False,
        is_active=is_active,
        created_at=NOW,
        updated_at=NOW,
    )


def _make_session(
    user_id: uuid.UUID,
    *,
    raw_token: str | None = None,
    status: str = SESSION_ACTIVE,
    family_id: uuid.UUID | None = None,
    expires_at: datetime | None = None,
) -> tuple[RefreshSession, str]:
    raw = raw_token or generate_raw_refresh_token()
    row = RefreshSession(
        user_id=user_id,
        family_id=family_id or uuid.uuid4(),
        token_hash=hash_refresh_token(raw),
        status=status,
        expires_at=expires_at or NOW + timedelta(days=7),
    )
    return row, raw


@pytest.fixture
def state(mocker):
    """In-memory users + sessions shared by patched repositories."""
    state: dict[str, object] = {"users": [], "sessions": []}

    async def fake_get_by_id(_self, user_id):
        return next((u for u in state["users"] if u.id == user_id), None)

    async def fake_get_by_email(_self, email):
        return next((u for u in state["users"] if u.email == email), None)

    async def fake_get_by_token_hash(_self, token_hash):
        return next((s for s in state["sessions"] if s.token_hash == token_hash), None)

    async def fake_try_mark_rotated(_self, session_id):
        for s in state["sessions"]:
            if s.id == session_id and s.status == SESSION_ACTIVE:
                s.status = SESSION_ROTATED
                return True
        return False

    async def fake_revoke_family(_self, family_id):
        for s in state["sessions"]:
            if s.family_id == family_id:
                s.status = SESSION_REVOKED

    async def fake_revoke(_self, session_id):
        for s in state["sessions"]:
            if s.id == session_id:
                s.status = SESSION_REVOKED

    async def fake_flush(_self):
        return None

    mocker.patch.object(UserRepository, "get_by_id", fake_get_by_id)
    mocker.patch.object(UserRepository, "get_by_email", fake_get_by_email)
    mocker.patch.object(RefreshSessionRepository, "get_by_token_hash", fake_get_by_token_hash)
    mocker.patch.object(RefreshSessionRepository, "try_mark_rotated", fake_try_mark_rotated)
    mocker.patch.object(RefreshSessionRepository, "revoke_family", fake_revoke_family)
    mocker.patch.object(RefreshSessionRepository, "revoke", fake_revoke)
    mocker.patch.object(
        RefreshSessionRepository,
        "add",
        lambda _self, row: state["sessions"].append(row),
    )
    mocker.patch.object(RefreshSessionRepository, "flush", fake_flush)

    # Tests that touch authenticated endpoints must not reach a real session.
    async def fake_list_targets(_self, **_kwargs):
        return []

    mocker.patch.object(TargetRepository, "list_for_owner", fake_list_targets)
    return state


async def _async_none() -> None:
    return None


@pytest.fixture
async def client(state) -> AsyncClient:
    application = create_application()

    class _StubSession:
        """Stand-in for AsyncSession; the route may persist security state."""

        async def commit(self) -> None:
            return None

    async def _overridden_session():
        yield _StubSession()

    application.dependency_overrides[get_db_session] = _overridden_session
    transport = ASGITransport(app=application)
    return AsyncClient(transport=transport, base_url="http://test")


def _login_cookies(user: User, raw_refresh: str) -> dict[str, str]:
    access = create_access_token(
        user_id=user.id,
        secret_key=SETTINGS.jwt_secret_key,
        algorithm=SETTINGS.jwt_algorithm,
        expires_in_minutes=SETTINGS.access_token_expire_minutes,
    )
    return {"accessToken": access, "refreshToken": raw_refresh}


# ---------------------------------------------------------------------------
# Login: cookie pair issuance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_sets_both_cookies_with_attributes_and_no_body_tokens(
    client: AsyncClient, state
) -> None:
    """Login issues the full cookie pair; the body carries zero token material."""
    user = _make_user()
    state["users"].append(user)

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "correct-horse-battery"},
    )

    assert response.status_code == 200
    set_cookies = "\n".join(response.headers.get_list("set-cookie")).lower()
    assert "accesstoken=" in set_cookies
    assert "refreshtoken=" in set_cookies
    assert "httponly" in set_cookies
    assert "secure" in set_cookies
    assert "samesite=strict" in set_cookies
    assert f"path={REFRESH_COOKIE_PATH.lower()}" in set_cookies
    # A server-side ACTIVE session was created for the family root.
    sessions: list[RefreshSession] = state["sessions"]  # type: ignore[assignment]
    assert len(sessions) == 1 and sessions[0].status == SESSION_ACTIVE
    assert "token" not in response.text.lower()


# ---------------------------------------------------------------------------
# Refresh: rotation & validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_success_rotates_credentials(client: AsyncClient, state) -> None:
    user = _make_user()
    old_row, old_raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(old_row)

    response = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies=_login_cookies(user, old_raw),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == user.email
    # True rotation: old credential ROTATED, exactly one new ACTIVE descendant.
    assert old_row.status == SESSION_ROTATED
    children = [s for s in state["sessions"] if s.status == SESSION_ACTIVE]
    assert len(children) == 1
    assert children[0].family_id == old_row.family_id
    assert children[0].token_hash != old_row.token_hash
    # Both cookies reissued.
    set_cookies = "\n".join(response.headers.get_list("set-cookie")).lower()
    assert "accesstoken=" in set_cookies and "refreshtoken=" in set_cookies


@pytest.mark.asyncio
async def test_refresh_without_csrf_header_is_forbidden(client: AsyncClient, state) -> None:
    user = _make_user()
    _, raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(_make_session(user.id, raw_token=raw)[0])

    response = await client.post(
        "/api/v1/auth/refresh",
        cookies=_login_cookies(user, raw),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_refresh_unknown_credential_rejected(client: AsyncClient, state) -> None:
    user = _make_user()
    state["users"].append(user)

    response = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies=_login_cookies(user, generate_raw_refresh_token()),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.asyncio
async def test_expired_refresh_rejected(client: AsyncClient, state) -> None:
    user = _make_user()
    row, raw = _make_session(user.id, expires_at=NOW - timedelta(seconds=1))
    state["users"].append(user)
    state["sessions"].append(row)

    response = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies=_login_cookies(user, raw),
    )
    assert response.status_code == 401
    assert row.status == SESSION_REVOKED


@pytest.mark.asyncio
async def test_inactive_user_cannot_refresh(client: AsyncClient, state) -> None:
    user = _make_user(is_active=False)
    row, raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(row)

    response = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies=_login_cookies(user, raw),
    )
    assert response.status_code == 401
    assert row.status == SESSION_REVOKED


@pytest.mark.asyncio
async def test_access_jwt_cannot_be_used_as_refresh_credential(client: AsyncClient, state) -> None:
    """Opaque refresh credentials and JWT access tokens are structurally separate."""
    user = _make_user()
    state["users"].append(user)
    access_only = create_access_token(
        user_id=user.id,
        secret_key=SETTINGS.jwt_secret_key,
        algorithm=SETTINGS.jwt_algorithm,
        expires_in_minutes=15,
    )

    response = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": access_only},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_credential_cannot_authenticate_api(client: AsyncClient, state) -> None:
    """A valid refresh credential must not work as an access credential."""
    user = _make_user()
    _, raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(_make_session(user.id, raw_token=raw)[0])

    response = await client.get("/api/v1/targets", cookies={"accessToken": raw})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Reuse detection & family revocation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reused_rotation_revokes_entire_family(client: AsyncClient, state) -> None:
    user = _make_user()
    family = uuid.uuid4()
    root, root_raw = _make_session(user.id, family_id=family)
    child, child_raw = _make_session(user.id, family_id=family)
    root.status = SESSION_ROTATED  # already rotated once
    state["users"].append(user)
    state["sessions"] += [root, child]

    replayed = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": root_raw},
    )
    assert replayed.status_code == 401
    # Family revocation: the live descendant is dead too.
    assert all(s.status == SESSION_REVOKED for s in state["sessions"])

    even_the_child = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": child_raw},
    )
    assert even_the_child.status_code == 401


@pytest.mark.asyncio
async def test_old_credential_invalid_after_successful_rotation(client: AsyncClient, state) -> None:
    user = _make_user()
    old_row, old_raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(old_row)

    first = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": old_raw},
    )
    assert first.status_code == 200
    new_raw = first.cookies.get("refreshToken")
    assert new_raw

    second = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": old_raw},
    )
    assert second.status_code == 401


@pytest.mark.asyncio
async def test_lost_rotation_race_treated_as_reuse(state) -> None:
    """Atomic ACTIVE->ROTATED means one winner only; loser kills the family."""
    user = _make_user()
    family = uuid.uuid4()
    row, raw = _make_session(user.id, family_id=family)
    state["users"].append(user)
    state["sessions"].append(row)

    service = RefreshService(session=None, refresh_ttl_days=7)  # type: ignore[arg-type]
    outcome_one = await service.refresh(raw)
    assert outcome_one.rotated is not None
    # Second concurrent-style attempt with the same now-ROTATED credential.
    outcome_two = await service.refresh(raw)
    assert outcome_two.rejection == RefreshRejection.REUSED
    assert all(s.status == SESSION_REVOKED for s in state["sessions"])


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_revokes_session_and_clears_cookies(client: AsyncClient, state) -> None:
    user = _make_user()
    row, raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(row)

    response = await client.post(
        "/api/v1/auth/logout",
        headers={"X-Refresh-Request": "1"},
        cookies=_login_cookies(user, raw),
    )

    assert response.status_code == 204
    assert row.status == SESSION_REVOKED
    set_cookies = "\n".join(response.headers.get_list("set-cookie"))
    lowered = set_cookies.lower()
    assert 'accesstoken=""' in lowered or "accesstoken=;" in lowered
    assert 'refreshtoken=""' in lowered or "refreshtoken=;" in lowered
    assert f"Path={REFRESH_COOKIE_PATH}" in set_cookies  # matching delete path


@pytest.mark.asyncio
async def test_logged_out_session_cannot_refresh_again(client: AsyncClient, state) -> None:
    user = _make_user()
    row, raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(row)

    first = await client.post(
        "/api/v1/auth/logout",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": raw},
    )
    assert first.status_code == 204

    again = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": raw},
    )
    assert again.status_code == 401


@pytest.mark.asyncio
async def test_repeat_logout_is_idempotent(client: AsyncClient, state) -> None:
    user = _make_user()
    row, raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(row)

    first = await client.post(
        "/api/v1/auth/logout",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": raw},
    )
    second = await client.post(
        "/api/v1/auth/logout",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": raw},
    )
    third = await client.post(
        "/api/v1/auth/logout",
        headers={"X-Refresh-Request": "1"},
    )  # no cookie at all
    assert first.status_code == second.status_code == third.status_code == 204


@pytest.mark.asyncio
async def test_logout_without_csrf_header_forbidden(client: AsyncClient, state) -> None:
    response = await client.post("/api/v1/auth/logout")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Access-token behavior around the session layer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_access_after_logout_still_valid_until_expiry_but_refresh_dead(
    client: AsyncClient, state
) -> None:
    """Stateless access JWT remains usable until expiry; refresh is revoked.

    This documents the SRS-consistent boundary: logout revokes server-side
    session state; short-lived access JWTs expire on their own clock.
    """
    user = _make_user()
    row, raw = _make_session(user.id)
    state["users"].append(user)
    state["sessions"].append(row)
    cookies = _login_cookies(user, raw)

    await client.post(
        "/api/v1/auth/logout",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": raw},
    )
    # Refresh path dead.
    refresh_attempt = await client.post(
        "/api/v1/auth/refresh",
        headers={"X-Refresh-Request": "1"},
        cookies={"refreshToken": raw},
    )
    assert refresh_attempt.status_code == 401
    # Access path still authenticates within TTL (stateless JWT).
    targets = await client.get("/api/v1/targets", cookies=cookies)
    assert targets.status_code == 200


def test_hash_is_deterministic_and_raw_never_equal_to_hash() -> None:
    raw = generate_raw_refresh_token()
    assert hash_refresh_token(raw) == hash_refresh_token(raw)
    assert len(hash_refresh_token(raw)) == 64
    assert raw not in hash_refresh_token(raw)
