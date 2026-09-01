"""Tests for ``GET /api/v1/auth/me`` (session-restore probe).

The endpoint is a cheap identity probe used by the SPA on page load to
restore the in-memory user from the still-attached HttpOnly access
cookie. It MUST:

* Return 200 with the same ``UserInfo`` the login response uses when
  the request carries a valid access JWT cookie.
* Return 401 UNAUTHENTICATED (the same structured envelope the rest of
  the API uses) when the cookie is missing or invalid.
* Never return token material in the body.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import get_settings
from src.domain.users.password_hasher import hash_password
from src.domain.users.token_service import create_access_token
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import User
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
        email="restore-me@example.com",
        password_hash=hash_password("correct-horse-battery"),
        mfa_enabled=False,
        is_active=is_active,
        created_at=NOW,
        updated_at=NOW,
    )


@pytest.fixture
def state(mocker: Any) -> dict[str, list[User]]:
    state: dict[str, list[User]] = {"users": []}

    async def fake_get_by_id(_self: Any, user_id: uuid.UUID) -> User | None:
        return next((u for u in state["users"] if u.id == user_id), None)

    async def fake_get_by_email(_self: Any, email: str) -> User | None:
        return next((u for u in state["users"] if u.email == email), None)

    async def fake_get_by_token_hash(_self: Any, _token_hash: str) -> None:
        return None

    async def fake_flush(_self: Any) -> None:
        return None

    mocker.patch.object(UserRepository, "get_by_id", fake_get_by_id)
    mocker.patch.object(UserRepository, "get_by_email", fake_get_by_email)
    mocker.patch.object(RefreshSessionRepository, "get_by_token_hash", fake_get_by_token_hash)
    mocker.patch.object(RefreshSessionRepository, "flush", fake_flush)

    # The route never reaches targets, but the dependency override is
    # installed so unrelated session-bearing code paths can't touch a
    # real database.
    async def fake_list_targets(_self: Any, **_kwargs: Any) -> list[Any]:
        return []

    mocker.patch.object(TargetRepository, "list_for_owner", fake_list_targets)
    return state


@pytest.fixture
async def client(state: dict[str, list[User]]) -> AsyncClient:
    application = create_application()

    class _StubSession:
        async def commit(self) -> None:
            return None

    async def _overridden_session() -> Any:
        yield _StubSession()

    application.dependency_overrides[get_db_session] = _overridden_session
    transport = ASGITransport(app=application)
    return AsyncClient(transport=transport, base_url="http://test")


def _access_cookie(user: User) -> dict[str, str]:
    access = create_access_token(
        user_id=user.id,
        secret_key=SETTINGS.jwt_secret_key,
        algorithm=SETTINGS.jwt_algorithm,
        expires_in_minutes=SETTINGS.access_token_expire_minutes,
    )
    return {"accessToken": access}


@pytest.mark.asyncio
async def test_me_returns_user_info_when_authenticated(
    client: AsyncClient, state: dict[str, list[User]]
) -> None:
    """A valid access cookie yields the standard UserInfo shape (200)."""
    user = _make_user()
    state["users"].append(user)

    response = await client.get("/api/v1/auth/me", cookies=_access_cookie(user))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == str(user.id)
    assert body["email"] == user.email
    assert "mfaEnabled" in body
    assert "organizations" in body
    # No token material may appear in the body.
    lowered = response.text.lower()
    assert "token" not in lowered
    assert "accesstoken" not in lowered
    assert "refreshtoken" not in lowered


@pytest.mark.asyncio
async def test_me_returns_401_when_no_cookie(client: AsyncClient) -> None:
    """Missing access cookie must surface the standard 401 envelope."""
    response = await client.get("/api/v1/auth/me")

    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "UNAUTHENTICATED"
    assert "requestId" in body["error"]


@pytest.mark.asyncio
async def test_me_returns_401_when_cookie_invalid(client: AsyncClient) -> None:
    """A garbage access cookie must surface the same 401 envelope."""
    response = await client.get(
        "/api/v1/auth/me",
        cookies={"accessToken": "not-a-jwt"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.asyncio
async def test_me_returns_401_for_inactive_user(
    client: AsyncClient, state: dict[str, list[User]]
) -> None:
    """A token whose user has been deactivated must not be honored."""
    user = _make_user(is_active=False)
    state["users"].append(user)

    response = await client.get("/api/v1/auth/me", cookies=_access_cookie(user))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.asyncio
async def test_me_does_not_issue_cookies(client: AsyncClient, state: dict[str, list[User]]) -> None:
    """/me is a pure read — it must not set or clear any auth cookies."""
    user = _make_user()
    state["users"].append(user)

    response = await client.get("/api/v1/auth/me", cookies=_access_cookie(user))

    assert response.status_code == 200
    set_cookies = response.headers.get_list("set-cookie")
    assert set_cookies == []
