"""Unit tests for Phase 0 auth endpoints and settings security validation."""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from src.config.settings import (
    DEVELOPMENT_INSECURE_JWT_SECRET,
    Settings,
)
from src.domain.users.password_hasher import hash_password
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import User
from src.infrastructure.database.repositories.user_repository import UserRepository
from src.main import create_application


def _make_user(email: str, password: str) -> User:
    """Build a fully-populated transient user row (no DB required).

    Column-level defaults apply at flush time, so every attribute the service
    logic reads must be set explicitly here.
    """
    now = datetime.now(UTC)
    return User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        mfa_enabled=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def fake_repo_state(mocker):
    """Patch repository reads/writes so routes run without a live database."""
    state: dict[str, object] = {"existing_user": None, "added": []}

    async def fake_get_by_email(_self: UserRepository, email: str) -> User | None:
        found = state["existing_user"]
        if isinstance(found, User) and found.email == email:
            return found
        return None

    def fake_add(_self: UserRepository, user: User) -> None:
        state["added"].append(user)

    async def fake_flush(_self: UserRepository) -> None:
        return None

    mocker.patch.object(UserRepository, "get_by_email", fake_get_by_email)
    mocker.patch.object(UserRepository, "add", fake_add)
    mocker.patch.object(UserRepository, "flush", fake_flush)
    return state


@pytest.fixture
async def client(fake_repo_state) -> AsyncClient:
    application = create_application()

    # Unit tests must never open a real database connection. Login now also
    # stages a refresh-session row, so the stub needs the write surface.
    class _StubSession:
        async def commit(self) -> None:
            return None

        def add(self, _obj: object) -> None:
            return None

        async def flush(self) -> None:
            return None

        async def rollback(self) -> None:
            return None

    async def _overridden_session():
        yield _StubSession()

    application.dependency_overrides[get_db_session] = _overridden_session

    transport = ASGITransport(app=application)
    return AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# POST /api/v1/auth/register
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_creates_account(client: AsyncClient, fake_repo_state) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "analyst@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "analyst@example.com"
    assert uuid.UUID(body["id"])
    assert "createdAt" in body
    added = fake_repo_state["added"]
    assert len(added) == 1
    assert isinstance(added[0], User)


@pytest.mark.asyncio
async def test_register_duplicate_email_conflict_envelope(
    client: AsyncClient, fake_repo_state
) -> None:
    fake_repo_state["existing_user"] = _make_user("taken@example.com", "whatever-long-password")

    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "taken@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "CONFLICT"
    assert error["requestId"]


@pytest.mark.asyncio
async def test_register_concurrent_duplicate_returns_409_not_500(
    client: AsyncClient, fake_repo_state, mocker
) -> None:
    """A racer committing between check and flush maps to 409, not 500."""
    from sqlalchemy.exc import IntegrityError

    from src.infrastructure.database.repositories.user_repository import UserRepository

    racer = _make_user("racer@example.com", "whatever-long-password")

    async def racy_flush(_self: UserRepository) -> None:
        # Simulate the racer's commit landing first.
        fake_repo_state["existing_user"] = racer
        raise IntegrityError("INSERT INTO user", {}, Exception("unique_violation"))

    mocker.patch.object(UserRepository, "flush", racy_flush)

    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "racer@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_register_password_too_short_validation_envelope(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "new@example.com", "password": "short"},
    )

    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    # No stack traces or internals leak through the envelope.
    assert "detail" not in response.json()


@pytest.mark.asyncio
async def test_register_invalid_email_validation_envelope(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "password": "correct-horse-battery"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


# ---------------------------------------------------------------------------
# POST /api/v1/auth/login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_success_returns_user_and_expires_in(
    client: AsyncClient, fake_repo_state
) -> None:
    fake_repo_state["existing_user"] = _make_user("analyst@example.com", "correct-horse-battery")

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == "analyst@example.com"
    assert body["expiresIn"] == 900
    # v3 invariant: no token material may ever appear in the JSON body.
    serialized = str(body).lower()
    assert "token" not in serialized


@pytest.mark.asyncio
async def test_login_unknown_email_is_unauthenticated(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@example.com", "password": "correct-horse-battery"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


@pytest.mark.asyncio
async def test_login_wrong_password_identical_to_unknown_email(
    client: AsyncClient, fake_repo_state
) -> None:
    """No user-enumeration oracle: failures are identical (SRS Ch5 §2)."""
    fake_repo_state["existing_user"] = _make_user("analyst@example.com", "correct-horse-battery")

    unknown = await client.post(
        "/api/v1/auth/login",
        json={"email": "ghost@example.com", "password": "correct-horse-battery"},
    )
    wrong_pw = await client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "definitely-wrong-password"},
    )

    assert unknown.status_code == wrong_pw.status_code == 401
    # requestId legitimately differs per request; code+message must not.
    unknown_error = unknown.json()["error"]
    wrong_pw_error = wrong_pw.json()["error"]
    assert unknown_error["code"] == wrong_pw_error["code"] == "UNAUTHENTICATED"
    assert unknown_error["message"] == wrong_pw_error["message"]


# ---------------------------------------------------------------------------
# H-01: environment-aware JWT secret safety (settings fail-fast validator)
# ---------------------------------------------------------------------------


def test_production_rejects_default_development_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production")


def test_staging_rejects_explicit_development_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="staging", jwt_secret_key=DEVELOPMENT_INSECURE_JWT_SECRET)


def test_production_rejects_short_custom_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production", jwt_secret_key="too-short")


def test_production_accepts_strong_unique_secret() -> None:
    settings = Settings(
        environment="production",
        jwt_secret_key="a-strong-production-secret-with-plenty-of-entropy-1234567890",
        debug=False,
    )
    assert settings.environment == "production"


def test_production_rejects_debug_mode() -> None:
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            jwt_secret_key="a-strong-production-secret-with-plenty-of-entropy-1234567890",
            debug=True,
        )


def test_local_keeps_developer_ergonomics_with_dev_secret() -> None:
    settings = Settings(environment="local")
    assert settings.jwt_secret_key == DEVELOPMENT_INSECURE_JWT_SECRET


def test_test_environment_allows_dev_secret() -> None:
    settings = Settings(environment="test", jwt_secret_key=DEVELOPMENT_INSECURE_JWT_SECRET)
    assert settings.environment == "test"
