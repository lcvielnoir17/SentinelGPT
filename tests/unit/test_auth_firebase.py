"""Unit tests for the POST /auth/firebase identity bridge (ADR-0010).

Covers the secure-mapping contract: identity comes ONLY from the verified
token, verified-email linkage, no linkage for unverified addresses,
provisioning for unknown identities, inactive-account rejection, and the
503 when the deployment has no Firebase project configured.
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import Settings
from src.domain.users.firebase_token_service import FirebaseIdentity
from src.domain.users.password_hasher import hash_password
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.models import User
from src.infrastructure.database.repositories.user_repository import UserRepository
from src.main import create_application

ROUTE = "/api/v1/auth/firebase"
PROJECT_ID = "demo-sentinelgpt"


def _make_user(
    email: str,
    *,
    password: str | None = "local-password-value",
    firebase_uid: str | None = None,
    is_active: bool = True,
) -> User:
    now = datetime.now(UTC)
    return User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password) if password else None,
        firebase_uid=firebase_uid,
        mfa_enabled=False,
        is_active=is_active,
        created_at=now,
        updated_at=now,
    )


class _StubVerifier:
    """Offline verifier returning a controlled identity or raising."""

    def __init__(self, identity: FirebaseIdentity | None = None) -> None:
        self._identity = identity

    def verify(self, _token: str) -> FirebaseIdentity:
        assert self._identity is not None, "test stub requires a configured identity"
        return self._identity


class _ExplodingVerifier:
    def verify(self, _token: str) -> FirebaseIdentity:
        from src.domain.errors import FirebaseTokenInvalidError

        raise FirebaseTokenInvalidError()


@pytest.fixture
def fake_repo_state(mocker):
    """Repository seam with in-memory lookup by email and firebase uid."""
    state: dict[str, object] = {"users": [], "added": [], "linked": []}

    def _find(predicate) -> User | None:
        for user in state["users"]:  # type: ignore[union-attr]
            if predicate(user):
                return user
        return None

    async def fake_get_by_email(_self: UserRepository, email: str) -> User | None:
        return _find(lambda u: u.email == email)

    async def fake_get_by_firebase_uid(_self: UserRepository, uid: str) -> User | None:
        return _find(lambda u: u.firebase_uid == uid)

    def fake_add(_self: UserRepository, user: User) -> None:
        state["added"].append(user)  # type: ignore[union-attr]
        state["users"].append(user)  # type: ignore[union-attr]

    def fake_link(_self: UserRepository, user: User, uid: str) -> None:
        user.firebase_uid = uid
        state["linked"].append((user, uid))  # type: ignore[union-attr]

    async def fake_flush(_self: UserRepository) -> None:
        return None

    mocker.patch.object(UserRepository, "get_by_email", fake_get_by_email)
    mocker.patch.object(UserRepository, "get_by_firebase_uid", fake_get_by_firebase_uid)
    mocker.patch.object(UserRepository, "add", fake_add)
    mocker.patch.object(UserRepository, "link_firebase_uid", fake_link)
    mocker.patch.object(UserRepository, "flush", fake_flush)
    return state


@pytest.fixture
async def client(fake_repo_state, mocker) -> AsyncClient:
    application = create_application()

    class _StubSession:
        async def commit(self) -> None:
            return None

        def add(self, _obj: object) -> None:
            return None

        async def flush(self) -> None:
            return None

    async def _overridden_session():
        yield _StubSession()

    application.dependency_overrides[get_db_session] = _overridden_session

    def _settings_with_firebase() -> Settings:
        return Settings(environment="test", debug=True, firebase_project_id=PROJECT_ID)

    mocker.patch("src.api.routes.auth_routes.get_settings", side_effect=_settings_with_firebase)

    transport = ASGITransport(app=application)
    return AsyncClient(transport=transport, base_url="http://test")


def _patch_verifier(mocker, verifier: object) -> None:
    mocker.patch("src.api.routes.auth_routes._firebase_verifier", return_value=verifier)


@pytest.mark.asyncio
async def test_exchange_provisions_new_federated_account(
    client: AsyncClient, fake_repo_state, mocker
) -> None:
    _patch_verifier(
        mocker,
        _StubVerifier(
            FirebaseIdentity(uid="uid-1", email="new-user@example.com", email_verified=True)
        ),
    )

    response = await client.post(ROUTE, json={"idToken": "token-value"})

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == "new-user@example.com"
    assert body["expiresIn"] > 0
    assert "access_token" in response.cookies or "accessToken" in response.cookies

    added = fake_repo_state["added"]
    assert len(added) == 1
    created: User = added[0]  # type: ignore[index]
    assert created.firebase_uid == "uid-1"
    assert created.password_hash is None


@pytest.mark.asyncio
async def test_exchange_is_idempotent_for_same_uid(
    client: AsyncClient, fake_repo_state, mocker
) -> None:
    _patch_verifier(
        mocker,
        _StubVerifier(
            FirebaseIdentity(uid="uid-1", email="new-user@example.com", email_verified=True)
        ),
    )
    await client.post(ROUTE, json={"idToken": "token-value"})
    second = await client.post(ROUTE, json={"idToken": "token-value"})

    assert second.status_code == 200
    assert len(fake_repo_state["added"]) == 1  # no duplicate account


@pytest.mark.asyncio
async def test_exchange_links_existing_local_account_on_verified_email(
    client: AsyncClient, fake_repo_state, mocker
) -> None:
    fake_repo_state["users"].append(_make_user("local@example.com"))  # type: ignore[attr-defined]
    _patch_verifier(
        mocker,
        _StubVerifier(
            FirebaseIdentity(uid="uid-2", email="local@example.com", email_verified=True)
        ),
    )

    response = await client.post(ROUTE, json={"idToken": "token"})

    assert response.status_code == 200
    assert len(fake_repo_state["added"]) == 0
    linked = fake_repo_state["linked"]
    assert len(linked) == 1
    assert linked[0][1] == "uid-2"


@pytest.mark.asyncio
async def test_exchange_does_not_link_unverified_email(
    client: AsyncClient, fake_repo_state, mocker
) -> None:
    fake_repo_state["users"].append(_make_user("victim@example.com"))  # type: ignore[attr-defined]
    _patch_verifier(
        mocker,
        _StubVerifier(
            FirebaseIdentity(uid="attacker-uid", email="victim@example.com", email_verified=False)
        ),
    )

    response = await client.post(ROUTE, json={"idToken": "token"})

    # The unverified address is untrusted: the exchange succeeds with a
    # synthetic identity address and the victim's account is never touched.
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "attacker-uid@users.firebase.demo-sentinelgpt"
    assert len(fake_repo_state["linked"]) == 0
    assert fake_repo_state["users"][0].firebase_uid is None  # type: ignore[index]
    assert len(fake_repo_state["added"]) == 1


@pytest.mark.asyncio
async def test_exchange_without_email_uses_synthetic_address(
    client: AsyncClient, fake_repo_state, mocker
) -> None:
    _patch_verifier(
        mocker, _StubVerifier(FirebaseIdentity(uid="uid-3", email=None, email_verified=False))
    )

    response = await client.post(ROUTE, json={"idToken": "token"})

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == "uid-3@users.firebase.demo-sentinelgpt"


@pytest.mark.asyncio
async def test_exchange_rejects_invalid_token(client: AsyncClient, fake_repo_state, mocker) -> None:
    _patch_verifier(mocker, _ExplodingVerifier())

    response = await client.post(ROUTE, json={"idToken": "forged"})

    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "UNAUTHENTICATED"
    assert len(fake_repo_state["added"]) == 0


@pytest.mark.asyncio
async def test_exchange_rejects_deactivated_account(
    client: AsyncClient, fake_repo_state, mocker
) -> None:
    fake_repo_state["users"].append(  # type: ignore[attr-defined]
        _make_user("banned@example.com", firebase_uid="uid-banned", is_active=False)
    )
    _patch_verifier(
        mocker,
        _StubVerifier(
            FirebaseIdentity(uid="uid-banned", email="banned@example.com", email_verified=True)
        ),
    )

    response = await client.post(ROUTE, json={"idToken": "token"})

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_exchange_requires_id_token_field(client: AsyncClient) -> None:
    # The global handler maps RequestValidationError to a 400 envelope.
    response = await client.post(ROUTE, json={})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_exchange_returns_503_when_not_configured(mocker) -> None:
    application = create_application()

    class _StubSession:
        async def commit(self) -> None:
            return None

        def add(self, _obj: object) -> None:
            return None

        async def flush(self) -> None:
            return None

    async def _overridden_session():
        yield _StubSession()

    application.dependency_overrides[get_db_session] = _overridden_session

    def _settings_without_firebase() -> Settings:
        return Settings(environment="test", debug=True, firebase_project_id="")

    mocker.patch("src.api.routes.auth_routes.get_settings", side_effect=_settings_without_firebase)

    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.post(ROUTE, json={"idToken": "token"})

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "FEATURE_DISABLED"
