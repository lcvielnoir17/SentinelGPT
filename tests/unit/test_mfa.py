"""MFA authentication hardening (M11): TOTP, challenge, recovery, disable.

Proves the additive second factor: verification-gated enrollment,
no session before the second factor, single-use hashed recovery
codes, re-authenticated disable/regeneration, brute-force throttling,
and full audit coverage — with zero regression in the existing
password/session/cookie architecture. Secrets and codes never reach
logs, audits, or post-enrollment responses.
"""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from src.domain.errors import NotAuthenticatedError
from src.domain.mfa.errors import InvalidMfaError, MfaConflictError, MfaNotConfiguredError
from src.domain.mfa.service import MfaService
from src.domain.mfa.totp import code_at, generate_secret, verify_code

USER_ID = uuid.uuid4()
EMAIL = "mfa@example.com"

# RFC 6238 Appendix B SHA-1 vectors (secret "12345678901234567890").
RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_VECTORS = [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
]


def _user_row(**overrides: object) -> SimpleNamespace:
    now = datetime.now(UTC)
    params: dict[str, object] = {
        "id": USER_ID,
        "email": EMAIL,
        "password_hash": "argon2id$fake",
        "mfa_enabled": False,
        "mfa_secret_encrypted": None,
        "is_active": True,
        "firebase_uid": None,
        "created_at": now,
        "updated_at": now,
    }
    params.update(overrides)
    return SimpleNamespace(**params)


class FakeSession:
    """User row + recovery rows; records commits; never touches a database."""

    def __init__(self, user: SimpleNamespace) -> None:
        self.user = user
        self.codes: list[SimpleNamespace] = []
        self.totp_steps: set[int] = set()
        self.commits = 0

    async def get(self, model: object, key: object) -> object | None:
        if getattr(model, "__name__", "") == "User":
            return self.user if key == self.user.id else None
        return None

    def add(self, row: object) -> None:
        from sqlalchemy.exc import IntegrityError

        if getattr(row, "__tablename__", "") == "mfa_totp_use":
            if row.time_step in self.totp_steps:
                raise IntegrityError("INSERT", {}, Exception("duplicate (user, step)"))
            self.totp_steps.add(row.time_step)
            return
        self.codes.append(row)

    async def flush(self) -> None:
        return None

    def begin_nested(self):  # type: ignore[no-untyped-def]
        from contextlib import asynccontextmanager

        session = self

        @asynccontextmanager
        async def _nested():  # type: ignore[no-untyped-def]
            codes, steps = list(session.codes), set(session.totp_steps)
            try:
                yield session
            except Exception:
                session.codes = codes
                session.totp_steps = steps
                raise

        return _nested()

    async def commit(self) -> None:
        self.commits += 1

    async def execute(self, stmt: object) -> object:
        from src.infrastructure.database.models import MfaRecoveryCode

        text = str(stmt)
        session = self

        class _Scalars:
            def all(self) -> list:
                if "mfa_recovery_code" in text:
                    return [c for c in session.codes if getattr(c, "used_at", None) is None]
                return []

            def first(self) -> None:
                return None

        class _Result:
            def scalars(self) -> _Scalars:
                return _Scalars()

            def scalar_one_or_none(self) -> None:
                return None

        if "DELETE" in text:
            session.codes = [c for c in session.codes if c.user_id != USER_ID]
        _ = MfaRecoveryCode
        return _Result()


@pytest.fixture
def fernet_key(monkeypatch):  # type: ignore[no-untyped-def]
    """Route MFA crypto through a test-only Fernet key."""
    from cryptography.fernet import Fernet

    import src.infrastructure.secrets.mfa_box as mfa_box

    key = Fernet(Fernet.generate_key())
    monkeypatch.setattr(mfa_box, "_fernet", lambda: key)
    return key


@pytest.fixture
def world(fernet_key, monkeypatch):  # type: ignore[no-untyped-def]
    """Service with user row, captured audits, allow-all limiter."""
    from src.domain.audit.audit_service import AuditService
    from src.infrastructure.database.repositories.user_repository import UserRepository

    session = FakeSession(_user_row())
    audits: list[dict] = []

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(dict(kwargs))

    async def fake_get_by_id(_self: object, user_id: uuid.UUID) -> object | None:
        return session.user if user_id == session.user.id else None

    async def allow(_scope: str) -> bool:
        return True

    monkeypatch.setattr(AuditService, "record", fake_record)
    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_by_id)
    service = MfaService(session, verify_limiter=SimpleNamespace(try_admit=allow))
    return SimpleNamespace(session=session, audits=audits, service=service)


def _codes(world) -> list[str]:  # type: ignore[no-untyped-def]
    return [str(a["action_code"]) for a in world.audits]


async def _enabled_world(world, secret: str | None = None):  # type: ignore[no-untyped-def]
    """Enroll + verify so the account ends MFA-enabled; returns the secret."""
    from src.infrastructure.secrets.mfa_box import encrypt_totp_secret

    raw = secret or generate_secret()
    world.session.user.mfa_secret_encrypted = encrypt_totp_secret(raw)
    from src.domain.mfa.totp import current_code

    await world.service.verify_enrollment(
        SimpleNamespace(id=USER_ID, email=EMAIL), current_code(raw)
    )
    world.audits.clear()
    return raw


# --------------------------------------------------------------------------- #
# TOTP construction (RFC vectors, window, malformed)                          #
# --------------------------------------------------------------------------- #


def test_rfc6238_vectors() -> None:
    for timestamp, expected in RFC_VECTORS:
        moment = datetime.fromtimestamp(timestamp, tz=UTC)
        assert code_at(RFC_SECRET_B32, moment) == expected


def test_totp_window_and_malformed() -> None:
    secret = generate_secret()
    now = datetime.now(UTC)
    assert verify_code(secret, code_at(secret, now), now)
    assert verify_code(secret, code_at(secret, now - timedelta(seconds=30)), now)
    assert verify_code(secret, code_at(secret, now + timedelta(seconds=30)), now)
    assert not verify_code(secret, code_at(secret, now - timedelta(seconds=90)), now)
    for bad in ("", "12345", "1234567", "abcdef", " 123456 ", 123456, None):
        assert not verify_code(secret, bad)  # type: ignore[arg-type]
    assert not verify_code("!!!not-base32!!!", "123456")


def test_secret_format() -> None:
    secret = generate_secret()
    assert "=" not in secret
    base64.b32decode(secret + "=" * (-len(secret) % 8))


# --------------------------------------------------------------------------- #
# Enrollment                                                                  #
# --------------------------------------------------------------------------- #


async def test_enrollment_start(world) -> None:  # type: ignore[no-untyped-def]
    started = await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    assert started.secret and started.provisioning_uri.startswith("otpauth://totp/")
    assert world.session.user.mfa_enabled is False  # pending, never active yet
    assert world.session.user.mfa_secret_encrypted not in (None, started.secret)
    assert _codes(world) == ["MFA_ENROLL_STARTED"]
    assert started.secret not in str(world.audits)


async def test_enrollment_replaces_pending_secret(world) -> None:  # type: ignore[no-untyped-def]
    first = await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    second = await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    assert second.secret != first.secret
    assert _codes(world) == ["MFA_ENROLL_STARTED", "MFA_SECRET_REPLACED"]


async def test_enrollment_when_enabled_is_409(world) -> None:  # type: ignore[no-untyped-def]
    await _enabled_world(world)
    with pytest.raises(MfaConflictError) as exc_info:
        await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    assert exc_info.value.status_code == 409


async def test_verify_enrollment_success(world) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code

    started = await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    issued = await world.service.verify_enrollment(
        SimpleNamespace(id=USER_ID, email=EMAIL), current_code(started.secret)
    )
    assert world.session.user.mfa_enabled is True
    assert len(issued.codes) == 10 and len(set(issued.codes)) == 10
    assert _codes(world)[-2:] == ["MFA_ENABLED", "MFA_RECOVERY_GENERATED"]
    assert started.secret not in str(world.audits)
    assert all(c not in str(world.audits) for c in issued.codes)


async def test_verify_enrollment_wrong_code_is_401(world) -> None:  # type: ignore[no-untyped-def]
    await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL), "000000")
    assert world.session.user.mfa_enabled is False


async def test_verify_enrollment_without_pending_is_400(world) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(InvalidMfaError):
        await world.service.verify_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL), "123456")


async def test_status(world) -> None:  # type: ignore[no-untyped-def]
    assert await world.service.status(SimpleNamespace(id=USER_ID)) == {"enabled": False}
    await _enabled_world(world)
    assert await world.service.status(SimpleNamespace(id=USER_ID)) == {"enabled": True}


async def test_enrollment_without_key_is_503(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import src.infrastructure.secrets.mfa_box as mfa_box

    def broken() -> object:
        raise mfa_box.MfaSecretsNotConfiguredError("no key")

    monkeypatch.setattr(mfa_box, "_fernet", broken)
    with pytest.raises(MfaNotConfiguredError) as exc_info:
        await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    assert exc_info.value.status_code == 503


# --------------------------------------------------------------------------- #
# Challenge verification                                                      #
# --------------------------------------------------------------------------- #


async def test_challenge_totp_success(world) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code

    raw = await _enabled_world(world)
    account = await world.service.verify_challenge(USER_ID, current_code(raw))
    assert account.id == USER_ID and account.mfa_enabled is True
    assert _codes(world) == ["MFA_CHALLENGE_SUCCESS"]


async def test_challenge_totp_replay_rejected(world) -> None:  # type: ignore[no-untyped-def]
    """The same TOTP code verifies once; immediate replay fails closed."""
    from src.domain.mfa.totp import current_code

    raw = await _enabled_world(world)
    code = current_code(raw)
    await world.service.verify_challenge(USER_ID, code)
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_challenge(USER_ID, code)
    assert _codes(world) == ["MFA_CHALLENGE_SUCCESS", "MFA_CHALLENGE_FAILURE"]


async def test_matching_step_names_counter() -> None:
    from datetime import timedelta

    from src.domain.mfa.totp import code_at, generate_secret, matching_step

    secret = generate_secret()
    now = datetime.now(UTC)
    base = int(now.timestamp()) // 30
    assert matching_step(secret, code_at(secret, now), now) == base
    assert matching_step(secret, code_at(secret, now - timedelta(seconds=30)), now) == base - 1
    assert matching_step(secret, "000000", now) is None


async def test_challenge_wrong_code_is_401(world) -> None:  # type: ignore[no-untyped-def]
    await _enabled_world(world)
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_challenge(USER_ID, "000000")
    assert _codes(world) == ["MFA_CHALLENGE_FAILURE"]


async def test_challenge_malformed_is_400(world) -> None:  # type: ignore[no-untyped-def]
    await _enabled_world(world)
    for bad in ("", "x" * 33, 123):
        with pytest.raises(InvalidMfaError):
            await world.service.verify_challenge(USER_ID, bad)  # type: ignore[arg-type]


async def test_challenge_after_disable_is_401(world) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code

    raw = await _enabled_world(world)
    world.session.user.mfa_enabled = False
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_challenge(USER_ID, current_code(raw))


async def test_challenge_rate_limited(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.errors import MfaRateLimitedError
    from src.domain.mfa.service import MfaService

    async def deny(_scope: str) -> bool:
        return False

    limited = MfaService(world.session, verify_limiter=SimpleNamespace(try_admit=deny))
    with pytest.raises(MfaRateLimitedError) as exc_info:
        await limited.verify_challenge(USER_ID, "123456")
    assert exc_info.value.status_code == 429
    assert exc_info.value.retry_after == 60


# --------------------------------------------------------------------------- #
# Recovery codes                                                              #
# --------------------------------------------------------------------------- #


async def test_recovery_code_single_use(world) -> None:  # type: ignore[no-untyped-def]
    from src.infrastructure.secrets.mfa_box import generate_recovery_codes, hash_recovery_code

    await _enabled_world(world)
    codes = generate_recovery_codes(2)
    for code in codes:
        world.session.codes.append(
            SimpleNamespace(user_id=USER_ID, code_hash=hash_recovery_code(code), used_at=None)
        )
    account = await world.service.verify_challenge(USER_ID, codes[0])
    assert account.mfa_enabled is True
    assert _codes(world)[-2:] == ["MFA_CHALLENGE_SUCCESS", "MFA_RECOVERY_USED"]
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_challenge(USER_ID, codes[0])  # reuse rejected


async def test_recovery_codes_hashed_at_rest(world) -> None:  # type: ignore[no-untyped-def]
    await _enabled_world(world)
    issued = await world.service.regenerate_recovery_codes(
        SimpleNamespace(id=USER_ID, email=EMAIL), totp_code=_current(world)
    )
    assert len(world.session.codes) == 10
    stored_hashes = {c.code_hash for c in world.session.codes}
    assert all(len(h) == 64 for h in stored_hashes)
    # No plaintext survives anywhere on the rows.
    assert not (set(issued.codes) & stored_hashes)
    assert all(c not in str(world.session.codes) for c in issued.codes)


def _current(world) -> str:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code
    from src.infrastructure.secrets.mfa_box import decrypt_totp_secret

    return current_code(decrypt_totp_secret(world.session.user.mfa_secret_encrypted))


async def test_concurrent_recovery_use_single_winner(world) -> None:  # type: ignore[no-untyped-def]
    """Racing consumers of one code: exactly one success (lock ordering)."""
    import asyncio

    from src.infrastructure.secrets.mfa_box import hash_recovery_code

    await _enabled_world(world)
    world.session.codes.append(
        SimpleNamespace(user_id=USER_ID, code_hash=hash_recovery_code("abc123"), used_at=None)
    )
    results = await asyncio.gather(
        *[world.service.verify_challenge(USER_ID, "abc123") for _ in range(5)],
        return_exceptions=True,
    )
    assert sum(not isinstance(r, Exception) for r in results) == 1
    assert sum(isinstance(r, NotAuthenticatedError) for r in results) == 4


# --------------------------------------------------------------------------- #
# Disable / regenerate                                                        #
# --------------------------------------------------------------------------- #


async def test_disable_with_password_and_totp(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code
    from src.domain.users.user_service import UserService

    raw = await _enabled_world(world)

    async def fake_authenticate(_self: object, email: str, password: str) -> object:
        assert password == "correct-horse"
        return SimpleNamespace(id=USER_ID, email=email)

    monkeypatch.setattr(UserService, "authenticate", fake_authenticate)
    await world.service.disable(
        SimpleNamespace(id=USER_ID, email=EMAIL),
        password="correct-horse",
        code=current_code(raw),
    )
    assert world.session.user.mfa_enabled is False
    assert world.session.user.mfa_secret_encrypted is None
    assert world.session.codes == []
    assert _codes(world)[-1] == "MFA_DISABLED"

    async def fake_deny(_self: object, email: str, password: str) -> object:
        from src.domain.errors import InvalidCredentialsError

        raise InvalidCredentialsError()

    monkeypatch.setattr(UserService, "authenticate", fake_deny)
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_challenge(USER_ID, current_code(raw))


async def test_disable_wrong_password_is_401(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.domain.errors import InvalidCredentialsError
    from src.domain.users.user_service import UserService

    await _enabled_world(world)

    async def fake_deny(_self: object, email: str, password: str) -> object:
        raise InvalidCredentialsError()

    monkeypatch.setattr(UserService, "authenticate", fake_deny)
    with pytest.raises(InvalidCredentialsError):
        await world.service.disable(
            SimpleNamespace(id=USER_ID, email=EMAIL), password="wrong", code="123456"
        )
    assert world.session.user.mfa_enabled is True


async def test_disable_with_recovery_code(world, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Lost authenticator: password + unused recovery code still disables."""
    from src.domain.users.user_service import UserService
    from src.infrastructure.secrets.mfa_box import generate_recovery_codes, hash_recovery_code

    await _enabled_world(world)
    (spare,) = generate_recovery_codes(1)
    world.session.codes.append(
        SimpleNamespace(user_id=USER_ID, code_hash=hash_recovery_code(spare), used_at=None)
    )

    async def fake_authenticate(_self: object, email: str, password: str) -> object:
        return SimpleNamespace(id=USER_ID, email=email)

    monkeypatch.setattr(UserService, "authenticate", fake_authenticate)
    await world.service.disable(SimpleNamespace(id=USER_ID, email=EMAIL), password="x", code=spare)
    assert world.session.user.mfa_enabled is False


async def test_regenerate_replaces_codes(world) -> None:  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime, timedelta

    from src.domain.mfa.totp import code_at

    raw = await _enabled_world(world)
    first = await world.service.regenerate_recovery_codes(
        SimpleNamespace(id=USER_ID, email=EMAIL),
        totp_code=code_at(raw, datetime.now(UTC) - timedelta(seconds=30)),
    )
    assert len(first.codes) == 10
    second = await world.service.regenerate_recovery_codes(
        SimpleNamespace(id=USER_ID, email=EMAIL), totp_code=_current(world)
    )
    assert set(second.codes).isdisjoint(first.codes)
    assert _codes(world)[-2:] == ["MFA_RECOVERY_REGENERATED", "MFA_RECOVERY_REGENERATED"]
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_challenge(USER_ID, first.codes[0])  # old set dead


async def test_regenerate_same_code_rejected_as_replay(world) -> None:  # type: ignore[no-untyped-def]
    """Single-use holds for code-protected management operations too."""
    await _enabled_world(world)
    await world.service.regenerate_recovery_codes(
        SimpleNamespace(id=USER_ID, email=EMAIL), totp_code=_current(world)
    )
    with pytest.raises(NotAuthenticatedError):
        await world.service.regenerate_recovery_codes(
            SimpleNamespace(id=USER_ID, email=EMAIL), totp_code=_current(world)
        )


async def test_regenerate_wrong_totp_is_401(world) -> None:  # type: ignore[no-untyped-def]
    await _enabled_world(world)
    with pytest.raises(NotAuthenticatedError):
        await world.service.regenerate_recovery_codes(
            SimpleNamespace(id=USER_ID, email=EMAIL), totp_code="000000"
        )


async def test_cross_user_isolation(world) -> None:  # type: ignore[no-untyped-def]
    """Unknown users answer 401 (same convention as row-level lookups)."""
    other = SimpleNamespace(id=uuid.uuid4(), email="other@x.test")
    await world.service.begin_enrollment(SimpleNamespace(id=USER_ID, email=EMAIL))
    with pytest.raises(NotAuthenticatedError):
        await world.service.status(other)
    with pytest.raises(NotAuthenticatedError):
        await world.service.verify_enrollment(other, "123456")


# --------------------------------------------------------------------------- #
# HTTP envelope                                                               #
# --------------------------------------------------------------------------- #


class RouteSession(FakeSession):
    """Session double for route tests (adds refresh-row staging)."""

    def __init__(self, user: SimpleNamespace) -> None:
        super().__init__(user)
        self.staged: list[object] = []

    def add(self, row: object) -> None:
        if getattr(row, "__tablename__", "") == "mfa_recovery_code":
            self.codes.append(row)
        else:
            self.staged.append(row)

    async def rollback(self) -> None:
        return None


@pytest.fixture
def http(monkeypatch):  # type: ignore[no-untyped-def]
    """Full app with stateful user row, test Fernet key, captured audits."""
    from cryptography.fernet import Fernet
    from httpx import ASGITransport, AsyncClient

    from src.api.routes import auth_routes
    from src.config.settings import get_settings
    from src.domain.audit.audit_service import AuditService
    from src.domain.users.password_hasher import hash_password
    from src.infrastructure.database.connection import get_db_session
    from src.infrastructure.database.models import User
    from src.infrastructure.database.repositories.user_repository import UserRepository
    from src.main import create_application

    now = datetime.now(UTC)
    user = User(
        id=USER_ID,
        email=EMAIL,
        password_hash=hash_password("correct-horse-battery-1"),
        mfa_enabled=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    session = RouteSession(user)  # type: ignore[arg-type]
    audits: list[dict] = []

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(dict(kwargs))

    async def fake_get_by_email(_self: object, email: str) -> object | None:
        return user if email == EMAIL else None

    async def fake_get_by_id(_self: object, user_id: uuid.UUID) -> object | None:
        return user if user_id == USER_ID else None

    async def allow(_scope: str) -> bool:
        return True

    settings = get_settings()
    monkeypatch.setattr(settings, "mfa_secret_key", Fernet.generate_key().decode(), raising=False)
    monkeypatch.setattr(AuditService, "record", fake_record)
    monkeypatch.setattr(UserRepository, "get_by_email", fake_get_by_email)
    monkeypatch.setattr(UserRepository, "get_by_id", fake_get_by_id)
    monkeypatch.setattr(
        auth_routes, "_mfa_verify_limiter", lambda: SimpleNamespace(try_admit=allow)
    )

    application = create_application()

    async def _overridden_session():  # type: ignore[no-untyped-def]
        yield session

    application.dependency_overrides[get_db_session] = _overridden_session
    transport = ASGITransport(app=application)
    return SimpleNamespace(
        client=AsyncClient(transport=transport, base_url="http://test"),
        user=user,
        session=session,
        audits=audits,
    )


def _codes_http(http) -> list[str]:  # type: ignore[no-untyped-def]
    return [str(a["action_code"]) for a in http.audits]


async def _enable_via_routes(http) -> list[str]:  # type: ignore[no-untyped-def]
    """Login, enroll + verify through HTTP; returns the recovery codes."""
    from src.domain.mfa.totp import current_code

    logged = await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    assert logged.status_code == 200, logged.text
    enrolled = await http.client.post("/api/v1/auth/mfa/enroll")
    assert enrolled.status_code == 201, enrolled.text
    secret = enrolled.json()["secret"]
    assert enrolled.json()["provisioningUri"].startswith("otpauth://totp/")
    verified = await http.client.post(
        "/api/v1/auth/mfa/verify-enrollment", json={"code": current_code(secret)}
    )
    assert verified.status_code == 200, verified.text
    codes = verified.json()["recoveryCodes"]
    assert len(codes) == 10
    # Provisioning secret appears exactly once, never again.
    assert secret not in (await http.client.get("/api/v1/auth/mfa/status")).text
    me = await http.client.get("/api/v1/auth/me")
    assert me.json()["mfaEnabled"] is True
    return codes


async def test_login_without_mfa_issues_session(http) -> None:  # type: ignore[no-untyped-def]
    response = await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["user"]["mfaEnabled"] is False
    set_cookies = response.headers.get_list("set-cookie")
    assert any("accessToken=" in c for c in set_cookies)
    assert not any("mfaChallenge=" in c for c in set_cookies)


async def test_login_wrong_password_is_401(http) -> None:  # type: ignore[no-untyped-def]
    response = await http.client.post(
        "/api/v1/auth/login", json={"email": EMAIL, "password": "wrong"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


async def test_login_with_mfa_issues_challenge_only(http) -> None:  # type: ignore[no-untyped-def]
    await _enable_via_routes(http)
    http.client.cookies.clear()
    response = await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    assert response.status_code == 202, response.text
    assert response.json() == {"mfaRequired": True, "expiresIn": 300}
    set_cookies = response.headers.get_list("set-cookie")
    challenge = next(c for c in set_cookies if "mfaChallenge=" in c)
    lowered = challenge.lower()
    assert "httponly" in lowered and "samesite=strict" in lowered
    assert "Path=/api/v1/auth" in challenge
    assert not any(c.startswith("accessToken=") for c in set_cookies)


async def test_challenge_cookie_is_not_a_session(http) -> None:  # type: ignore[no-untyped-def]
    await _enable_via_routes(http)
    http.client.cookies.clear()
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    me = await http.client.get("/api/v1/auth/me")
    assert me.status_code == 401  # challenge alone authenticates nothing


async def test_verify_challenge_issues_session(http) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code
    from src.infrastructure.secrets.mfa_box import decrypt_totp_secret

    await _enable_via_routes(http)
    http.client.cookies.clear()
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    secret = decrypt_totp_secret(http.user.mfa_secret_encrypted)
    verified = await http.client.post(
        "/api/v1/auth/mfa/verify", json={"code": current_code(secret)}
    )
    assert verified.status_code == 200, verified.text
    set_cookies = verified.headers.get_list("set-cookie")
    assert any(c.startswith("accessToken=") for c in set_cookies)
    # Challenge cookie is cleared on success.
    assert any("mfaChallenge=" in c and "Max-Age=0" in c for c in set_cookies)
    me = await http.client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["mfaEnabled"] is True
    assert "MFA_CHALLENGE_SUCCESS" in _codes_http(http)


async def test_verify_challenge_wrong_code_is_401(http) -> None:  # type: ignore[no-untyped-def]
    await _enable_via_routes(http)
    http.client.cookies.clear()
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    denied = await http.client.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
    assert denied.status_code == 401
    assert "MFA_CHALLENGE_FAILURE" in _codes_http(http)


async def test_verify_challenge_malformed_is_400(http) -> None:  # type: ignore[no-untyped-def]
    await _enable_via_routes(http)
    http.client.cookies.clear()
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    for bad in ("", "x" * 33):
        response = await http.client.post("/api/v1/auth/mfa/verify", json={"code": bad})
        assert response.status_code == 400, bad


async def test_verify_without_challenge_is_401(http) -> None:  # type: ignore[no-untyped-def]
    await _enable_via_routes(http)
    http.client.cookies.clear()
    response = await http.client.post("/api/v1/auth/mfa/verify", json={"code": "123456"})
    assert response.status_code == 401


async def test_verify_tampered_challenge_is_401(http) -> None:  # type: ignore[no-untyped-def]
    await _enable_via_routes(http)
    http.client.cookies.clear()
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    http.client.cookies.set("mfaChallenge", "tampered.token.value", domain="test", path="/")
    response = await http.client.post("/api/v1/auth/mfa/verify", json={"code": "123456"})
    assert response.status_code == 401


async def test_verify_with_recovery_code_http(http) -> None:  # type: ignore[no-untyped-def]
    codes = await _enable_via_routes(http)
    http.client.cookies.clear()
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    first = await http.client.post("/api/v1/auth/mfa/verify", json={"code": codes[0]})
    assert first.status_code == 200, first.text
    assert "MFA_RECOVERY_USED" in _codes_http(http)
    # Single use: a fresh challenge plus the same code fails.
    http.client.cookies.clear()
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    reuse = await http.client.post("/api/v1/auth/mfa/verify", json={"code": codes[0]})
    assert reuse.status_code == 401


async def test_enroll_verify_disable_roundtrip(http) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code
    from src.infrastructure.secrets.mfa_box import decrypt_totp_secret

    codes = await _enable_via_routes(http)
    assert codes
    secret = decrypt_totp_secret(http.user.mfa_secret_encrypted)
    disabled = await http.client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "correct-horse-battery-1", "code": current_code(secret)},
    )
    assert disabled.status_code == 204, disabled.text
    assert "MFA_DISABLED" in _codes_http(http)
    status = await http.client.get("/api/v1/auth/mfa/status")
    assert status.json() == {"enabled": False}
    # Back to password-only login.
    http.client.cookies.clear()
    plain = await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    assert plain.status_code == 200


async def test_disable_wrong_password_is_401_http(http) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code
    from src.infrastructure.secrets.mfa_box import decrypt_totp_secret

    await _enable_via_routes(http)
    secret = decrypt_totp_secret(http.user.mfa_secret_encrypted)
    denied = await http.client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "wrong", "code": current_code(secret)},
    )
    assert denied.status_code == 401
    assert (await http.client.get("/api/v1/auth/mfa/status")).json() == {"enabled": True}


async def test_disable_with_recovery_code_http(http) -> None:  # type: ignore[no-untyped-def]
    codes = await _enable_via_routes(http)
    disabled = await http.client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "correct-horse-battery-1", "code": codes[1]},
    )
    assert disabled.status_code == 204, disabled.text


async def test_regenerate_http(http) -> None:  # type: ignore[no-untyped-def]
    from src.domain.mfa.totp import current_code
    from src.infrastructure.secrets.mfa_box import decrypt_totp_secret

    old = await _enable_via_routes(http)
    secret = decrypt_totp_secret(http.user.mfa_secret_encrypted)
    regenerated = await http.client.post(
        "/api/v1/auth/mfa/recovery-codes/regenerate",
        json={"code": current_code(secret)},
    )
    assert regenerated.status_code == 200, regenerated.text
    new = regenerated.json()["recoveryCodes"]
    assert len(new) == 10 and set(new).isdisjoint(old)
    assert "MFA_RECOVERY_REGENERATED" in _codes_http(http)


async def test_mfa_endpoints_require_auth(http) -> None:  # type: ignore[no-untyped-def]
    http.client.cookies.clear()
    assert (await http.client.get("/api/v1/auth/mfa/status")).status_code == 401
    assert (await http.client.post("/api/v1/auth/mfa/enroll")).status_code in (401, 422)
    assert (
        await http.client.post("/api/v1/auth/mfa/disable", json={"password": "x", "code": "123456"})
    ).status_code == 401


async def test_enroll_when_enabled_is_409(http) -> None:  # type: ignore[no-untyped-def]
    await _enable_via_routes(http)
    response = await http.client.post("/api/v1/auth/mfa/enroll")
    assert response.status_code == 409


async def test_verify_rate_limited_http(http, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.api.routes import auth_routes

    await _enable_via_routes(http)
    http.client.cookies.clear()

    async def deny(_scope: str) -> bool:
        return False

    monkeypatch.setattr(auth_routes, "_mfa_verify_limiter", lambda: SimpleNamespace(try_admit=deny))
    await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    limited = await http.client.post("/api/v1/auth/mfa/verify", json={"code": "123456"})
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMITED"
    assert limited.headers.get("Retry-After") == "60"


async def test_firebase_login_with_mfa_challenges(http, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from types import SimpleNamespace as _NS

    from src.api.routes import auth_routes
    from src.config.settings import get_settings

    await _enable_via_routes(http)
    http.client.cookies.clear()

    class _FakeVerifier:
        def verify(self, token: str) -> object:
            assert token == "firebase-id-token"
            return _NS(uid=None, email=EMAIL, email_verified=True)

    monkeypatch.setattr(auth_routes, "_firebase_verifier", lambda _pid: _FakeVerifier())
    settings = get_settings()
    monkeypatch.setattr(settings, "firebase_project_id", "test-project", raising=False)
    response = await http.client.post(
        "/api/v1/auth/firebase", json={"idToken": "firebase-id-token"}
    )
    assert response.status_code == 202, response.text
    assert response.json()["mfaRequired"] is True


async def test_cookie_security_flags(http) -> None:  # type: ignore[no-untyped-def]
    from src.api.routes.auth_routes import _cookie_secure_flag

    await _enable_via_routes(http)
    http.client.cookies.clear()
    response = await http.client.post(
        "/api/v1/auth/login",
        json={"email": EMAIL, "password": "correct-horse-battery-1"},
    )
    challenge = next(c for c in response.headers.get_list("set-cookie") if "mfaChallenge=" in c)
    lowered = challenge.lower()
    assert "httponly" in lowered and "samesite=strict" in lowered
    for env in ("staging", "production"):
        assert _cookie_secure_flag(SimpleNamespace(environment=env)) is True
    for env in ("local", "test"):
        assert _cookie_secure_flag(SimpleNamespace(environment=env)) is False


async def test_audits_carry_no_secrets(http) -> None:  # type: ignore[no-untyped-def]
    codes = await _enable_via_routes(http)
    blob = str(http.audits)
    assert "otpauth" not in blob
    assert all(code not in blob for code in codes)


# --------------------------------------------------------------------------- #
# Migration chain                                                             #
# --------------------------------------------------------------------------- #


def test_migration_chain_head_is_0019() -> None:
    from importlib import import_module

    chain = {
        "0016": ("0015", "remediation_collaboration"),
        "0017": ("0016", "ci_credentials"),
        "0018": ("0017", "mfa_recovery_codes"),
        "0019": ("0018", "mfa_totp_replay_guard"),
    }
    for revision, (down, name) in chain.items():
        module = import_module(f"src.infrastructure.database.migrations.versions.{revision}_{name}")
        assert module.revision == revision
        assert module.down_revision == down

    from src.infrastructure.database.models import Base

    assert "mfa_recovery_code" in Base.metadata.tables
    assert "mfa_totp_use" in Base.metadata.tables
