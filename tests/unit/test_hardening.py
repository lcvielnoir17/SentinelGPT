"""Final hardening threats (M17): cross-boundary confusion regressions.

Each test pins a reviewed security property that must never silently
regress: JWT audience separation (challenge tokens are not sessions
and sessions are not challenges), algorithm confusion, challenge
expiry, MFA-status non-oracle on failed logins, credential-family
isolation (CI bearers never authenticate browser endpoints),
append-only audit enforcement in the migration chain, full downgrade
rendering, benign concurrent enrollment, report/comment separation,
secret placement in the public contract, and idempotent attestation
revocation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from src.domain.errors import NotAuthenticatedError

USER_ID = uuid.uuid4()
SECRET = "test-secret-key-must-be-at-least-32-chars-long"


def _user() -> SimpleNamespace:
    now = datetime.now(UTC)
    return SimpleNamespace(
        id=USER_ID,
        email="owner@example.com",
        password_hash="x",
        mfa_enabled=False,
        mfa_secret_encrypted=None,
        is_active=True,
        firebase_uid=None,
        created_at=now,
        updated_at=now,
    )


# --------------------------------------------------------------------------- #
# A. Token-family confusion                                                   #
# --------------------------------------------------------------------------- #


def test_challenge_token_rejected_as_session() -> None:
    """A challenge JWT must never authenticate as a session (MFA bypass)."""
    from src.domain.users.token_service import (
        create_access_token,
        create_mfa_challenge_token,
        decode_access_token,
        decode_mfa_challenge_token,
    )

    challenge = create_mfa_challenge_token(user_id=USER_ID, secret_key=SECRET, algorithm="HS256")
    with pytest.raises(NotAuthenticatedError):
        decode_access_token(challenge, secret_key=SECRET, algorithm="HS256")
    session_token = create_access_token(
        user_id=USER_ID, secret_key=SECRET, algorithm="HS256", expires_in_minutes=15
    )
    with pytest.raises(NotAuthenticatedError):
        decode_mfa_challenge_token(session_token, secret_key=SECRET, algorithm="HS256")
    assert decode_mfa_challenge_token(challenge, secret_key=SECRET, algorithm="HS256") == USER_ID


def test_jwt_none_algorithm_rejected() -> None:
    """alg=none tokens are rejected (algorithm confusion)."""
    import jwt as pyjwt

    from src.domain.users.token_service import decode_access_token

    now = datetime.now(UTC)
    token = pyjwt.encode(
        {"sub": str(USER_ID), "exp": now + timedelta(minutes=15)}, key="", algorithm="none"
    )
    with pytest.raises(NotAuthenticatedError):
        decode_access_token(token, secret_key=SECRET, algorithm="HS256")


def test_expired_challenge_rejected() -> None:
    """Stale challenges die with expiry (replay window is 5 minutes)."""
    from src.domain.users.token_service import (
        create_mfa_challenge_token,
        decode_mfa_challenge_token,
    )

    stale = create_mfa_challenge_token(
        user_id=USER_ID, secret_key=SECRET, algorithm="HS256", expires_in_minutes=-1
    )
    with pytest.raises(NotAuthenticatedError):
        decode_mfa_challenge_token(stale, secret_key=SECRET, algorithm="HS256")


# --------------------------------------------------------------------------- #
# A. MFA-status oracle + credential-family isolation (HTTP)                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def http(monkeypatch):  # type: ignore[no-untyped-def]
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
        email="owner@example.com",
        password_hash=hash_password("correct-horse-battery-1"),
        mfa_enabled=False,
        is_active=True,
        created_at=now,
        updated_at=now,
    )

    class RouteSession:
        def __init__(self) -> None:
            self.codes: list = []

        async def get(self, model: object, key: object) -> object | None:
            if getattr(model, "__name__", "") == "User":
                return user if key == USER_ID else None
            return None

        def add(self, row: object) -> None:
            self.codes.append(row)

        async def flush(self) -> None:
            return None

        async def commit(self) -> None:
            return None

        async def rollback(self) -> None:
            return None

        async def execute(self, stmt: object) -> object:
            text = str(stmt)

            class _Scalars:
                def all(self) -> list:
                    return []

                def first(self) -> None:
                    return None

            class _Result:
                def scalars(self) -> _Scalars:
                    return _Scalars()

                def scalar_one_or_none(self) -> None:
                    return None

            if "DELETE" in text:
                user.mfa_enabled = user.mfa_enabled
            return _Result()

    session = RouteSession()

    async def fake_record(_self: object, **kwargs: object) -> None:
        return None

    async def fake_get_by_email(_self: object, email: str) -> object | None:
        return user if email == "owner@example.com" else None

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
        client=AsyncClient(transport=transport, base_url="http://test"), user=user
    )


async def test_wrong_password_on_mfa_account_is_plain_401(http) -> None:  # type: ignore[no-untyped-def]
    """Failed logins never reveal MFA status (no enumeration oracle)."""
    from src.domain.mfa.totp import current_code
    from src.infrastructure.secrets.mfa_box import decrypt_totp_secret

    http.user.mfa_enabled = False
    logged = await http.client.post(
        "/api/v1/auth/login",
        json={"email": "owner@example.com", "password": "correct-horse-battery-1"},
    )
    assert logged.status_code == 200
    enrolled = await http.client.post("/api/v1/auth/mfa/enroll")
    assert enrolled.status_code == 201
    secret = enrolled.json()["secret"]
    verified = await http.client.post(
        "/api/v1/auth/mfa/verify-enrollment", json={"code": current_code(secret)}
    )
    assert verified.status_code == 200
    assert decrypt_totp_secret(http.user.mfa_secret_encrypted)
    http.client.cookies.clear()
    denied = await http.client.post(
        "/api/v1/auth/login",
        json={"email": "owner@example.com", "password": "wrong-password-xyz"},
    )
    assert denied.status_code == 401
    assert denied.json() == {
        "error": {
            "code": "UNAUTHENTICATED",
            "message": "Invalid email or password.",
            "requestId": denied.json()["error"]["requestId"],
        }
    }


async def test_ci_bearer_never_authenticates_browser_endpoints(http, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Credential families do not cross: CI bearers are not sessions."""
    from src.domain.ci import tokens

    credential_id = uuid.uuid4()
    bearer = tokens.build_plaintext(credential_id, tokens.generate_secret())
    me = await http.client.get("/api/v1/auth/me", cookies={"accessToken": bearer})
    assert me.status_code == 401
    forged = await http.client.get(
        "/api/v1/auth/me", cookies={"accessToken": "sgptci_" + "00" * 32}
    )
    assert forged.status_code == 401


# --------------------------------------------------------------------------- #
# F. Concurrent enrollment is benign                                          #
# --------------------------------------------------------------------------- #


async def test_concurrent_enrollment_verify_single_activation(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Double-submitted enrollment codes: one activates, one gets 409."""
    import asyncio

    from cryptography.fernet import Fernet

    import src.infrastructure.secrets.mfa_box as mfa_box
    from src.domain.audit.audit_service import AuditService
    from src.domain.mfa.errors import MfaConflictError
    from src.domain.mfa.service import MfaService
    from src.domain.mfa.totp import current_code

    async def noop_record(_self: object, **kwargs: object) -> None:
        return None

    key = Fernet(Fernet.generate_key())
    monkeypatch.setattr(mfa_box, "_fernet", lambda: key)
    monkeypatch.setattr(AuditService, "record", noop_record)

    class Session:
        def __init__(self, user: object) -> None:
            self.user = user

        async def get(self, _model: object, _key: object) -> object | None:
            return self.user

        async def flush(self) -> None:
            return None

        async def execute(self, _stmt: object) -> object:
            class _Scalars:
                def all(self) -> list:
                    return []

            class _Result:
                def scalars(self) -> _Scalars:
                    return _Scalars()

            return _Result()

        def add(self, _row: object) -> None:
            return None

    session = Session(_user())
    service = MfaService(session)
    principal = SimpleNamespace(id=USER_ID, email="owner@example.com")
    started = await service.begin_enrollment(principal)
    code = current_code(started.secret)
    results = await asyncio.gather(
        service.verify_enrollment(principal, code),
        service.verify_enrollment(principal, code),
        return_exceptions=True,
    )
    successes = sum(not isinstance(r, Exception) for r in results)
    conflicts = sum(isinstance(r, MfaConflictError) for r in results)
    assert (successes, conflicts) == (1, 1)


# --------------------------------------------------------------------------- #
# K. Report/comment separation                                                #
# --------------------------------------------------------------------------- #


async def test_remediation_report_excludes_comments() -> None:
    """M8 decision pin: comment history never enters report output."""
    from src.api.routes.scan_routes import _to_remediation_response

    row = {
        "id": str(uuid.uuid4()),
        "fingerprint": "fp",
        "status": "IN_PROGRESS",
        "notes": "n",
        "updated_by_user_id": None,
        "created_at": None,
        "updated_at": None,
    }
    body = _to_remediation_response(row).model_dump()
    assert "comment" not in json_keys(body)


def json_keys(payload: object) -> str:
    import json as _json

    return _json.dumps(payload)


# --------------------------------------------------------------------------- #
# O. OpenAPI secret placement contract                                        #
# --------------------------------------------------------------------------- #


def test_openapi_secret_placement_contract() -> None:
    """Secrets appear only in once-only creation responses; passwords in bodies."""
    import json as _json
    import pathlib as _pathlib

    schema = _json.loads((_pathlib.Path("openapi.json")).read_text())
    secret_responses: list[str] = []
    password_places: list[str] = []
    for name, component in sorted(schema.get("components", {}).get("schemas", {}).items()):
        props = (component or {}).get("properties", {})
        if "secret" in props:
            secret_responses.append(name)
        if "password" in props:
            password_places.append(name)
    assert secret_responses == [
        "CreatedCredentialResponse",
        "CreatedWebhookResponse",
        "EnrollMfaResponse",
    ]
    assert password_places == ["DisableMfaRequest", "LoginRequest", "RegisterRequest"]


# --------------------------------------------------------------------------- #
# N. Migration chain integrity (offline)                                      #
# --------------------------------------------------------------------------- #


def test_audit_append_only_trigger_in_chain() -> None:
    """The append-only trigger ships in migration 0005 (physical guarantee)."""
    import pathlib as _pathlib

    text = (
        _pathlib.Path("backend/src/infrastructure/database/migrations/versions")
        / "0005_phase8_audit_log.py"
    ).read_text()
    assert "audit_log_entry_no_update" in text
    assert "audit_log_entry_no_delete" in text
    assert "RAISE EXCEPTION" in text


def test_full_downgrade_chain_renders() -> None:
    """Every migration downgrades cleanly (offline render, no database)."""
    import subprocess as _subprocess
    import sys as _sys

    completed = _subprocess.run(
        [_sys.executable, "-m", "alembic", "downgrade", "head:base", "--sql"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "DROP TABLE" in completed.stdout


# --------------------------------------------------------------------------- #
# Attestation revocation idempotency                                          #
# --------------------------------------------------------------------------- #


async def test_attestation_rerevoke_idempotent(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Re-revoking returns current state without duplicate audit rows."""
    from src.domain.audit.audit_service import AuditService
    from src.domain.scans.attestation_service import AttestationService
    from src.infrastructure.database.repositories.attestation_repository import (
        AttestationRepository,
    )

    audits: list[dict] = []
    now = datetime.now(UTC)
    attestation = SimpleNamespace(
        id=uuid.uuid4(),
        target_id=uuid.uuid4(),
        status="REVOKED",
        method_id=1,
        expires_at=None,
        evidence_file_ref=None,
        created_by_user_id=USER_ID,
        revoked_at=now,
        revoked_reason="r",
        created_at=now,
    )

    async def fake_get_by_id(_self: object, aid: uuid.UUID) -> object | None:
        return attestation

    async def fake_record(_self: object, **kwargs: object) -> None:
        audits.append(dict(kwargs))

    async def fake_codes(_self: object) -> dict:
        return {1: "self-attestation"}

    async def fake_visible(_self: object, tid: uuid.UUID) -> object:
        return SimpleNamespace(id=tid, owner_user_id=USER_ID)

    monkeypatch.setattr(AttestationRepository, "get_by_id", fake_get_by_id)
    monkeypatch.setattr(AttestationRepository, "method_code_map", fake_codes)
    monkeypatch.setattr(AuditService, "record", fake_record)
    monkeypatch.setattr(AttestationService, "_require_visible_target", fake_visible)
    service = AttestationService(
        object(),
        SimpleNamespace(id=USER_ID, email="o@e.com", created_at=datetime.now(UTC)),  # type: ignore[arg-type]
    )
    first = await service.revoke(attestation.id, reason="r")
    second = await service.revoke(attestation.id, reason="r")
    assert first.status == second.status == "REVOKED"
    assert audits == []
