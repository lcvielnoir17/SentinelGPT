"""Authentication & session endpoints (SRS Chapter 5, Section 2).

Implements the Chapter 2 Section 9 / Chapter 11 Section 8 session invariants:
* ``/auth/login`` issues a short-lived signed access JWT AND an opaque,
  server-side-tracked refresh credential — each delivered ONLY as
  HttpOnly; Secure; SameSite=Strict cookies (refresh scoped to the auth
  routes). No token material ever appears in a JSON body.
* ``/auth/refresh`` rotates both cookies on every use and requires the
  ``X-Refresh-Request: 1`` header (cross-site forms cannot set custom
  headers). Presenting a rotated-out refresh credential revokes the entire
  token family (reuse detection, Chapter 5 Section 2) and answers 401.
* ``/auth/logout`` revokes the presented session and clears both cookies.

The ``Secure`` cookie attribute is REQUIRED in production but breaks the
local HTTP dev loop (browsers / ``httpx.AsyncClient`` refuse to store
Secure cookies over a non-HTTPS connection). The attribute is therefore
gated on the runtime environment: ``staging``/``production`` set it,
``local``/``test`` omit it. The chapter 2 §9 invariant — that deployed
environments NEVER relax this — is preserved by the settings validator
and the docker-compose production overlay, which always run in
``production`` with the attribute on.

MFA (M11, implemented below): TOTP enrollment with verification-gated
activation, a short-lived challenge token after password authentication
(never a session before the second factor), single-use hashed recovery
codes, and re-authenticated disable/regeneration. Secrets never leave
the enrollment response; audits carry ids and outcomes only. Lockout
and login audit logging remain outstanding Phase 1 deliverables.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from functools import lru_cache
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Header, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from src.api.dependencies import ACCESS_TOKEN_COOKIE, CurrentUser, SessionDep
from src.config.constants import (
    ENV_PRODUCTION,
    ENV_STAGING,
    REFRESH_COOKIE_PATH,
    REFRESH_TOKEN_COOKIE,
)
from src.config.settings import Settings, get_settings
from src.domain.errors import (
    FeatureDisabledError,
    NotAuthenticatedError,
    RefreshCsrfHeaderMissingError,
)
from src.domain.users.firebase_token_service import FirebaseTokenVerifier
from src.domain.users.refresh_service import RefreshService
from src.domain.users.token_service import create_access_token
from src.domain.users.user_service import UserAccount, UserService

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/auth", tags=["Auth"])


def _require_refresh_csrf_header(x_refresh_request: str | None) -> None:
    """Ch2 §9: only same-origin JS can set this custom header."""
    if x_refresh_request != "1":
        raise RefreshCsrfHeaderMissingError()


def _read_refresh_cookie(request: Request) -> str | None:
    return request.cookies.get(REFRESH_TOKEN_COOKIE)


def _cookie_secure_flag(settings: Settings) -> bool:
    """``Secure`` is on for deployed environments, off for local/test.

    The dev/test loops use plain HTTP; the ``Secure`` attribute would
    cause browsers and ``httpx.AsyncClient`` to silently drop the
    cookie, breaking the auth flow. Production / staging always run
    behind TLS, so the attribute is always set there.
    """
    return settings.environment in (ENV_STAGING, ENV_PRODUCTION)


def _issue_session(
    response: Response,
    session: AsyncSession,
    account: UserAccount,
    settings: Settings,
) -> str:
    """Issue both cookies for a fresh login; returns the raw refresh token.

    Access JWT: short-lived, path=/. Refresh credential: opaque, server-side
    tracked (hash only persisted), scoped to /api/v1/auth. Both HttpOnly;
    SameSite=Strict. ``Secure`` is set in staging/production only
    (see :func:`_cookie_secure_flag`).
    """
    refresh_service = RefreshService(session, settings.refresh_token_expire_days)
    raw_refresh, _ = refresh_service.issue_family(account.id)
    access = create_access_token(
        user_id=account.id,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_in_minutes=settings.access_token_expire_minutes,
    )
    cookie_secure = _cookie_secure_flag(settings)
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=raw_refresh,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )
    return raw_refresh


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    """Clear both cookies with attributes matching how they were set."""
    cookie_secure = _cookie_secure_flag(settings)
    response.delete_cookie(
        key=ACCESS_TOKEN_COOKIE,
        path="/",
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
    )
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
    )


class RegisterRequest(BaseModel):
    """POST /auth/register request body (SRS Chapter 5, Section 2)."""

    email: EmailStr
    password: str = Field(
        min_length=12,
        max_length=128,
        description="Plaintext password; hashed with Argon2id before storage.",
    )


class UserCreatedResponse(BaseModel):
    """201 response: { id, email, createdAt } per the SRS contract."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    created_at: datetime = Field(serialization_alias="createdAt")


class LoginRequest(BaseModel):
    """POST /auth/login request body."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class FirebaseLoginRequest(BaseModel):
    """POST /auth/firebase request body (ADR-0010)."""

    id_token: str = Field(
        min_length=1,
        max_length=4096,
        validation_alias="idToken",
        description="Firebase ID token obtained from the Firebase Auth SDK.",
    )


class UserInfo(BaseModel):
    """Authenticated-user representation ({ id, email, mfaEnabled })."""

    id: uuid.UUID
    email: EmailStr
    mfa_enabled: bool = Field(default=False, serialization_alias="mfaEnabled")


class LoginResponse(BaseModel):
    """200 response: { user, expiresIn } + Set-Cookie per the SRS contract.

    The JSON body contains deliberately no token material of any kind — the
    access token travels exclusively in the HttpOnly cookie.
    """

    user: UserInfo
    expires_in: int = Field(
        serialization_alias="expiresIn",
        description="Access-token lifetime in seconds.",
    )


class MfaChallengeResponse(BaseModel):
    """202 response: second factor outstanding, challenge cookie issued.

    No session exists yet — the caller must complete
    POST /auth/mfa/verify before any authenticated session is minted.
    """

    mfa_required: bool = Field(default=True, serialization_alias="mfaRequired")
    expires_in: int = Field(
        serialization_alias="expiresIn",
        description="Challenge lifetime in seconds.",
    )


def _to_user_info(account: UserAccount) -> UserInfo:
    return UserInfo(id=account.id, email=account.email, mfa_enabled=account.mfa_enabled)


MFA_CHALLENGE_COOKIE = "mfaChallenge"


def _mfa_verify_limiter() -> Any:
    """Per-user atomic throttle for second-factor attempts (fail-open)."""
    from src.domain.scans.rate_limit import RedisAtomicRateLimiter
    from src.infrastructure.cache.redis_client import get_redis_client

    settings = get_settings()
    return RedisAtomicRateLimiter(
        get_redis_client(),
        key_prefix="sgpt:mfa:verify",
        limit=settings.mfa_verify_limit_per_minute,
        window_seconds=60,
    )


def _mfa_service(session: AsyncSession) -> Any:
    from src.domain.mfa.service import MfaService

    return MfaService(session, verify_limiter=_mfa_verify_limiter())


def _set_challenge_cookie(response: Response, token: str, settings: Settings) -> None:
    """Short-lived challenge cookie (challenge endpoint only, never a session)."""
    from src.domain.users.token_service import MFA_CHALLENGE_EXPIRE_MINUTES

    response.set_cookie(
        key=MFA_CHALLENGE_COOKIE,
        value=token,
        max_age=MFA_CHALLENGE_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=_cookie_secure_flag(settings),
        samesite="strict",
        path="/api/v1/auth",
    )


def _clear_challenge_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=MFA_CHALLENGE_COOKIE,
        path="/api/v1/auth",
        httponly=True,
        secure=_cookie_secure_flag(settings),
        samesite="strict",
    )


def _challenge_response(
    response: Response, account: UserAccount, settings: Settings
) -> MfaChallengeResponse:
    """202 + challenge cookie for MFA-enabled accounts (no session issued).

    The status is set on the injected response so cookies set here are
    honored (returning a bare JSONResponse would drop them).
    """
    from src.domain.users.token_service import (
        MFA_CHALLENGE_EXPIRE_MINUTES,
        create_mfa_challenge_token,
    )

    token = create_mfa_challenge_token(
        user_id=account.id,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    _set_challenge_cookie(response, token, settings)
    response.status_code = status.HTTP_202_ACCEPTED
    return MfaChallengeResponse(expires_in=MFA_CHALLENGE_EXPIRE_MINUTES * 60)


@lru_cache
def _firebase_verifier(project_id: str) -> FirebaseTokenVerifier:
    """One verifier (and its JWK cache) per process per project ID.

    Patched by the unit tests to inject offline JWK resolution.
    """
    return FirebaseTokenVerifier(project_id)


@router.post(
    "/register",
    response_model=UserCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
)
async def register(payload: RegisterRequest, session: SessionDep) -> UserCreatedResponse:
    """Register a new account; duplicate emails yield a 409 CONFLICT envelope."""
    service = UserService(session)
    account = await service.register_user(payload.email, payload.password)
    return UserCreatedResponse(id=account.id, email=account.email, created_at=account.created_at)


@router.post(
    "/login",
    response_model=None,
    responses={
        200: {"model": LoginResponse},
        202: {"model": MfaChallengeResponse},
    },
    summary="Authenticate and receive session cookies",
    description=(
        "Verifies credentials server-side and issues the access JWT and the "
        "opaque refresh credential as HttpOnly; Secure; SameSite=Strict "
        "cookies (Chapter 2, Section 9). No token material in the body. "
        "MFA-enabled accounts receive 202 + a short-lived challenge cookie "
        "instead — no session is minted before the second factor."
    ),
)
async def login(payload: LoginRequest, session: SessionDep, response: Response) -> Any:
    service = UserService(session)
    settings = get_settings()
    # Unknown-email and wrong-password raise the identical InvalidCredentialsError
    # (401 UNAUTHENTICATED) — no user-enumeration oracle (Chapter 5, Section 2).
    account = await service.authenticate(payload.email, payload.password)
    if account.mfa_enabled:
        # Second factor outstanding: challenge only, never a session.
        return _challenge_response(response, account, settings)
    _issue_session(response, session, account, settings)
    return LoginResponse(
        user=_to_user_info(account),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/firebase",
    response_model=None,
    responses={
        200: {"model": LoginResponse},
        202: {"model": MfaChallengeResponse},
    },
    summary="Exchange a Firebase ID token for SentinelGPT session cookies",
    description=(
        "Verifies a Firebase ID token server-side (signature, audience, "
        "issuer, expiry against Google's public JWKs) and resolves or "
        "provisions the canonical SentinelGPT account for that identity "
        "(ADR-0010), then issues the same HttpOnly session cookies as "
        "POST /auth/login. The client never sends a user ID — identity "
        "comes exclusively from the verified token. Requires "
        "FIREBASE_PROJECT_ID to be configured (503 otherwise)."
    ),
)
async def firebase_login(
    payload: FirebaseLoginRequest,
    session: SessionDep,
    response: Response,
) -> Any:
    settings = get_settings()
    if not settings.firebase_project_id:
        raise FeatureDisabledError("Firebase sign-in is not configured on this deployment.")
    verifier = _firebase_verifier(settings.firebase_project_id)
    # JWKS resolution is blocking HTTP; keep it off the event loop.
    identity = await asyncio.to_thread(verifier.verify, payload.id_token)
    account = await UserService(session).authenticate_firebase(
        identity, project_id=settings.firebase_project_id
    )
    if account.mfa_enabled:
        return _challenge_response(response, account, settings)
    _issue_session(response, session, account, settings)
    return LoginResponse(
        user=_to_user_info(account),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get(
    "/me",
    response_model=UserInfo,
    summary="Return the authenticated user (session restore probe)",
    description=(
        "Cheap identity probe used by the SPA on page load to restore the "
        "in-memory user from the still-attached HttpOnly access cookie. "
        "Returns 200 with the same UserInfo the login response uses; "
        "returns the standard 401 UNAUTHENTICATED envelope when no valid "
        "session is attached. No token material is ever returned in the body."
    ),
)
async def get_me(current_user: CurrentUser) -> UserInfo:
    return _to_user_info(current_user)


@router.post(
    "/refresh",
    response_model=LoginResponse,
    summary="Rotate the refresh credential and reissue both cookies",
    description=(
        "Reads the HttpOnly refreshToken cookie (requires X-Refresh-Request: 1). "
        "Every call rotates both cookies. Presenting a rotated-out credential "
        "revokes the entire token family and returns 401 (Ch5 §2 reuse detection)."
    ),
)
async def refresh_session(
    request: Request,
    session: SessionDep,
    response: Response,
    x_refresh_request: Annotated[str | None, Header()] = None,
) -> LoginResponse:
    _require_refresh_csrf_header(x_refresh_request)
    settings = get_settings()
    refresh_service = RefreshService(session, settings.refresh_token_expire_days)
    outcome = await refresh_service.refresh(_read_refresh_cookie(request))

    if outcome.rotated is None or outcome.rejection is not None:
        # Security transitions staged by the service (family revocation on
        # reuse, expired/invalidated single revocations) MUST survive the 401.
        # The shared request session rolls back on any exception, so persist
        # those transitions explicitly before raising. Every rejection reason
        # maps to the identical 401 envelope — reuse is not distinguishable.
        await session.commit()
        raise NotAuthenticatedError()

    rotated = outcome.rotated
    # User eligibility was already verified inside RefreshService.refresh;
    # re-check activity here so a deactivation landing in between cannot
    # mint a fresh access JWT.
    account = await UserService(session).get_account(rotated.user_id, require_active=True)
    if account is None:
        await session.commit()
        raise NotAuthenticatedError()

    access = create_access_token(
        user_id=rotated.user_id,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_in_minutes=settings.access_token_expire_minutes,
    )
    cookie_secure = _cookie_secure_flag(settings)
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=rotated.raw_token,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )
    return LoginResponse(
        user=_to_user_info(account), expires_in=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke the presented refresh session and clear cookies",
    description=(
        "Requires X-Refresh-Request: 1. Revokes the presented ACTIVE refresh "
        "credential server-side (idempotent) and clears both auth cookies."
    ),
)
async def logout(
    request: Request,
    session: SessionDep,
    response: Response,
    x_refresh_request: Annotated[str | None, Header()] = None,
) -> None:
    _require_refresh_csrf_header(x_refresh_request)
    settings = get_settings()
    refresh_service = RefreshService(session, settings.refresh_token_expire_days)
    await refresh_service.logout(_read_refresh_cookie(request))
    _clear_auth_cookies(response, settings)


# --------------------------------------------------------------------- #
# MFA (M11): additive second factor over the session architecture above  #
# --------------------------------------------------------------------- #


class EnrollMfaResponse(BaseModel):
    """200 response: provisioning material, shown exactly once."""

    provisioning_uri: str = Field(serialization_alias="provisioningUri")
    secret: str = Field(description="Raw TOTP secret; shown once, never again")


class VerifyMfaRequest(BaseModel):
    """TOTP-or-recovery code body (1..32 chars)."""

    code: str = Field(min_length=1, max_length=32)


class RecoveryCodesResponse(BaseModel):
    """Recovery codes, shown exactly once per generation."""

    recovery_codes: list[str] = Field(serialization_alias="recoveryCodes")


class MfaStatusResponse(BaseModel):
    """Enrollment state (never any secret material)."""

    enabled: bool


class DisableMfaRequest(BaseModel):
    """Password plus a second factor (TOTP or unused recovery code)."""

    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=1, max_length=32)


def _read_challenge_cookie(request: Request) -> str | None:
    return request.cookies.get(MFA_CHALLENGE_COOKIE)


@router.post(
    "/mfa/enroll",
    response_model=EnrollMfaResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Begin MFA enrollment",
)
async def enroll_mfa(session: SessionDep, current_user: CurrentUser) -> EnrollMfaResponse:
    """Stage an encrypted pending secret (inactive until verified).

    Returns provisioning material exactly once; already-enabled
    accounts get 409. Re-enrolling while pending replaces the secret.
    """
    started = await _mfa_service(session).begin_enrollment(current_user)
    return EnrollMfaResponse(provisioning_uri=started.provisioning_uri, secret=started.secret)


@router.post(
    "/mfa/verify-enrollment",
    response_model=RecoveryCodesResponse,
    summary="Verify enrollment and activate MFA",
)
async def verify_mfa_enrollment(
    payload: VerifyMfaRequest, session: SessionDep, current_user: CurrentUser
) -> RecoveryCodesResponse:
    """Activate MFA after a correct code; recovery codes shown once."""
    issued = await _mfa_service(session).verify_enrollment(current_user, payload.code)
    return RecoveryCodesResponse(recovery_codes=issued.codes)


@router.get(
    "/mfa/status",
    response_model=MfaStatusResponse,
    summary="Read MFA enrollment state",
)
async def mfa_status(session: SessionDep, current_user: CurrentUser) -> MfaStatusResponse:
    """Enrollment state for the caller (never any secret material)."""
    state = await _mfa_service(session).status(current_user)
    return MfaStatusResponse(enabled=bool(state["enabled"]))


@router.post(
    "/mfa/verify",
    response_model=LoginResponse,
    summary="Complete the MFA challenge and receive session cookies",
)
async def verify_mfa_challenge(
    payload: VerifyMfaRequest,
    request: Request,
    session: SessionDep,
    response: Response,
) -> LoginResponse:
    """Consume the challenge cookie + TOTP/recovery code, then issue a session.

    Accepts ONLY the short-lived challenge token — never a session
    JWT. Malformed codes are 400; wrong codes are the identical 401
    as login failures. Rate-limited per user against brute force.
    """
    from src.domain.users.token_service import decode_mfa_challenge_token

    settings = get_settings()
    user_id = decode_mfa_challenge_token(
        _read_challenge_cookie(request) or "",
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    account = await _mfa_service(session).verify_challenge(user_id, payload.code)
    _clear_challenge_cookie(response, settings)
    _issue_session(response, session, account, settings)
    return LoginResponse(
        user=_to_user_info(account),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/mfa/disable",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable MFA with password + second factor",
)
async def disable_mfa(
    payload: DisableMfaRequest, session: SessionDep, current_user: CurrentUser
) -> None:
    """Disable requires the current password AND a second factor.

    A bare session hijack cannot strip MFA; a user who lost the
    authenticator recovers with password + recovery code.
    """
    await _mfa_service(session).disable(current_user, password=payload.password, code=payload.code)


@router.post(
    "/mfa/recovery-codes/regenerate",
    response_model=RecoveryCodesResponse,
    summary="Replace all recovery codes",
)
async def regenerate_mfa_recovery_codes(
    payload: VerifyMfaRequest, session: SessionDep, current_user: CurrentUser
) -> RecoveryCodesResponse:
    """Replace codes (authed session + current TOTP); new set shown once."""
    issued = await _mfa_service(session).regenerate_recovery_codes(
        current_user, totp_code=payload.code
    )
    return RecoveryCodesResponse(recovery_codes=issued.codes)
