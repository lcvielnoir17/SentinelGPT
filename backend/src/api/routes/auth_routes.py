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

MFA enrollment/challenge, lockout, and login audit logging remain outstanding
Phase 1 Auth Service deliverables.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Request, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import ACCESS_TOKEN_COOKIE
from src.config.constants import (
    REFRESH_COOKIE_PATH,
    REFRESH_TOKEN_COOKIE,
)
from src.config.settings import Settings, get_settings
from src.domain.errors import NotAuthenticatedError, RefreshCsrfHeaderMissingError
from src.domain.users.refresh_service import RefreshService
from src.domain.users.token_service import create_access_token
from src.domain.users.user_service import UserAccount, UserService
from src.infrastructure.database.connection import get_db_session

router = APIRouter(prefix="/auth", tags=["Auth"])

SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


def _require_refresh_csrf_header(x_refresh_request: str | None) -> None:
    """Ch2 §9: only same-origin JS can set this custom header."""
    if x_refresh_request != "1":
        raise RefreshCsrfHeaderMissingError()


def _read_refresh_cookie(request: Request) -> str | None:
    return request.cookies.get(REFRESH_TOKEN_COOKIE)


def _issue_session(
    response: Response,
    session: AsyncSession,
    account: UserAccount,
    settings: Settings,
) -> str:
    """Issue both cookies for a fresh login; returns the raw refresh token.

    Access JWT: short-lived, path=/. Refresh credential: opaque, server-side
    tracked (hash only persisted), scoped to /api/v1/auth. Both HttpOnly;
    Secure; SameSite=Strict (Ch2 §9).
    """
    refresh_service = RefreshService(session, settings.refresh_token_expire_days)
    raw_refresh, _ = refresh_service.issue_family(account.id)
    access = create_access_token(
        user_id=account.id,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_in_minutes=settings.access_token_expire_minutes,
    )
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=raw_refresh,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )
    return raw_refresh


def _clear_auth_cookies(response: Response) -> None:
    """Clear both cookies with attributes matching how they were set."""
    response.delete_cookie(
        key=ACCESS_TOKEN_COOKIE,
        path="/",
        httponly=True,
        secure=True,
        samesite="strict",
    )
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=True,
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


class UserInfo(BaseModel):
    """Authenticated-user representation ({ id, email, mfaEnabled, organizations })."""

    id: uuid.UUID
    email: EmailStr
    mfa_enabled: bool = Field(default=False, serialization_alias="mfaEnabled")
    organizations: list[str] = Field(default_factory=list)


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


def _to_user_info(account: UserAccount) -> UserInfo:
    return UserInfo(id=account.id, email=account.email, mfa_enabled=False)


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
    response_model=LoginResponse,
    summary="Authenticate and receive session cookies",
    description=(
        "Verifies credentials server-side and issues the access JWT and the "
        "opaque refresh credential as HttpOnly; Secure; SameSite=Strict "
        "cookies (Chapter 2, Section 9). No token material in the body."
    ),
)
async def login(payload: LoginRequest, session: SessionDep, response: Response) -> LoginResponse:
    service = UserService(session)
    settings = get_settings()
    # Unknown-email and wrong-password raise the identical InvalidCredentialsError
    # (401 UNAUTHENTICATED) — no user-enumeration oracle (Chapter 5, Section 2).
    account = await service.authenticate(payload.email, payload.password)
    _issue_session(response, session, account, settings)
    return LoginResponse(
        user=_to_user_info(account),
        expires_in=settings.access_token_expire_minutes * 60,
    )


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
    # User eligibility was already verified inside RefreshService.refresh.
    account = await UserService(session).get_account(rotated.user_id)
    if account is None:
        await session.commit()
        raise NotAuthenticatedError()

    access = create_access_token(
        user_id=rotated.user_id,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_in_minutes=settings.access_token_expire_minutes,
    )
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=rotated.raw_token,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        httponly=True,
        secure=True,
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
    refresh_service = RefreshService(session, get_settings().refresh_token_expire_days)
    await refresh_service.logout(_read_refresh_cookie(request))
    _clear_auth_cookies(response)
