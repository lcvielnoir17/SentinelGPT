"""Authentication & session endpoints (SRS Chapter 5, Section 2).

``/auth/register`` creates real Argon2id-hashed accounts and ``/auth/login``
verifies credentials server-side, issuing the short-lived signed access JWT
exactly as the v3 invariant (Chapter 2, Section 9) prescribes: delivered ONLY
as an HttpOnly; Secure; SameSite=Strict cookie — no token material ever
appears in the JSON body. MFA, lockout, audit logging, and the refresh-token
session layer are subsequent Phase 1 deliverables and are intentionally
absent here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import ACCESS_TOKEN_COOKIE
from src.config.settings import get_settings
from src.domain.users.token_service import create_access_token
from src.domain.users.user_service import UserAccount, UserService
from src.infrastructure.database.connection import get_db_session

router = APIRouter(prefix="/auth", tags=["Auth"])

SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


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
    """200 response: { user, expiresIn } per the SRS contract.

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
    summary="Authenticate and receive session confirmation",
    description=(
        "Verifies credentials server-side and issues the access token as an "
        "HttpOnly; Secure; SameSite=Strict cookie (Chapter 2, Section 9)."
    ),
)
async def login(payload: LoginRequest, session: SessionDep, response: Response) -> LoginResponse:
    service = UserService(session)
    settings = get_settings()
    # Unknown-email and wrong-password raise the identical InvalidCredentialsError
    # (401 UNAUTHENTICATED) — no user-enumeration oracle (Chapter 5, Section 2).
    account = await service.authenticate(payload.email, payload.password)
    token = create_access_token(
        user_id=account.id,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        expires_in_minutes=settings.access_token_expire_minutes,
    )
    # Chapter 2, Section 9 invariant: HttpOnly; Secure; SameSite=Strict.
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=token,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    return LoginResponse(
        user=_to_user_info(account),
        expires_in=settings.access_token_expire_minutes * 60,
    )
