"""Authentication & session endpoints (SRS Chapter 5, Section 2).

PHASE 0 STUBS — intentionally temporary behavior, clearly marked:
* ``/auth/register`` creates a real user row (Argon2id hash).
* ``/auth/login`` performs real credential verification against the database.
* NO tokens are issued and no cookies are set. Per the v3 invariant
  (Chapter 2, Section 9) tokens will be delivered exclusively via
  HttpOnly/Secure/SameSite=Strict cookies in Phase 1; until then the client
  only learns *that* credentials were valid (``user`` + ``expiresIn``), never
  any credential material. MFA challenge branch, refresh rotation, lockout,
  and audit logging are Phase 1 deliverables.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import get_settings
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

    PHASE 0: contains deliberately no token material of any kind.
    """

    user: UserInfo
    expires_in: int = Field(
        serialization_alias="expiresIn",
        description="Access-token lifetime in seconds once Phase 1 issues cookies.",
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
        "Verifies credentials server-side. PHASE 0: confirms validity only — "
        "HttpOnly cookie token issuance arrives with the Phase 1 Auth Service."
    ),
)
async def login(payload: LoginRequest, session: SessionDep) -> LoginResponse:
    service = UserService(session)
    settings = get_settings()
    # Unknown-email and wrong-password raise the identical InvalidCredentialsError
    # (401 UNAUTHENTICATED) — no user-enumeration oracle (Chapter 5, Section 2).
    account = await service.authenticate(payload.email, payload.password)
    return LoginResponse(
        user=_to_user_info(account),
        expires_in=settings.access_token_expire_minutes * 60,
    )
