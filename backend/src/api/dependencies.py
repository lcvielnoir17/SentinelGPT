"""Request-scoped authentication dependency (SRS Chapter 6, Section 4).

Resolves the current authenticated user from the HttpOnly ``accessToken``
cookie per the Chapter 2 Section 9 invariant — no Authorization header, no
token material readable by client JavaScript. Missing/invalid credentials
raise NotAuthenticatedError (401 UNAUTHENTICATED envelope).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.constants import ACCESS_TOKEN_COOKIE
from src.config.settings import get_settings
from src.domain.errors import NotAuthenticatedError
from src.domain.users.token_service import decode_access_token
from src.domain.users.user_service import UserAccount
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.repositories.user_repository import UserRepository

__all__ = ["ACCESS_TOKEN_COOKIE", "CurrentUser", "get_current_user"]

SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


async def get_current_user(request: Request, session: SessionDep) -> UserAccount:
    """Authenticate the request via the access-token cookie and load the user."""
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if not token:
        raise NotAuthenticatedError()

    settings = get_settings()
    user_id = decode_access_token(
        token,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    user = await UserRepository(session).get_by_id(user_id)
    if user is None or not user.is_active:
        raise NotAuthenticatedError()
    return UserAccount(
        id=user.id,
        email=user.email,
        created_at=user.created_at,
        firebase_uid=user.firebase_uid,
    )


CurrentUser = Annotated[UserAccount, Depends(get_current_user)]
