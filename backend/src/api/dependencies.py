"""Request-scoped authentication dependency (SRS Chapter 6, Section 4).

Resolves the current authenticated user from the HttpOnly ``accessToken``
cookie per the Chapter 2 Section 9 invariant — no Authorization header, no
token material readable by client JavaScript. Missing/invalid credentials
raise NotAuthenticatedError (401 UNAUTHENTICATED envelope).

Also hosts the conversation-stack providers (ADR-0011/0012): the
user-scoped ConversationStore (Firestore in production, in-memory without
Google credentials), the optional Gemini conversation agent, and the
per-user rate limiter. Each is a FastAPI dependency so tests override them
cleanly via ``dependency_overrides``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.constants import ACCESS_TOKEN_COOKIE
from src.config.settings import get_settings
from src.domain.conversations.rate_limit import RedisFixedWindowLimiter
from src.domain.conversations.store import ConversationStore
from src.domain.errors import NotAuthenticatedError
from src.domain.users.token_service import decode_access_token
from src.domain.users.user_service import UserAccount
from src.infrastructure.database.connection import get_db_session
from src.infrastructure.database.repositories.user_repository import UserRepository

__all__ = [
    "ACCESS_TOKEN_COOKIE",
    "ConversationStoreDep",
    "CurrentUser",
    "get_conversation_agent",
    "get_conversation_store",
    "get_current_user",
    "get_rate_limiter",
]

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


# --------------------------------------------------------------------- #
# Conversation stack providers                                          #
# --------------------------------------------------------------------- #


@lru_cache
def _firestore_store(project_id: str, database_id: str) -> ConversationStore:
    """One Firestore client per (project, database) per process."""
    del project_id, database_id  # cache key only; from_settings reads settings
    from src.infrastructure.firestore.conversation_store import FirestoreConversationStore

    return FirestoreConversationStore.from_settings(get_settings())


_memory_store: ConversationStore | None = None


def get_conversation_store() -> ConversationStore:
    """Production wiring: Firestore when configured, in-memory otherwise."""
    global _memory_store
    settings = get_settings()
    if settings.firestore_conversations_enabled and settings.firebase_project_id:
        return _firestore_store(settings.firebase_project_id, settings.firestore_database_id)
    # Local development without Google credentials: durable-less but
    # behaviorally identical storage (documented in ADR-0011).
    if _memory_store is None:
        from src.infrastructure.firestore.memory_store import InMemoryConversationStore

        _memory_store = InMemoryConversationStore()
    return _memory_store


_agent_cache: tuple[str, str, Any] | None = None


def _cache_key_digest(api_key: str) -> str:
    """SHA-256 digest identifying a cached agent's key without retaining it.

    The module-global agent cache must never hold raw secret material: the
    digest is sufficient to detect a rotation (which simply builds the next
    agent) while keeping the key itself out of long-lived process state.
    """
    import hashlib

    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_conversation_agent() -> Any | None:
    """The Gemini multi-turn agent, or None when no API key is resolvable.

    The agent — and the HTTP client pool inside the genai Client — is
    cached per (key, model) pair so a chat turn does not pay connection
    setup on every request. A rotated secret key simply builds the next
    agent; the single-entry cache keeps memory bounded. Only a digest of
    the key is retained for the comparison, never the key itself.
    """
    from src.infrastructure.secrets import get_gemini_api_key

    global _agent_cache
    settings = get_settings()
    api_key = get_gemini_api_key()
    if not api_key:
        return None
    model = settings.gemini_flash_model
    digest = _cache_key_digest(api_key)
    if _agent_cache is not None and _agent_cache[0] == digest and _agent_cache[1] == model:
        return _agent_cache[2]
    try:
        from src.infrastructure.ai.gemini_chat_agent import GeminiConversationAgent

        agent = GeminiConversationAgent(api_key=api_key, model=model)
    except Exception:  # noqa: BLE001 - AI must degrade, never block requests
        return None
    _agent_cache = (digest, model, agent)
    return agent


def get_rate_limiter() -> RedisFixedWindowLimiter:
    """Redis fixed-window limiter (fails open when Redis is unreachable)."""
    from src.infrastructure.cache.redis_client import get_redis_client

    settings = get_settings()
    return RedisFixedWindowLimiter(
        get_redis_client(), limit=settings.conversation_rate_limit_per_minute
    )


ConversationStoreDep = Annotated[ConversationStore, Depends(get_conversation_store)]
