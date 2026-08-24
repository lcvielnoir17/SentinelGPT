"""Async Redis client management and health check utilities."""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis

from src.config.settings import get_settings
from src.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

_redis_client: aioredis.Redis[str] | None = None


def get_redis_client() -> aioredis.Redis[str]:
    """Get or create the global async Redis client."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def check_redis_connection() -> dict[str, Any]:
    """Ping Redis to verify connectivity for readiness checks."""
    try:
        client = get_redis_client()
        pong = await client.ping()
        if pong:
            return {"status": "up"}
        return {"status": "down", "error": "Ping failed"}
    except Exception as exc:
        logger.error("redis_health_check_failed", error=str(exc))
        return {"status": "down", "error": str(exc)}


async def close_redis_client() -> None:
    """Close Redis client connections during application shutdown."""
    global _redis_client
    if _redis_client is not None:
        if hasattr(_redis_client, "aclose"):
            await _redis_client.aclose()
        else:
            await _redis_client.close()
        _redis_client = None
        logger.info("redis_client_closed")
