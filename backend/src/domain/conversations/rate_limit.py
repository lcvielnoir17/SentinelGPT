"""Per-user rate limiting for the conversational analyst (ADR-0012).

A Redis fixed-window counter keyed by user id and minute bucket. The
limiter fails OPEN: if Redis is unreachable the request proceeds (the
platform's core scanning behavior must never depend on chat throttling),
and the degradation is logged.

Counters are incremented AFTER admission so a rejected request does not
consume budget, and expire after one window.

Concurrency note: the check-then-increment sequence is not atomic, so a
burst of simultaneous requests may admit slightly more than ``limit`` in
one window. This is accepted: the limiter is an abuse throttle, not a
security boundary — tenant isolation is enforced independently in the
conversation service, and quota enforcement (max conversations) uses the
authoritative store.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    import uuid

_logger = structlog.get_logger(__name__)

WINDOW_SECONDS = 60


class RedisFixedWindowLimiter:
    """Allow at most ``limit`` admissions per user per minute."""

    def __init__(self, client: Any, *, limit: int) -> None:
        self._client = client
        self._limit = limit

    async def try_admit(self, user_id: uuid.UUID) -> bool:
        if self._limit <= 0:
            return True
        bucket = int(datetime.now(UTC).timestamp()) // WINDOW_SECONDS
        key = f"sgpt:conv:rl:{user_id}:{bucket}"
        try:
            count = await self._client.get(key)
            if count is not None and int(count) >= self._limit:
                return False
            await self._client.incr(key)
            await self._client.expire(key, WINDOW_SECONDS)
            return True
        except Exception as exc:  # noqa: BLE001 - fail open on any Redis failure
            _logger.warning("conversation_rate_limiter_degraded", error=str(exc))
            return True
