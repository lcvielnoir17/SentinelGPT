"""Atomic Redis rate limiting for scan creation.

Complements the conversational ``RedisFixedWindowLimiter`` (which
documents its check-then-increment burst tolerance): scan creation spends
real worker capacity, so admission must be atomic. A single Lua script
increments the window counter and sets its expiry, closing the race
between concurrent ``POST /scans`` requests from the same user.

Fails OPEN like the rest of the platform's throttles: if Redis is
unreachable the scan proceeds (availability over throttling) and the
degradation is logged. Quota caps in ``ScanService`` are database-backed
and hold regardless.
"""

from __future__ import annotations

from typing import Any

import structlog

_logger = structlog.get_logger(__name__)

_ADMIT_LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""


class RedisAtomicRateLimiter:
    """At most ``limit`` admissions per ``scope`` per window (atomic)."""

    def __init__(
        self, client: Any, *, key_prefix: str, limit: int, window_seconds: int = 60
    ) -> None:
        self._client = client
        self._key_prefix = key_prefix
        self._limit = limit
        self._window_seconds = window_seconds

    def _window_key(self, scope: str, bucket: int) -> str:
        return f"{self._key_prefix}:{scope}:{bucket}"

    async def try_admit(self, scope: str) -> bool:
        """Atomically consume one admission; False when the window is spent."""
        if self._limit <= 0:
            return True
        from datetime import UTC, datetime

        bucket = int(datetime.now(UTC).timestamp()) // self._window_seconds
        try:
            count = await self._client.eval(
                _ADMIT_LUA, 1, self._window_key(scope, bucket), self._window_seconds
            )
            return int(count) <= self._limit
        except Exception as exc:  # noqa: BLE001 - fail open on any Redis failure
            _logger.warning("scan_rate_limiter_degraded", error=str(exc))
            return True
