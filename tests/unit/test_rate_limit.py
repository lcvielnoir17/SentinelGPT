"""RedisFixedWindowLimiter behavior tests (ADR-0012).

The limiter is the only admission control on the multi-turn AI path, so
its contract is pinned here:

* at most ``limit`` admissions per user per 60 s window;
* a REJECTED request does not consume budget (no increment);
* keys are per-user — one user exhausting the limit never affects another;
* Redis being unreachable fails OPEN (availability-over-throttling
  decision documented in ADR-0012) — chat throttling must never take down
  the platform;
* ``limit <= 0`` disables the limiter entirely;
* a new minute produces a fresh bucket (window rollover).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from src.domain.conversations import rate_limit as rate_limit_module
from src.domain.conversations.rate_limit import WINDOW_SECONDS, RedisFixedWindowLimiter

USER_1 = "11111111-1111-1111-1111-111111111111"
USER_2 = "22222222-2222-2222-2222-222222222222"


class FakeRedis:
    """Minimal async Redis subset with call recording and a broken mode."""

    def __init__(self, *, broken: bool = False) -> None:
        self.counts: dict[str, int] = {}
        self.expirations: dict[str, int] = {}
        self.broken = broken

    async def get(self, key: str) -> int | None:
        if self.broken:
            raise ConnectionError("redis down")
        return self.counts.get(key)

    async def incr(self, key: str) -> int:
        if self.broken:
            raise ConnectionError("redis down")
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key: str, seconds: int) -> bool:
        if self.broken:
            raise ConnectionError("redis down")
        self.expirations[key] = seconds
        return True


class FakeDateTime(datetime):
    """``datetime`` stand-in whose ``now`` the test controls."""

    current: datetime = datetime.now(UTC)

    @classmethod
    def now(cls, tz: Any = None) -> datetime:
        del tz
        return cls.current


def _limiter(client: FakeRedis, *, limit: int = 3) -> RedisFixedWindowLimiter:
    return RedisFixedWindowLimiter(client, limit=limit)


async def test_admits_up_to_limit_then_rejects() -> None:
    limiter = _limiter(FakeRedis(), limit=3)
    assert [await limiter.try_admit(USER_1) for _ in range(3)] == [True, True, True]
    assert await limiter.try_admit(USER_1) is False


async def test_rejection_does_not_consume_budget() -> None:
    client = FakeRedis()
    limiter = _limiter(client, limit=2)
    await limiter.try_admit(USER_1)
    await limiter.try_admit(USER_1)
    assert await limiter.try_admit(USER_1) is False
    # The counter holds exactly the admitted requests — the rejected call
    # must not have incremented it (key includes the minute bucket).
    assert list(client.counts.values()) == [2]


async def test_per_user_isolation() -> None:
    limiter = _limiter(FakeRedis(), limit=1)
    assert await limiter.try_admit(USER_1) is True
    assert await limiter.try_admit(USER_1) is False
    # A different user is never affected by another user's exhaustion.
    assert await limiter.try_admit(USER_2) is True


async def test_fails_open_when_redis_is_unreachable() -> None:
    limiter = _limiter(FakeRedis(broken=True), limit=1)
    # Both calls succeed despite Redis raising on every operation.
    assert await limiter.try_admit(USER_1) is True
    assert await limiter.try_admit(USER_1) is True


async def test_zero_limit_disables_limiter() -> None:
    client = FakeRedis()
    limiter = _limiter(client, limit=0)
    results = [await limiter.try_admit(USER_1) for _ in range(10)]
    assert results == [True] * 10
    assert client.counts == {}  # never touched Redis


async def test_expire_is_set_to_the_window() -> None:
    client = FakeRedis()
    limiter = _limiter(client, limit=3)
    await limiter.try_admit(USER_1)
    assert set(client.expirations.values()) == {WINDOW_SECONDS}


async def test_window_rollover_starts_a_fresh_bucket(
    mocker,  # type: ignore[no-untyped-def]
) -> None:
    FakeDateTime.current = datetime(2026, 9, 4, 12, 0, 30, tzinfo=UTC)
    mocker.patch.object(rate_limit_module, "datetime", FakeDateTime)
    client = FakeRedis()
    limiter = _limiter(client, limit=1)

    assert await limiter.try_admit(USER_1) is True
    assert await limiter.try_admit(USER_1) is False

    FakeDateTime.current = FakeDateTime.current + timedelta(seconds=WINDOW_SECONDS + 1)
    # New minute bucket → fresh budget, and a distinct Redis key.
    assert await limiter.try_admit(USER_1) is True
    assert len(client.counts) == 2


@pytest.mark.parametrize("limit", [1, 5])
async def test_limit_boundary_is_exact(limit: int) -> None:
    limiter = _limiter(FakeRedis(), limit=limit)
    results = [await limiter.try_admit(USER_1) for _ in range(limit + 1)]
    assert results == [True] * limit + [False]
