"""Unit tests for /healthz and /readyz endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_healthz_endpoint(async_client: AsyncClient) -> None:
    """Test that /healthz returns 200 OK and healthy status without dependency checks."""
    response = await async_client.get("/healthz")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "version" in data
    assert "environment" in data


@pytest.mark.asyncio
async def test_healthz_api_v1_prefix(async_client: AsyncClient) -> None:
    """Test that /api/v1/healthz also responds with 200 OK."""
    response = await async_client.get("/api/v1/healthz")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_readyz_endpoint_all_healthy(async_client: AsyncClient) -> None:
    """Test that /readyz returns 200 OK when DB and Redis connections succeed."""
    with (
        patch(
            "src.api.routes.health.check_database_connection",
            new_callable=AsyncMock,
            return_value={"status": "up"},
        ),
        patch(
            "src.api.routes.health.check_redis_connection",
            new_callable=AsyncMock,
            return_value={"status": "up"},
        ),
    ):
        response = await async_client.get("/readyz")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["components"]["database"]["status"] == "up"
        assert data["components"]["redis"]["status"] == "up"
        assert "gemini" in data["components"]


@pytest.mark.asyncio
async def test_readyz_endpoint_database_down(async_client: AsyncClient) -> None:
    """Test that /readyz returns 503 Service Unavailable when DB is down."""
    with (
        patch(
            "src.api.routes.health.check_database_connection",
            new_callable=AsyncMock,
            return_value={"status": "down", "error": "Connection refused"},
        ),
        patch(
            "src.api.routes.health.check_redis_connection",
            new_callable=AsyncMock,
            return_value={"status": "up"},
        ),
    ):
        response = await async_client.get("/readyz")

        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not_ready"
        assert data["components"]["database"]["status"] == "down"
        assert data["components"]["database"]["error"] == "Connection refused"
        assert data["components"]["redis"]["status"] == "up"


@pytest.mark.asyncio
async def test_readyz_endpoint_redis_down(async_client: AsyncClient) -> None:
    """Test that /readyz returns 503 Service Unavailable when Redis is down."""
    with (
        patch(
            "src.api.routes.health.check_database_connection",
            new_callable=AsyncMock,
            return_value={"status": "up"},
        ),
        patch(
            "src.api.routes.health.check_redis_connection",
            new_callable=AsyncMock,
            return_value={"status": "down", "error": "Redis timeout"},
        ),
    ):
        response = await async_client.get("/readyz")

        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not_ready"
        assert data["components"]["redis"]["status"] == "down"
        assert data["components"]["redis"]["error"] == "Redis timeout"
        assert data["components"]["database"]["status"] == "up"
