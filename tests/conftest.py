"""Pytest configuration and shared test fixtures."""

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from src.config.settings import Settings
from src.main import create_application


@pytest.fixture
def test_settings() -> Settings:
    """Provide test-specific application settings."""
    return Settings(
        environment="test",
        debug=True,
        database_url="postgresql+asyncpg://postgres:postgres@localhost:5432/sentinelgpt_test",
        redis_url="redis://localhost:6379/15",
        jwt_secret_key="test-secret-key-must-be-at-least-32-chars-long",
    )


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Provide an asynchronous HTTP client for testing endpoints."""
    app = create_application()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
