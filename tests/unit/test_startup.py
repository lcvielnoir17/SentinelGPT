"""Unit tests for FastAPI application startup and configuration."""

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from src.config.settings import Settings, get_settings
from src.main import create_application


def test_create_application() -> None:
    """Test that the application factory builds a valid FastAPI instance."""
    app = create_application()
    assert isinstance(app, FastAPI)
    assert app.title == "SentinelGPT API"
    assert app.version == "0.1.0"


def test_settings_defaults() -> None:
    """Test that default settings conform to SRS requirements."""
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.api_v1_prefix == "/api/v1"
    assert "postgresql+asyncpg" in settings.database_url
    assert "redis://" in settings.redis_url


@pytest.mark.asyncio
async def test_openapi_schema_endpoint(async_client: AsyncClient) -> None:
    """Test that the OpenAPI JSON schema is generated and accessible."""
    response = await async_client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "SentinelGPT API"
    assert "/healthz" in schema["paths"]
    assert "/readyz" in schema["paths"]
