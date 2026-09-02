"""Health check and readiness verification routes."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from src.config.settings import Settings, get_settings
from src.infrastructure.cache.redis_client import check_redis_connection
from src.infrastructure.database.connection import check_database_connection
from src.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Liveness probe response."""

    status: str = Field(description="Liveness status indicator", examples=["healthy"])
    timestamp: str = Field(description="ISO 8601 UTC timestamp", examples=["2026-08-24T00:00:00Z"])
    version: str = Field(description="Application version", examples=["0.1.0"])
    environment: str = Field(description="Runtime environment name", examples=["local"])


class ComponentHealth(BaseModel):
    """Individual component readiness detail."""

    status: str = Field(description="Component status indicator", examples=["up"])
    details: dict[str, Any] | None = Field(default=None, description="Optional diagnostic details")
    error: str | None = Field(default=None, description="Error message if component is degraded")


class ReadinessResponse(BaseModel):
    """Readiness probe response."""

    status: str = Field(description="Overall readiness status", examples=["ready", "not_ready"])
    timestamp: str = Field(description="ISO 8601 UTC timestamp", examples=["2026-08-24T00:00:00Z"])
    version: str = Field(description="Application version", examples=["0.1.0"])
    environment: str = Field(description="Runtime environment name", examples=["local"])
    components: dict[str, ComponentHealth] = Field(
        description="Health status of downstream dependencies"
    )


@router.get(
    "/healthz",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Liveness Probe",
    description="Returns 200 if the process is up and running. No external dependencies are checked.",
)
async def healthz() -> HealthResponse:
    """Liveness probe endpoint."""
    settings: Settings = get_settings()
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(UTC).isoformat(),
        version=settings.app_version,
        environment=settings.environment,
    )


@router.get(
    "/readyz",
    response_model=ReadinessResponse,
    status_code=status.HTTP_200_OK,
    summary="Readiness Probe",
    description="Verifies that database, cache, and configuration dependencies are healthy and ready to serve traffic.",
)
async def readyz(response: Response) -> ReadinessResponse:
    """Readiness probe endpoint checking DB, Redis, and configuration readiness."""
    settings: Settings = get_settings()
    timestamp = datetime.now(UTC).isoformat()

    # 1. Check Database connectivity
    db_result = await check_database_connection()
    db_status = db_result.get("status", "down")
    db_error = db_result.get("error")

    # 2. Check Redis connectivity
    redis_result = await check_redis_connection()
    redis_status = redis_result.get("status", "down")
    redis_error = redis_result.get("error")

    # 3. Check AI / Gemini configuration readiness
    from src.infrastructure.secrets import get_gemini_api_key

    gemini_configured = bool(get_gemini_api_key())
    gemini_status = "up" if gemini_configured else "not_configured"
    gemini_details: dict[str, Any] = {
        "flash_lite_model": settings.gemini_flash_lite_model,
        "flash_model": settings.gemini_flash_model,
        "configured": gemini_configured,
    }

    components: dict[str, ComponentHealth] = {
        "database": ComponentHealth(
            status=db_status,
            error=db_error,
        ),
        "redis": ComponentHealth(
            status=redis_status,
            error=redis_error,
        ),
        "gemini": ComponentHealth(
            status=gemini_status,
            details=gemini_details,
        ),
    }

    # Core readiness requires database and redis to be operational
    is_ready = db_status == "up" and redis_status == "up"

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        overall_status = "not_ready"
    else:
        overall_status = "ready"

    return ReadinessResponse(
        status=overall_status,
        timestamp=timestamp,
        version=settings.app_version,
        environment=settings.environment,
        components=components,
    )
