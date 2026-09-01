"""Application settings configuration using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Well-known insecure development placeholder. Refused outside local/test so a
# missing environment variable can never silently boot a deployed environment
# with a publicly-known signing key (SRS Chapter 6, Section 5 fail-fast rule;
# Chapter 11, Section 4 secrets policy).
DEVELOPMENT_INSECURE_JWT_SECRET = (
    "development-insecure-secret-key-change-in-production-min-32-chars"
)
MIN_PRODUCTION_SECRET_LENGTH = 32


def _project_root_env_file() -> str | None:
    """Locate the project-root ``.env`` regardless of process CWD.

    When uvicorn is started from ``backend/`` the relative ``.env`` is
    unreachable; the project keeps its single source of truth at
    ``<repo>/.env``. We walk upward from this file until a ``.env`` is
    found, so the same code works whether the process is launched from
    ``SentinelGPT/`` or ``SentinelGPT/backend/``.
    """
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        candidate = parent / ".env"
        if candidate.is_file():
            return str(candidate)
    return None


class Settings(BaseSettings):
    """SentinelGPT Application Settings."""

    model_config = SettingsConfigDict(
        env_file=_project_root_env_file() or ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Core Application Settings
    app_name: str = "SentinelGPT API"
    app_version: str = "0.1.0"
    environment: Literal["local", "test", "staging", "production"] = "local"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # Server Configuration
    host: str = "0.0.0.0"  # nosec B104
    port: int = 8000

    # Logging Configuration
    log_level: str = "INFO"
    log_json: bool = False

    # Database Configuration
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/sentinelgpt",
        description="Async PostgreSQL connection string",
    )
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30

    # Redis Configuration
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for caching",
    )

    # Celery Configuration
    celery_broker_url: str = Field(
        default="redis://localhost:6379/1",
        description="Celery broker connection URL",
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/2",
        description="Celery result backend URL",
    )

    # Gemini AI Configuration
    gemini_api_key: str = Field(
        default="",
        description="Google Gemini API key for evidence-grounded AI explanations",
    )
    gemini_flash_lite_model: str = "gemini-2.0-flash-lite"
    gemini_flash_model: str = "gemini-2.0-flash"
    # Phase 7 execution switch (ADR-0009): the composition root schedules
    # background scan jobs ONLY when this is true. Default OFF keeps the
    # scanner execution gate closed everywhere (dev, tests, first deploy).
    scanner_execution_enabled: bool = Field(
        default=False,
        description="Enable background execution of authorized scans (Phase 7+)",
    )

    # Security & Authentication (Invariants: HttpOnly; Secure; SameSite=Strict cookies)
    jwt_secret_key: str = Field(
        default="development-insecure-secret-key-change-in-production-min-32-chars",
        description="Secret key for signing JWT tokens",
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # CORS Configuration
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    @model_validator(mode="after")
    def validate_deployed_environment_security(self) -> "Settings":
        """Fail fast when a deployed environment would boot insecurely.

        local/test keep full developer ergonomics (insecure placeholder secret,
        debug mode). staging/production refuse to start with the known
        development secret, a short secret, or debug enabled.
        """
        if self.environment in ("staging", "production"):
            secret_is_weak = (
                not self.jwt_secret_key
                or self.jwt_secret_key == DEVELOPMENT_INSECURE_JWT_SECRET
                or len(self.jwt_secret_key) < MIN_PRODUCTION_SECRET_LENGTH
            )
            if secret_is_weak:
                raise ValueError(
                    "JWT_SECRET_KEY must be overridden with a strong, unique "
                    f"secret of at least {MIN_PRODUCTION_SECRET_LENGTH} characters "
                    f"when ENVIRONMENT={self.environment!r}."
                )
            if self.debug:
                raise ValueError(f"DEBUG must be false when ENVIRONMENT={self.environment!r}.")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    return Settings()
