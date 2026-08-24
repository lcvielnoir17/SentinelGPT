"""Application settings configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SentinelGPT Application Settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
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


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    return Settings()
