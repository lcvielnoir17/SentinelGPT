"""SentinelGPT FastAPI application entry point."""

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.api.middlewares.error_handlers import register_exception_handlers
from src.api.routes import api_router
from src.api.routes.health import router as health_router
from src.config.settings import Settings, get_settings
from src.infrastructure.cache.redis_client import close_redis_client
from src.infrastructure.database.connection import close_database_engine
from src.infrastructure.logging.logger import configure_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Application lifecycle manager for startup and shutdown hooks."""
    settings = get_settings()
    configure_logging(log_level=settings.log_level, log_json=settings.log_json)
    logger.info(
        "sentinelgpt_api_startup",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
    )
    yield
    logger.info("sentinelgpt_api_shutdown_commencing")
    await close_database_engine()
    await close_redis_client()
    logger.info("sentinelgpt_api_shutdown_completed")


def create_application() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    settings: Settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description="SentinelGPT: AI-Powered Vulnerability Analysis Platform",
        version=settings.app_version,
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Configure CORS (allow_credentials=True for HttpOnly cookie auth)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Correlation ID & Request Logging Middleware
    @app.middleware("http")
    async def request_logging_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id  # reused by error handlers
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )

        start_time = time.perf_counter()
        try:
            response = await call_next(request)
            process_time = time.perf_counter() - start_time
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = f"{process_time:.4f}"
            logger.info(
                "http_request_finished",
                status_code=response.status_code,
                duration_ms=round(process_time * 1000, 2),
            )
            return response
        except Exception as exc:
            process_time = time.perf_counter() - start_time
            logger.exception("unhandled_http_exception", error=str(exc))
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": {
                        "code": "INTERNAL_SERVER_ERROR",
                        "message": "An unexpected internal server error occurred.",
                        "requestId": request_id,
                    }
                },
                headers={"X-Request-ID": request_id},
            )

    # Centralized error-envelope handlers (SRS Chapter 5, Section 14)
    register_exception_handlers(app)

    # Include Routes: operational probes stay unprefixed (Chapter 6, Section 10);
    # versioned business routes mount under /api/v1 (Chapter 5, Section 1).
    app.include_router(health_router)
    app.include_router(api_router)

    return app


app = create_application()
