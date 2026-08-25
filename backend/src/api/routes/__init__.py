"""API Routes package for SentinelGPT."""

from fastapi import APIRouter

from src.api.routes.auth_routes import router as auth_router
from src.api.routes.health import router as health_router
from src.config.constants import API_V1_STR

api_router = APIRouter(prefix=API_V1_STR)
api_router.include_router(health_router)
api_router.include_router(auth_router)

__all__ = ["api_router", "health_router"]
