"""API Routes package for SentinelGPT."""

from fastapi import APIRouter

from src.api.routes.attestation_routes import router as attestation_router
from src.api.routes.audit_routes import router as audit_router
from src.api.routes.auth_routes import router as auth_router
from src.api.routes.ci_routes import router as ci_router
from src.api.routes.compliance_routes import router as compliance_router
from src.api.routes.conversation_routes import router as conversation_router
from src.api.routes.dashboard_routes import router as dashboard_router
from src.api.routes.health import router as health_router
from src.api.routes.investigation_routes import router as investigation_router
from src.api.routes.scan_routes import router as scan_router
from src.api.routes.schedule_routes import router as schedule_router
from src.api.routes.target_routes import router as target_router
from src.api.routes.webhook_routes import router as webhook_router
from src.config.constants import API_V1_STR

api_router = APIRouter(prefix=API_V1_STR)
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(target_router)
api_router.include_router(attestation_router)
api_router.include_router(scan_router)
api_router.include_router(schedule_router)
api_router.include_router(audit_router)
api_router.include_router(conversation_router)
api_router.include_router(dashboard_router)
api_router.include_router(webhook_router)
api_router.include_router(compliance_router)
api_router.include_router(ci_router)
api_router.include_router(investigation_router)

__all__ = ["api_router", "health_router"]
