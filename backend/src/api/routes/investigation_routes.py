"""AI investigation endpoint (read-only narrator over owned evidence).

One-shot Q&A: the caller names an owned target (optionally one of its
scans) and asks a bounded security question. The deterministic
evidence view is always returned; the AI narration is validated
against that view and dropped on any failure. Unauthenticated callers
get 401; foreign targets/scans get 404 through the existing gates.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from src.api.dependencies import CurrentUser, SessionDep  # noqa: TC001 - FastAPI runtime
from src.domain.investigation.service import InvestigationService

router = APIRouter(prefix="/investigations", tags=["Investigations"])


class InvestigationRequest(BaseModel):
    """POST /investigations/query body."""

    target_id: uuid.UUID = Field(validation_alias="targetId")
    scan_id: uuid.UUID | None = Field(default=None, validation_alias="scanId")
    question: str = Field(min_length=1, max_length=2000)


@router.post("/query", summary="Ask a bounded question about owned evidence")
async def query_investigation(
    payload: InvestigationRequest,
    session: SessionDep,
    current_user: CurrentUser,
) -> dict[str, Any]:
    """Narrate deterministic evidence (validated) or fall back to the data.

    Read-only: no finding, remediation, evidence, scan, target, or
    compliance writes occur on any path, and no audit rows are minted
    for reads (consistent with posture/compliance views).
    """
    return await _service(session, current_user).investigate(
        target_id=payload.target_id,
        scan_id=payload.scan_id,
        question=payload.question,
    )


def _service(session: Any, current_user: Any) -> InvestigationService:
    from src.config.settings import get_settings
    from src.domain.scans.rate_limit import RedisAtomicRateLimiter
    from src.infrastructure.cache.redis_client import get_redis_client

    settings = get_settings()
    return InvestigationService(
        session,
        current_user,
        query_limiter=RedisAtomicRateLimiter(
            get_redis_client(),
            key_prefix="sgpt:investigation",
            limit=settings.investigation_limit_per_minute,
            window_seconds=60,
        ),
    )


__all__ = ["router"]
