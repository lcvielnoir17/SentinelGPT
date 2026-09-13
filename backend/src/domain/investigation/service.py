"""Investigation service: bounded read-only narration (M12).

Orchestration only: validate the question, throttle, build the
bounded evidence view (owner gates inside), narrate through the
existing conversation agent (its timeout/cost protections apply),
and fail closed on provider or validation failure — the deterministic
evidence summary always survives, so an AI outage never becomes a
security-data outage. No database writes occur on any path (no audit
rows either, consistent with the other read-only derived views).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.domain.conversations.errors import ConversationAiUnavailableError
from src.domain.investigation.errors import (
    EmptyQuestionError,
    InvestigationRateLimitedError,
)
from src.domain.investigation.evidence import InvestigationEvidence, build_evidence
from src.domain.investigation.prompts import (
    MAX_QUESTION_CHARS,
    build_evidence_block,
    build_system_instructions,
)
from src.domain.investigation.validator import validate_investigation_response

if TYPE_CHECKING:
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.users.user_service import UserAccount


class InvestigationService:
    """One-shot security Q&A over owned deterministic evidence."""

    def __init__(
        self,
        session: AsyncSession,
        principal: UserAccount,
        *,
        agent_factory: Any | None = None,
        query_limiter: Any | None = None,
    ) -> None:
        self._session = session
        self._principal = principal
        self._agent_factory = agent_factory
        self._limiter = query_limiter

    async def investigate(
        self,
        *,
        target_id: uuid.UUID,
        scan_id: uuid.UUID | None = None,
        question: str,
    ) -> dict[str, Any]:
        """Answer a bounded question from owned evidence (read-only)."""
        clean = _validate_question(question)
        await self._check_limit()
        evidence = await build_evidence(
            self._session, self._principal, target_id=target_id, scan_id=scan_id
        )
        agent = self._resolve_agent()
        if agent is None:
            return _fallback(evidence, detail="AI analyst is not configured")
        try:
            raw = agent.respond(
                system_instructions=build_system_instructions(),
                history=[],
                user_message=clean,
                context_block=build_evidence_block(evidence, question=clean),
            )
        except ConversationAiUnavailableError as exc:
            return _fallback(evidence, detail=str(exc))
        except Exception as exc:  # noqa: BLE001 - any provider fault degrades
            return _fallback(evidence, detail=type(exc).__name__)
        validated = validate_investigation_response(raw, evidence)
        if not validated.accepted or validated.answer is None:
            return _fallback(
                evidence, detail="AI reply failed validation", errors=list(validated.errors)
            )
        return {
            "target_id": evidence.target_id,
            "scan_id": evidence.scan_id,
            "question": clean,
            "evidence": evidence.summary(),
            "answer": validated.answer,
            "provider": {"model": getattr(agent, "model", "unknown")},
            "fallback": False,
        }

    def _resolve_agent(self) -> Any | None:
        """The shared conversation agent (None when unconfigured)."""
        if self._agent_factory is not None:
            try:
                return self._agent_factory()
            except Exception:  # noqa: BLE001 - factory faults degrade
                return None
        from src.api.dependencies import get_conversation_agent

        try:
            return get_conversation_agent()
        except Exception:  # noqa: BLE001 - agent faults degrade
            return None

    async def _check_limit(self) -> None:
        if self._limiter is None:
            return
        if not await self._limiter.try_admit(str(self._principal.id)):
            raise InvestigationRateLimitedError()


def _validate_question(question: object) -> str:
    if not isinstance(question, str):
        raise EmptyQuestionError()
    clean = question.strip()
    if not clean:
        raise EmptyQuestionError()
    if len(question) > MAX_QUESTION_CHARS:
        from src.domain.investigation.errors import InvestigationQuestionTooLongError as TooLong

        raise TooLong()
    return clean


def _fallback(
    evidence: InvestigationEvidence, *, detail: str, errors: list[str] | None = None
) -> dict[str, Any]:
    """Safe deterministic envelope: evidence survives, narration does not."""
    payload: dict[str, Any] = {
        "target_id": evidence.target_id,
        "scan_id": evidence.scan_id,
        "evidence": evidence.summary(),
        "answer": None,
        "provider": {"model": None},
        "fallback": True,
        "detail": detail,
    }
    if errors:
        payload["validation_errors"] = errors
    return payload


__all__ = ["InvestigationService"]
