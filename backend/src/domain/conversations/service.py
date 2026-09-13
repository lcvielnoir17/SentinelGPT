"""ConversationService: multi-turn analyst orchestration (ADR-0012).

Turns the scan → findings pipeline into scan → findings → interactive AI
investigation. Responsibilities:

* authorization — every conversation access is checked against the
  canonical user id from the verified session BEFORE any store call;
  cross-owner access is indistinguishable from a missing conversation
  (404, no existence leak);
* context assembly — when a conversation is anchored to a finding, the
  finding and its scan are loaded from PostgreSQL (still the
  authoritative core data), ownership-verified, and rendered into a
  framed, size-capped untrusted block (see prompts.py);
* turn flow — persist the user message, run the Gemini agent OFF the
  event loop, persist the reply; a provider failure leaves the question
  in history so the turn can be retried;
* safeguards — per-message size caps, history windowing, per-user
  per-minute admission via the Redis fixed-window limiter, and a
  per-user conversation quota.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, TypeVar

import structlog

from src.domain.conversations.errors import (
    AiNotConfiguredError,
    ConversationAiUnavailableError,
    ConversationMessageTooLongError,
    ConversationQuotaExceededError,
    ConversationRateLimitedError,
    ConversationStoreUnavailableError,
    EmptyMessageError,
    InvalidComparisonAnchorError,
)
from src.domain.conversations.models import (
    Conversation,
    ConversationMessage,
    new_conversation_id,
    new_message_id,
)
from src.domain.conversations.prompts import (
    ComparisonBrief,
    FindingContext,
    build_comparison_context_block,
    build_context_block,
    build_system_instructions,
)
from src.domain.conversations.store import MAX_MESSAGES_PER_CONVERSATION, ConversationNotFoundError
from src.domain.errors import DomainError, NotFoundError
from src.domain.users.user_service import UserAccount  # noqa: TC001 - runtime annotations

if TYPE_CHECKING:
    import uuid
    from collections.abc import Awaitable, Callable, Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.conversations.rate_limit import RedisFixedWindowLimiter
    from src.domain.conversations.store import ConversationStore

ROLE_ASSISTANT = "assistant"
ROLE_USER = "user"

_T = TypeVar("_T")

_logger = structlog.get_logger(__name__)


def _as_evidence_rows(raw: object) -> list[dict[str, object]]:
    """Narrow the untyped evidence_rows payload from the repository DTO."""
    if isinstance(raw, list):
        return [row for row in raw if isinstance(row, dict)]
    return []


class AnalystAgent(Protocol):
    """The conversational analyst seam (satisfied by GeminiConversationAgent)."""

    def respond(
        self,
        *,
        system_instructions: str,
        history: Sequence[ConversationMessage],
        user_message: str,
        context_block: str | None = None,
    ) -> str: ...


class ConversationService:
    """Application service for user-scoped AI conversations."""

    def __init__(
        self,
        session: AsyncSession,
        store: ConversationStore,
        agent: AnalystAgent | None,
        limiter: RedisFixedWindowLimiter,
        *,
        max_message_chars: int = 8_000,
        max_history_messages: int = 40,
        max_context_chars: int = 12_000,
        agent_timeout_s: float = 50.0,
    ) -> None:
        self._session = session
        self._store = store
        self._agent = agent
        self._limiter = limiter
        self._max_message_chars = max_message_chars
        self._max_history_messages = max_history_messages
        self._max_context_chars = max_context_chars
        self._agent_timeout_s = agent_timeout_s

    # ------------------------------------------------------------------ #
    # Conversation lifecycle                                              #
    # ------------------------------------------------------------------ #

    async def create_conversation(
        self,
        user: UserAccount,
        *,
        title: str | None = None,
        scan_id: uuid.UUID | None = None,
        finding_id: str | None = None,
        compare_scan_a_id: uuid.UUID | None = None,
        compare_scan_b_id: uuid.UUID | None = None,
    ) -> Conversation:
        """Create a conversation owned by ``user``, optionally anchored."""
        if user.firebase_uid is None:
            # Conversations are Firestore-scoped by the verified Firebase
            # UID; accounts that never used the bridge have no scope yet.
            raise ConversationAiUnavailableError("Conversations require Firebase-linked sign-in.")

        # Narrowed once: every store call below scopes under this verified UID.
        uid = user.firebase_uid
        finding = None
        if finding_id is not None:
            finding = await self._load_finding_context(scan_id, finding_id, user.id)
            if finding is None:
                raise NotFoundError()
        elif scan_id is not None:
            if not await self._owns_scan(scan_id, user.id):
                raise NotFoundError()

        if (compare_scan_a_id is None) != (compare_scan_b_id is None):
            raise InvalidComparisonAnchorError()
        if (
            compare_scan_a_id is not None
            and compare_scan_b_id is not None
            and not await self._owns_comparison(compare_scan_a_id, compare_scan_b_id, user.id)
        ):
            raise NotFoundError()

        from src.domain.conversations.store import MAX_CONVERSATIONS_PER_USER

        stored_count = await self._guarded_store(
            "count_conversations",
            None,
            lambda: self._store.count_conversations(uid),
        )
        if stored_count >= MAX_CONVERSATIONS_PER_USER:
            raise ConversationQuotaExceededError()

        resolved_title = (
            title
            or (finding.title if finding else None)
            or ("Scan comparison" if compare_scan_a_id is not None else "Security conversation")
        )[:120]
        conversation = Conversation(
            id=new_conversation_id(),
            user_id=user.id,
            firebase_uid=uid,
            title=resolved_title,
            scan_id=scan_id,
            finding_id=finding_id,
            compare_scan_a_id=compare_scan_a_id,
            compare_scan_b_id=compare_scan_b_id,
        )
        return await self._guarded_store(
            "create_conversation",
            conversation.id,
            lambda: self._store.create_conversation(conversation),
        )

    async def list_conversations(self, user: UserAccount, *, limit: int = 50) -> list[Conversation]:
        if user.firebase_uid is None:
            return []
        uid = user.firebase_uid
        return await self._guarded_store(
            "list_conversations",
            None,
            lambda: self._store.list_conversations(uid, limit=limit),
        )

    async def get_conversation(
        self, user: UserAccount, conversation_id: str
    ) -> tuple[Conversation, list[ConversationMessage]]:
        conversation, uid = await self._require_owned(user, conversation_id)
        messages = await self._guarded_store(
            "list_messages",
            conversation_id,
            lambda: self._store.list_messages(
                uid, conversation_id, limit=MAX_MESSAGES_PER_CONVERSATION
            ),
        )
        return conversation, messages

    async def delete_conversation(self, user: UserAccount, conversation_id: str) -> bool:
        _, uid = await self._require_owned(user, conversation_id)
        return await self._guarded_store(
            "delete_conversation",
            conversation_id,
            lambda: self._store.delete_conversation(uid, conversation_id),
        )

    # ------------------------------------------------------------------ #
    # Turn flow                                                           #
    # ------------------------------------------------------------------ #

    async def send_message(
        self, user: UserAccount, conversation_id: str, content: str
    ) -> tuple[ConversationMessage, ConversationMessage]:
        """One multi-turn exchange: persist question, answer, persist reply."""
        if not content.strip():
            raise EmptyMessageError()
        if len(content) > self._max_message_chars:
            raise ConversationMessageTooLongError()
        if self._agent is None:
            raise AiNotConfiguredError()

        conversation, uid = await self._require_owned(user, conversation_id)
        if not await self._limiter.try_admit(user.id):
            raise ConversationRateLimitedError()

        context_block = await self._build_context_block(user, conversation)
        history = (
            await self._guarded_store(
                "list_messages",
                conversation_id,
                lambda: self._store.list_messages(uid, conversation_id),
            )
        )[-self._max_history_messages :]

        now = datetime.now(UTC)
        user_message = ConversationMessage(
            id=new_message_id(), role=ROLE_USER, content=content, created_at=now
        )
        stored_user_message = await self._guarded_store(
            "append_message",
            conversation_id,
            lambda: self._store.append_message(uid, conversation_id, user_message),
        )

        try:
            reply_text = await asyncio.wait_for(
                asyncio.to_thread(self._invoke_agent, context_block, history, content),
                timeout=self._agent_timeout_s,
            )
        except TimeoutError as exc:
            # A slow Gemini turn must surface as a retryable 503 — the
            # question is already persisted, so the user can retry without
            # losing it. Only the failure kind is logged, never content.
            _logger.warning(
                "conversation_agent_timeout",
                conversation_id=conversation_id,
                timeout_s=self._agent_timeout_s,
            )
            raise ConversationAiUnavailableError("analyst timed out") from exc
        # A fresh timestamp after generation keeps turn ordering strictly
        # chronological (both messages could otherwise share a clock tick).
        assistant_message = ConversationMessage(
            id=new_message_id(),
            role=ROLE_ASSISTANT,
            content=reply_text,
            created_at=datetime.now(UTC),
        )
        stored_assistant_message = await self._guarded_store(
            "append_message",
            conversation_id,
            lambda: self._store.append_message(uid, conversation_id, assistant_message),
        )
        return stored_user_message, stored_assistant_message

    # ------------------------------------------------------------------ #
    # Internals                                                           #
    # ------------------------------------------------------------------ #

    async def _guarded_store(
        self, operation: str, conversation_id: str | None, call: Callable[[], Awaitable[_T]]
    ) -> _T:
        """Run one store call, translating persistence outages to a 503.

        ``ConversationNotFoundError`` (unknown id in the caller's own scope)
        and domain errors pass through untouched so 404/409 semantics hold;
        any other persistence failure becomes the controlled
        ``CONVERSATION_UNAVAILABLE`` envelope instead of a 500.
        """
        try:
            return await call()
        except (ConversationNotFoundError, DomainError):
            raise
        except Exception as exc:
            _logger.error(
                "conversation_store_failed",
                operation=operation,
                conversation_id=conversation_id,
                error=type(exc).__name__,
            )
            raise ConversationStoreUnavailableError() from exc

    def _invoke_agent(
        self, context_block: str | None, history: Sequence[ConversationMessage], content: str
    ) -> str:

        agent = self._agent
        assert agent is not None
        try:
            reply: str = agent.respond(
                system_instructions=build_system_instructions(),
                history=history,
                user_message=content,
                context_block=context_block,
            )
            return reply
        except ConversationAiUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - provider failures must not 500
            raise ConversationAiUnavailableError(type(exc).__name__) from exc

    async def _require_owned(
        self, user: UserAccount, conversation_id: str
    ) -> tuple[Conversation, str]:
        """Load a conversation the caller owns; returns (conversation, uid)."""
        if user.firebase_uid is None:
            raise NotFoundError()
        uid = user.firebase_uid
        conversation = await self._guarded_store(
            "get_conversation",
            conversation_id,
            lambda: self._store.get_conversation(uid, conversation_id),
        )
        if (
            conversation is None
            or conversation.user_id != user.id
            or conversation.firebase_uid != user.firebase_uid
        ):
            # Cross-owner access and unknown ids are identical (no leak).
            raise NotFoundError()
        return conversation, user.firebase_uid

    async def _owns_scan(self, scan_id: uuid.UUID, user_id: uuid.UUID) -> bool:
        from src.infrastructure.database.repositories.scan_repository import ScanRepository

        scan = await ScanRepository(self._session).get_by_id(scan_id)
        return scan is not None and scan.initiated_by_user_id == user_id

    async def _owns_comparison(
        self, scan_a_id: uuid.UUID, scan_b_id: uuid.UUID, user_id: uuid.UUID
    ) -> bool:
        """Both scans visible to the user and targeting the same asset."""
        from src.infrastructure.database.repositories.scan_repository import ScanRepository

        repository = ScanRepository(self._session)
        scan_a = await repository.get_by_id(scan_a_id)
        scan_b = await repository.get_by_id(scan_b_id)
        return (
            scan_a is not None
            and scan_b is not None
            and scan_a.initiated_by_user_id == user_id
            and scan_b.initiated_by_user_id == user_id
            and scan_a.target_id == scan_b.target_id
        )

    async def _load_finding_context(
        self, scan_id: uuid.UUID | None, finding_id: str, user_id: uuid.UUID
    ) -> FindingContext | None:
        """Load finding + scan metadata with strict ownership verification."""
        import uuid as uuid_module

        from src.infrastructure.database.repositories.scan_repository import (
            ScanEngineExecutionRepository,
            ScanRepository,
        )

        try:
            finding_uuid = uuid_module.UUID(finding_id)
        except ValueError:
            return None

        finding_row = await ScanEngineExecutionRepository(self._session).get_finding_with_evidence(
            finding_uuid
        )
        if finding_row is None:
            return None

        # The finding's owning scan comes from its persisted denormalized
        # scan_id; ownership is verified against it before any context is
        # exposed.
        from sqlalchemy import select

        from src.infrastructure.database.models import ScanFinding

        row = (
            await self._session.execute(
                select(ScanFinding.scan_id).where(ScanFinding.id == finding_uuid)
            )
        ).first()
        if row is None or row.scan_id is None:
            return None
        finding_scan_id = row.scan_id
        if scan_id is not None and finding_scan_id != scan_id:
            # The caller anchored the conversation to a different scan than
            # the finding belongs to; reject rather than mislabel context.
            return None

        scan = await ScanRepository(self._session).get_by_id(finding_scan_id)
        if scan is None or scan.initiated_by_user_id != user_id:
            return None

        from src.infrastructure.database.repositories.scan_repository import (
            _profile_code,
            _status_code_of,
        )

        profile = await _profile_code(self._session, scan.scan_profile_id)
        status = await _status_code_of(self._session, scan.status_id)

        return FindingContext(
            scan_id=str(scan.id),
            scan_profile=profile,
            scan_status=status,
            finding_id=str(finding_row["id"]),
            title=str(finding_row["title"]),
            severity=str(finding_row["severity"]),
            category=str(finding_row["category"]),
            location=str(finding_row["location"] or ""),
            description=str(finding_row["description"] or ""),
            evidence=str(finding_row["evidence"] or ""),
            recommendation=str(finding_row["recommendation"] or ""),
            evidence_rows=tuple(
                (str(row["type"]), str(row["content"] or ""))
                for row in _as_evidence_rows(finding_row.get("evidence_rows"))
            ),
        )

    async def _build_context_block(
        self, user: UserAccount, conversation: Conversation
    ) -> str | None:
        if conversation.finding_id is not None and conversation.scan_id is not None:
            # Ownership was already verified at creation and re-checked per turn
            # via _require_owned; the scan/finding load is scoped to the
            # conversation's stored ids, which only its owner can reach.
            context = await self._load_finding_context(
                conversation.scan_id, conversation.finding_id, conversation.user_id
            )
            if context is None:
                return None
            return build_context_block(context, max_field_chars=self._max_context_chars)
        if (
            conversation.compare_scan_a_id is not None
            and conversation.compare_scan_b_id is not None
        ):
            brief = await self._load_comparison_brief(
                user,
                conversation.compare_scan_a_id,
                conversation.compare_scan_b_id,
            )
            if brief is None:
                return None
            return build_comparison_context_block(brief, max_field_chars=self._max_context_chars)
        return None

    async def _load_comparison_brief(
        self, user: UserAccount, scan_a_id: uuid.UUID, scan_b_id: uuid.UUID
    ) -> ComparisonBrief | None:
        """Deterministic comparison brief, rebuilt fresh every turn.

        Ownership gates run inside ``compare_scans_detailed`` (invisible
        scans are 404, cross-target pairs rejected); any failure degrades
        to no comparison context rather than leaking or blocking chat.
        """
        from src.domain.scans.scan_service import ScanService

        try:
            detailed = await ScanService(self._session, user).compare_scans_detailed(
                scan_a_id, scan_b_id
            )
        except Exception:  # noqa: BLE001 - degraded context, never a 500
            return None
        summary = detailed.get("summary")
        records = detailed.get("records")
        if not isinstance(summary, dict) or not isinstance(records, list):
            return None
        severity_changed: list[str] = []
        regressed: list[str] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            title = record.get("title")
            if not isinstance(title, str) or not title:
                continue
            if record.get("severity_changed") is True and len(severity_changed) < 10:
                severity_changed.append(title)
            if record.get("lifecycle_status") == "REGRESSED" and len(regressed) < 10:
                regressed.append(title)
        return ComparisonBrief(
            scan_a_id=str(scan_a_id),
            scan_b_id=str(scan_b_id),
            new_count=int(summary.get("new_count", 0) or 0),
            persistent_count=int(summary.get("persistent_count", 0) or 0),
            resolved_count=int(summary.get("resolved_count", 0) or 0),
            regressed_count=int(summary.get("regressed_count", 0) or 0),
            severity_changed=tuple(severity_changed),
            regressions=tuple(regressed),
        )
