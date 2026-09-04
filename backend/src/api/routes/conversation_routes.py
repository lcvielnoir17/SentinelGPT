"""Conversational analyst endpoints (ADR-0011/0012).

Every route requires authentication; the identity comes exclusively from
the verified session cookie, and all Firestore access is scoped under that
identity's Firebase UID. Cross-owner conversation ids answer the same 404
envelope as unknown ids (no existence leak).

Routes (prefix ``/conversations``):
* POST   ````                    create a conversation (optionally anchored
                                 to a scan/finding the caller owns)
* GET    ````                    list the caller's conversations
* GET    ``/{conversation_id}``  conversation + message history
* DELETE ``/{conversation_id}``  delete conversation and messages (204)
* POST   ``/{conversation_id}/messages``  submit a message, receive the
                                 assistant reply (multi-turn Gemini)
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from src.api.dependencies import (
    CurrentUser,
    SessionDep,
    get_conversation_agent,
    get_conversation_store,
    get_rate_limiter,
)
from src.config.settings import get_settings
from src.domain.conversations.models import (  # noqa: TC001 - FastAPI runtime
    Conversation,
    ConversationMessage,
)
from src.domain.conversations.rate_limit import RedisFixedWindowLimiter  # noqa: TC001
from src.domain.conversations.service import AnalystAgent, ConversationService  # noqa: TC001
from src.domain.conversations.store import ConversationStore  # noqa: TC001 - FastAPI runtime

router = APIRouter(prefix="/conversations", tags=["Conversations"])

# Hard request-body cap; the service enforces the configured per-message
# cap (settings.conversation_max_message_chars) on top of this.
HARD_MESSAGE_CAP = 16_384


# --------------------------------------------------------------------- #
# DTOs                                                                  #
# --------------------------------------------------------------------- #


class CreateConversationRequest(BaseModel):
    title: str | None = Field(default=None, max_length=120)
    scan_id: uuid.UUID | None = Field(default=None, validation_alias="scanId")
    finding_id: str | None = Field(default=None, validation_alias="findingId", max_length=64)


class ConversationResponse(BaseModel):
    id: str
    title: str
    user_id: uuid.UUID = Field(serialization_alias="userId")
    scan_id: uuid.UUID | None = Field(default=None, serialization_alias="scanId")
    finding_id: str | None = Field(default=None, serialization_alias="findingId")
    message_count: int = Field(serialization_alias="messageCount")
    created_at: datetime = Field(serialization_alias="createdAt")
    updated_at: datetime = Field(serialization_alias="updatedAt")


class MessageResponse(BaseModel):
    id: str
    role: str
    content: str
    created_at: datetime = Field(serialization_alias="createdAt")


class ConversationDetailResponse(ConversationResponse):
    messages: list[MessageResponse]


class SendMessageRequest(BaseModel):
    content: str = Field(min_length=1, max_length=HARD_MESSAGE_CAP)


class SendMessageResponse(BaseModel):
    user_message: MessageResponse = Field(serialization_alias="userMessage")
    assistant_message: MessageResponse = Field(serialization_alias="assistantMessage")


# --------------------------------------------------------------------- #
# Helpers                                                               #
# --------------------------------------------------------------------- #


def _to_response(conversation: Conversation) -> ConversationResponse:
    return ConversationResponse(
        id=conversation.id,
        title=conversation.title,
        user_id=conversation.user_id,
        scan_id=conversation.scan_id,
        finding_id=conversation.finding_id,
        message_count=conversation.message_count,
        created_at=conversation.created_at,
        updated_at=conversation.updated_at,
    )


def _to_message_response(message: ConversationMessage) -> MessageResponse:
    return MessageResponse(
        id=message.id,
        role=message.role,
        content=message.content,
        created_at=message.created_at,
    )


def _service(
    session: SessionDep,
    store: Annotated[ConversationStore, Depends(get_conversation_store)],
    agent: Annotated[AnalystAgent | None, Depends(get_conversation_agent)],
    limiter: Annotated[RedisFixedWindowLimiter, Depends(get_rate_limiter)],
) -> ConversationService:
    settings = get_settings()
    return ConversationService(
        session,
        store,
        agent,
        limiter,
        max_message_chars=settings.conversation_max_message_chars,
        max_history_messages=settings.conversation_max_history_messages,
        max_context_chars=settings.conversation_max_context_chars,
    )


ServiceDep = Annotated[ConversationService, Depends(_service)]


# --------------------------------------------------------------------- #
# Endpoints                                                             #
# --------------------------------------------------------------------- #


@router.post(
    "",
    response_model=ConversationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a conversation (optionally anchored to a scan/finding)",
)
async def create_conversation(
    payload: CreateConversationRequest | None, user: CurrentUser, service: ServiceDep
) -> ConversationResponse:
    conversation = await service.create_conversation(
        user,
        title=payload.title if payload else None,
        scan_id=payload.scan_id if payload else None,
        finding_id=payload.finding_id if payload else None,
    )
    return _to_response(conversation)


@router.get(
    "",
    response_model=list[ConversationResponse],
    summary="List the caller's conversations (most recent first)",
)
async def list_conversations(
    user: CurrentUser,
    service: ServiceDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> list[ConversationResponse]:
    conversations = await service.list_conversations(user, limit=limit)
    return [_to_response(c) for c in conversations]


@router.get(
    "/{conversation_id}",
    response_model=ConversationDetailResponse,
    summary="Retrieve a conversation with its full message history",
)
async def get_conversation(
    conversation_id: str, user: CurrentUser, service: ServiceDep
) -> ConversationDetailResponse:
    conversation, messages = await service.get_conversation(user, conversation_id)
    return ConversationDetailResponse(
        **_to_response(conversation).model_dump(),
        messages=[_to_message_response(m) for m in messages],
    )


@router.delete(
    "/{conversation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a conversation and its messages",
)
async def delete_conversation(conversation_id: str, user: CurrentUser, service: ServiceDep) -> None:
    deleted = await service.delete_conversation(user, conversation_id)
    if not deleted:
        # Ownership was already verified; a False here means an unknown id.
        from src.domain.errors import NotFoundError

        raise NotFoundError()


@router.post(
    "/{conversation_id}/messages",
    response_model=SendMessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a message and receive the assistant reply",
    description=(
        "Multi-turn exchange with the Gemini security analyst. The user "
        "message is persisted first, then the reply is generated with the "
        "conversation history (and any anchored finding context). A 503 "
        "AI_UNAVAILABLE leaves the question in history for retry."
    ),
)
async def send_message(
    conversation_id: str,
    payload: SendMessageRequest,
    user: CurrentUser,
    service: ServiceDep,
) -> SendMessageResponse:
    # Blank content is rejected by the request schema; the service re-checks
    # and raises the structured 400 envelope if it slips through.
    user_message, assistant_message = await service.send_message(
        user, conversation_id, payload.content
    )
    return SendMessageResponse(
        user_message=_to_message_response(user_message),
        assistant_message=_to_message_response(assistant_message),
    )
