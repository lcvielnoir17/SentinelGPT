/**
 * Conversational-analyst API bindings (ADR-0011/0012 response shapes).
 *
 * All requests ride the cookie session through the central API client.
 * Conversation ids are opaque server-generated strings; ownership is
 * enforced server-side, so cross-owner ids simply 404.
 */

import { apiRequest } from "../../../services/apiClient";

/**
 * Bounded waits for the analyst feature so the panel can never spin
 * forever: fast metadata calls get a short leash, while a Gemini turn —
 * which legitimately runs up to the backend's agent timeout — gets a
 * longer one that still guarantees a terminal UI state.
 */
export const CONVERSATION_REQUEST_TIMEOUT_MS = 30_000;
export const SEND_MESSAGE_TIMEOUT_MS = 100_000;

export type MessageRole = "user" | "assistant";

export interface ConversationMessageDto {
  id: string;
  role: MessageRole;
  content: string;
  sequence: number | null;
  createdAt: string;
}

export interface ConversationDto {
  id: string;
  title: string;
  userId: string;
  scanId: string | null;
  findingId: string | null;
  compareScanAId?: string | null;
  compareScanBId?: string | null;
  messageCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface ConversationDetailDto extends ConversationDto {
  messages: ConversationMessageDto[];
}

export interface SendMessageResponseDto {
  userMessage: ConversationMessageDto;
  assistantMessage: ConversationMessageDto;
}

export function createConversation(payload: {
  title?: string;
  scanId?: string;
  findingId?: string;
  compareScanAId?: string;
  compareScanBId?: string;
}): Promise<ConversationDto> {
  return apiRequest<ConversationDto>("/conversations", {
    method: "POST",
    body: payload,
    timeoutMs: CONVERSATION_REQUEST_TIMEOUT_MS,
  });
}

export function listConversations(limit = 50): Promise<ConversationDto[]> {
  return apiRequest<ConversationDto[]>(`/conversations?limit=${limit}`, {
    timeoutMs: CONVERSATION_REQUEST_TIMEOUT_MS,
  });
}

export function getConversation(id: string): Promise<ConversationDetailDto> {
  return apiRequest<ConversationDetailDto>(`/conversations/${id}`, {
    timeoutMs: CONVERSATION_REQUEST_TIMEOUT_MS,
  });
}

export function deleteConversation(id: string): Promise<void> {
  return apiRequest<void>(`/conversations/${id}`, {
    method: "DELETE",
    timeoutMs: CONVERSATION_REQUEST_TIMEOUT_MS,
  });
}

export function sendMessage(id: string, content: string): Promise<SendMessageResponseDto> {
  return apiRequest<SendMessageResponseDto>(`/conversations/${id}/messages`, {
    method: "POST",
    body: { content },
    timeoutMs: SEND_MESSAGE_TIMEOUT_MS,
  });
}
