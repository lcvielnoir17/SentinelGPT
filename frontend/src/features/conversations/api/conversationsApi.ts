/**
 * Conversational-analyst API bindings (ADR-0011/0012 response shapes).
 *
 * All requests ride the cookie session through the central API client.
 * Conversation ids are opaque server-generated strings; ownership is
 * enforced server-side, so cross-owner ids simply 404.
 */

import { apiRequest } from "../../../services/apiClient";

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
}): Promise<ConversationDto> {
  return apiRequest<ConversationDto>("/conversations", {
    method: "POST",
    body: payload,
  });
}

export function listConversations(limit = 50): Promise<ConversationDto[]> {
  return apiRequest<ConversationDto[]>(`/conversations?limit=${limit}`);
}

export function getConversation(id: string): Promise<ConversationDetailDto> {
  return apiRequest<ConversationDetailDto>(`/conversations/${id}`);
}

export function deleteConversation(id: string): Promise<void> {
  return apiRequest<void>(`/conversations/${id}`, { method: "DELETE" });
}

export function sendMessage(id: string, content: string): Promise<SendMessageResponseDto> {
  return apiRequest<SendMessageResponseDto>(`/conversations/${id}/messages`, {
    method: "POST",
    body: { content },
  });
}
