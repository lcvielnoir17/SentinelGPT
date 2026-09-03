/**
 * Chat panel for one finding (ADR-0012 demo flow: finding → Ask
 * SentinelGPT → multi-turn Gemini analysis).
 *
 * The conversation is created lazily with the first question, anchored to
 * the finding's scan. Ownership is server-side; this component only ever
 * talks about the scan/finding already shown to the authenticated user.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../../../services/apiClient";
import {
  createConversation,
  getConversation,
  listConversations,
  sendMessage,
} from "../api/conversationsApi";
import type { ConversationMessageDto } from "../api/conversationsApi";

const MAX_MESSAGE_CHARS = 8_000;

export function ConversationPanel({
  scanId,
  findingId,
}: {
  scanId: string;
  findingId: string;
}) {
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ConversationMessageDto[]>([]);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastMessageRef = useRef<HTMLDivElement | null>(null);
  // Server-truth id behind the state, plus single-flight resolution so the
  // mount-time reconnect and a first send never create two conversations.
  const conversationIdRef = useRef<string | null>(null);
  const resolvingRef = useRef<Promise<string> | null>(null);

  useEffect(() => {
    if (messages.length === 0) return;
    lastMessageRef.current?.scrollIntoView({ block: "nearest" });
  }, [messages]);

  const loadHistory = useCallback(async (id: string) => {
    setLoading(true);
    try {
      const detail = await getConversation(id);
      setMessages(detail.messages);
    } catch {
      // History is best-effort; the turn flow surfaces real errors.
    } finally {
      setLoading(false);
    }
  }, []);

  const resolveConversation = useCallback((): Promise<string> => {
    if (conversationIdRef.current !== null) {
      return Promise.resolve(conversationIdRef.current);
    }
    if (resolvingRef.current === null) {
      resolvingRef.current = (async () => {
        // Reconnect to the conversation this finding already has (persistence
        // across panel close/reopen and page reloads) before creating one.
        const existing = await listConversations(50);
        const known = existing.find(
          (c) => c.findingId === findingId && c.scanId === scanId,
        );
        const id =
          known?.id ??
          (await createConversation({ scanId, findingId })).id;
        conversationIdRef.current = id;
        setConversationId(id);
        return id;
      })().finally(() => {
        resolvingRef.current = null;
      });
    }
    return resolvingRef.current;
  }, [findingId, scanId]);

  // Reconnect on mount so a reopened panel shows the prior thread. Local
  // messages always win over a stale history fetch (a send may be in flight).
  useEffect(() => {
    let cancelled = false;
    void resolveConversation()
      .then(async (id) => {
        if (cancelled || conversationIdRef.current !== id) return;
        const detail = await getConversation(id);
        if (!cancelled) {
          setMessages((prev) => (prev.length > 0 ? prev : detail.messages));
        }
      })
      .catch(() => {
        // Best-effort: creation happens on first send instead.
      });
    return () => {
      cancelled = true;
    };
  }, [resolveConversation]);

  const submitDraft = useCallback(async () => {
    const content = draft.trim();
    if (!content || sending) return;
    setError(null);
    setSending(true);
    setDraft("");
    try {
      const id = await resolveConversation();
      const response = await sendMessage(id, content);
      setMessages((prev) => [...prev, response.userMessage, response.assistantMessage]);
    } catch (err) {
      setDraft(content);
      if (err instanceof ApiError) {
        setError(
          err.code === "AI_NOT_CONFIGURED"
            ? "AI analysis is not configured on this deployment."
            : err.message,
        );
      } else {
        setError("The AI analyst is unreachable; try again.");
      }
    } finally {
      setSending(false);
    }
  }, [draft, resolveConversation, sending]);

  return (
    <div className="chat-panel" aria-label="SentinelGPT analyst conversation">
      <div className="chat-messages">
        {loading && <p className="muted small">Loading conversation…</p>}
        {messages.length === 0 && !loading && (
          <p className="muted small chat-empty">
            Ask about this finding: why it matters, real-world impact, whether it is
            exploitable, or how to fix it.
          </p>
        )}
        {messages.map((m) => (
          <div key={m.id} className={`chat-message chat-${m.role}`}>
            <span className="chat-role">{m.role === "user" ? "You" : "SentinelGPT"}</span>
            <p>{m.content}</p>
          </div>
        ))}
        {sending && (
          <div className="chat-message chat-assistant chat-pending" aria-live="polite">
            <span className="chat-role">SentinelGPT</span>
            <p>Thinking…</p>
          </div>
        )}
        <div ref={lastMessageRef} />
      </div>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      <form
        className="chat-input"
        onSubmit={(e) => {
          e.preventDefault();
          void submitDraft();
        }}
      >
        <textarea
          value={draft}
          maxLength={MAX_MESSAGE_CHARS}
          placeholder="Ask the analyst…"
          rows={2}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void submitDraft();
            }
          }}
        />
        <button type="submit" disabled={sending || draft.trim().length === 0}>
          {conversationId === null ? "Start conversation" : "Send"}
        </button>
        {conversationId !== null && (
          <button
            type="button"
            className="link-button"
            onClick={() => void loadHistory(conversationId)}
          >
            Refresh
          </button>
        )}
      </form>
    </div>
  );
}
