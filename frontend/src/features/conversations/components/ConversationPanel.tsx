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

/**
 * Translate a resolution/send failure into user-facing guidance.
 *
 * Every branch is a terminal, retryable state — nothing here may leave the
 * panel spinning. The Firebase-identity branch names the supported flow
 * instead of implying a retry will help; transport branches name the
 * transport problem instead of blaming the analyst.
 */
function describeAnalystError(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case "AI_NOT_CONFIGURED":
        return "AI analysis is not configured on this deployment.";
      case "AI_UNAVAILABLE":
        return (
          "The AI analyst is unavailable. The analyst requires Google sign-in " +
          "(email sessions cannot use it); otherwise, try again shortly."
        );
      case "CONVERSATION_UNAVAILABLE":
        return err.message;
      case "TIMEOUT":
        return "The analyst took too long to respond. Your question is kept — try again.";
      case "NETWORK_ERROR":
        return "The AI analyst is unreachable; check your connection and try again.";
      case "ABORTED":
        return "The request was cancelled; try again.";
      case "NOT_FOUND":
        return "This finding is no longer available for analysis.";
      case "RATE_LIMITED":
      case "CONVERSATION_LIMIT":
      case "MESSAGE_TOO_LONG":
      case "VALIDATION_ERROR":
        return err.message;
      default:
        if (err.status === 401) {
          return "Your session expired. Sign in again and retry.";
        }
        return err.message;
    }
  }
  return "The AI analyst is unreachable; try again.";
}

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
  // Initialization (mount-time reconnect/creation) has its own state so a
  // failed start is visible instead of a silent dead panel. `error` covers
  // both init and send failures; either clears on the next submit attempt.
  const [resolving, setResolving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lastMessageRef = useRef<HTMLDivElement | null>(null);
  // Server-truth id behind the state, plus single-flight resolution so the
  // mount-time reconnect and a first send never create two conversations.
  const conversationIdRef = useRef<string | null>(null);
  const resolvingRef = useRef<Promise<string> | null>(null);
  // Synchronous submit guard: the `sending` state update is async, so two
  // rapid submits (double-Enter, double-click before re-render) would both
  // read a stale `false`. The ref closes that window — no duplicate turns.
  const sendingRef = useRef(false);

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
  // Init failures are surfaced (never swallowed): the panel shows guidance
  // and the next submit retries the resolution.
  useEffect(() => {
    let cancelled = false;
    setResolving(true);
    void resolveConversation()
      .then(async (id) => {
        if (cancelled || conversationIdRef.current !== id) return;
        try {
          const detail = await getConversation(id);
          if (!cancelled) {
            setMessages((prev) => (prev.length > 0 ? prev : detail.messages));
            setError(null);
          }
        } catch (err) {
          if (!cancelled) {
            setError(describeAnalystError(err));
          }
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(describeAnalystError(err));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setResolving(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [resolveConversation]);

  const submitDraft = useCallback(async () => {
    const content = draft.trim();
    if (!content || sendingRef.current) return;
    sendingRef.current = true;
    setError(null);
    setSending(true);
    setDraft("");
    try {
      const id = await resolveConversation();
      const response = await sendMessage(id, content);
      setMessages((prev) => [...prev, response.userMessage, response.assistantMessage]);
    } catch (err) {
      setDraft(content);
      setError(describeAnalystError(err));
    } finally {
      sendingRef.current = false;
      setSending(false);
    }
  }, [draft, resolveConversation]);

  // Submits share the mount-time resolution flight, so typing and sending
  // while the panel is still starting never creates a second conversation —
  // the button therefore stays enabled during init (only sending or an
  // empty draft disables it) and the live region above reports progress.
  const startLabel = conversationId === null ? "Start conversation" : "Send";
  const sendDisabled = sending || draft.trim().length === 0;

  return (
    <div className="chat-panel" aria-label="SentinelGPT analyst conversation">
      <div className="chat-messages" aria-busy={sending || resolving}>
        {loading && <p className="muted small">Loading conversation…</p>}
        {resolving && (
          <p className="muted small" aria-live="polite">
            Starting conversation…
          </p>
        )}
        {messages.length === 0 && !loading && !resolving && (
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
        <button
          type="submit"
          disabled={sendDisabled}
          title={
            conversationId === null && draft.trim().length === 0
              ? "Type a question first — the conversation starts with your first message"
              : undefined
          }
        >
          {startLabel}
        </button>
        {conversationId === null && !resolving && (
          <p className="muted small chat-hint">
            Type a question below — the conversation starts with your first message.
          </p>
        )}
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
