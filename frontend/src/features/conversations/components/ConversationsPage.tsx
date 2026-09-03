/**
 * All conversations for the signed-in user (ADR-0012).
 *
 * Conversations persist in Firestore under the user's Firebase UID; this
 * page reopens persisted threads so a user can resume an investigation
 * after a refresh or on another device. Expandable threads keep the UI
 * inside the existing SentinelGPT layout (no separate chat surface).
 */

import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../../services/apiClient";
import {
  deleteConversation,
  getConversation,
  listConversations,
  sendMessage,
} from "../api/conversationsApi";
import type { ConversationDetailDto, ConversationDto, ConversationMessageDto } from "../api/conversationsApi";

export function ConversationsPage() {
  const [conversations, setConversations] = useState<ConversationDto[] | null>(null);
  const [open, setOpen] = useState<ConversationDetailDto | null>(null);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setConversations(await listConversations());
    } catch (err) {
      if (err instanceof ApiError) setError(err.message);
      else setError("Unable to load conversations.");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const openConversation = useCallback(async (id: string) => {
    setError(null);
    try {
      setOpen(await getConversation(id));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unable to open conversation.");
    }
  }, []);

  const remove = useCallback(
    async (id: string) => {
      try {
        await deleteConversation(id);
        if (open?.id === id) setOpen(null);
        await refresh();
      } catch (err) {
        setError(err instanceof ApiError ? err.message : "Unable to delete conversation.");
      }
    },
    [open, refresh],
  );

  const reply = useCallback(async () => {
    if (open === null) return;
    const content = draft.trim();
    if (!content || sending) return;
    setSending(true);
    setDraft("");
    try {
      const response = await sendMessage(open.id, content);
      setOpen({
        ...open,
        messageCount: open.messageCount + 2,
        messages: [...open.messages, response.userMessage, response.assistantMessage],
      });
    } catch (err) {
      setDraft(content);
      setError(err instanceof ApiError ? err.message : "The AI analyst is unreachable.");
    } finally {
      setSending(false);
    }
  }, [draft, open, sending]);

  return (
    <section>
      <header className="page-header">
        <h2>AI analyst conversations</h2>
        <p className="muted small">
          Persisted per user in Firestore; anchored to the scan finding you asked about.
        </p>
      </header>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {conversations === null ? (
        <p className="muted">Loading conversations…</p>
      ) : conversations.length === 0 ? (
        <p className="muted">
          No conversations yet. Open a scan and press “Ask SentinelGPT” on a finding.
        </p>
      ) : (
        <ul className="conversation-list">
          {conversations.map((c) => (
            <li key={c.id} className="conversation-item">
              <div className="conversation-summary">
                <button
                  type="button"
                  className="link-button"
                  onClick={() => void openConversation(c.id)}
                >
                  {c.title}
                </button>
                <span className="muted small">
                  {c.messageCount} message{c.messageCount === 1 ? "" : "s"} ·{" "}
                  {new Date(c.updatedAt).toLocaleString()}
                </span>
                {c.scanId && (
                  <Link className="small" to={`/scans/${c.scanId}`}>
                    view scan
                  </Link>
                )}
                <button
                  type="button"
                  className="link-button danger"
                  onClick={() => void remove(c.id)}
                >
                  delete
                </button>
              </div>

              {open?.id === c.id && (
                <div className="chat-panel" aria-label={`Conversation ${c.title}`}>
                  <div className="chat-messages">
                    {open.messages.map((m: ConversationMessageDto) => (
                      <div key={m.id} className={`chat-message chat-${m.role}`}>
                        <span className="chat-role">
                          {m.role === "user" ? "You" : "SentinelGPT"}
                        </span>
                        <p>{m.content}</p>
                      </div>
                    ))}
                    {open.messages.length === 0 && (
                      <p className="muted small">No messages in this conversation yet.</p>
                    )}
                  </div>
                  <form
                    className="chat-input"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void reply();
                    }}
                  >
                    <textarea
                      rows={2}
                      value={draft}
                      placeholder="Continue the conversation…"
                      onChange={(e) => setDraft(e.target.value)}
                    />
                    <button type="submit" disabled={sending || draft.trim().length === 0}>
                      Send
                    </button>
                  </form>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
