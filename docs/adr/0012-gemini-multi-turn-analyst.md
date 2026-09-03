# ADR-0012: Gemini multi-turn conversational security analyst

**Status:** Implemented (2026-09-03)

## Context

The Ideathon requires **multi-turn interaction with the Gemini API** — a
real conversation, not a series of independent one-shot calls. SentinelGPT
already had one-shot AI: `GeminiEvidenceAnalyzer` (ADR-0008) assesses a
single finding with a JSON-mode response. That design cannot carry context
between turns, remember what was already explained, or let the analyst ask
follow-up questions of their scan.

The conversation layer also inherits a hard constraint from the platform:
scanner output is **untrusted data**. A hostile target can embed
"ignore previous instructions" text in response headers or page bodies that
scanners copy verbatim into finding evidence.

## Decision

**A dedicated multi-turn agent over the conversation aggregate (ADR-0011),
with a strict trusted/untrusted prompt boundary.**

### Conversation flow

1. `POST /api/v1/conversations` creates a conversation, optionally anchored
   to a scan/finding **the caller owns** (verified against PostgreSQL before
   any context is exposed).
2. `POST /api/v1/conversations/{id}/messages` persists the user message,
   assembles the prompt, calls Gemini **off the event loop**, and persists
   the reply. A provider failure leaves the question in history so the turn
   can be retried (503 `AI_UNAVAILABLE`).
3. Prior turns are replayed as Gemini `contents` with role mapping
   (`user`/`assistant` → `user`/`model`); the trusted system instructions
   travel as `system_instruction`, never as a turn.

### Prompt-injection defenses (bounded, not perfect)

* Every target-derived string (finding title/description/evidence, raw
  evidence rows) is wrapped in an explicit `<untrusted_target_data>` frame
  whose closing delimiter is neutralized inside the payload so crafted
  content cannot break out of the frame.
* System instructions state unconditionally that framed content is evidence
  to analyze, never instructions to follow.
* The framed context is anchored before the first user turn with a synthetic
  model acknowledgment, so the trust rule is established at turn 0.
* Context is bounded: per-field caps, a total context cap
  (`conversation_max_context_chars`, default 12 000), a history window
  (`conversation_max_history_messages`, default 40), and a response size
  cap (65 536 chars).

### Abuse and cost bounds

* Redis fixed-window limiter: 12 assistant replies per user per minute
  (`conversation_rate_limit_per_minute`; 0 disables). Fails **open** — chat
  throttling must never take down scanning.
* Quotas: 100 conversations per user, 200 messages per conversation
  (enforced by the store).
* Message length cap (8 000 chars by default) under a hard 16 384-char
  request-body ceiling.

### Model and safety

`gemini-2.0-flash` (configurable), 30 s timeout, safety thresholds set to
`BLOCK_ONLY_HIGH` — the analyst legitimately discusses exploits and
remediation, and default thresholds over-block benign security analysis.
The analyst is **read-only**: it can never mutate scan state.

## Alternatives considered

* **Reuse the one-shot analyzer per message** — no shared context between
  turns; the requirement is precisely multi-turn.
* **Client-side history replay** (SPA sends full transcript each turn) —
  lets the client forge prior turns and unbounds prompt size; history is
  read from the store instead.
* **Unlimited history** — uncontrolled prompt growth and cost; rejected in
  favor of the windowed design.

## Consequences

* The AI experience is a security analyst that understands the user's scan
  and remembers the conversation, grounded in authoritative PostgreSQL data.
* Prompt-injection risk is reduced (framing + caps + system rules) but is
  explicitly **not claimed to be eliminated** — the system instructions,
  not the framing, carry the trust decision.
* Provider outages degrade to a retryable 503 with the question preserved;
  they never affect the scanning pipeline.
