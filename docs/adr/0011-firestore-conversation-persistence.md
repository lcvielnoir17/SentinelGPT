# ADR-0011: Firestore for user-scoped AI conversations

**Status:** Implemented (2026-09-03)

## Context

The Ideathon requires user-isolated Firestore document storage. SentinelGPT's
authoritative security data (users, targets, attestations, scans, findings,
evidence, assessments, audit log) is and stays in PostgreSQL; duplicating it
into Firestore would create two sources of truth.

## Decision

Firestore stores exactly one aggregate: **AI conversations**.

```
users/{firebase_uid}/conversations/{conversation_id}
    title, userId, scanId?, findingId?, messageCount, createdAt, updatedAt
users/{firebase_uid}/conversations/{conversation_id}/messages/{message_id}
    role, content, createdAt, seq
```

* **Path scoping as the isolation boundary.** Every store operation
  addresses documents under `users/{firebase_uid}/…` where the UID comes
  exclusively from the verified session identity (ADR-0010) — never from
  client input. The store API deliberately exposes no way to address
  another user's subtree.
* **Defense in depth.** `ConversationService` re-checks ownership against
  the canonical `user_id` before every store call, and
  `infra/firebase/firestore.rules` denies all *client* access — all
  Firestore I/O is backend Admin SDK.
* **Backend-only access.** The SPA never talks to Firestore; the rules file
  is uploaded so even direct SDK attempts are refused.
* **Local development.** Without a Firebase project the app wires an
  in-memory store with identical semantics (no durability); production
  always uses the Firestore `AsyncClient` via Application Default
  Credentials.
* Message ordering uses a store-assigned monotonic `seq` (timestamps are
  not monotonic on all platform clocks).

## Alternatives considered

* PostgreSQL `conversation`/`message` tables — trivially safe but does not
  satisfy the Ideathon requirement and misses the per-user document model.
* Client-direct Firestore with security rules — moves authorization into
  declarative rules and splits the trust story; rejected in favor of the
  backend-enforced boundary (rules remain deny-all).

## Consequences

* Conversations persist across sessions/devices per user.
* Cross-user access is structurally impossible: wrong-scope reads return
  "not found", and service-level checks make cross-owner ids
  indistinguishable from unknown ids (404, no existence leak).
* A per-user conversation quota (100) and per-conversation message bound
  (200) keep subtree scans cheap.
