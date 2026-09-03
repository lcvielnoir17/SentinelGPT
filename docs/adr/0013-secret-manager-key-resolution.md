# ADR-0013: Secret Manager-backed Gemini key resolution

**Status:** Implemented (2026-09-03)

## Context

The Ideathon requires **secure API key retrieval using Google Cloud Secret
Manager**. The platform's only secret-backed external integration is the
Gemini API key. Previously it could only arrive as a plain environment
value — functional, but plain env values end up in deploy commands, shell
history, and orchestrator state, and rotating them means redeploys.

## Decision

**Resolve at runtime from Secret Manager, with a guarded environment
fallback; degrade, never block.**

Resolution order (`src/infrastructure/secrets/resolver.py`):

1. `SECRET_MANAGER_ENABLED=true` **and** `GEMINI_API_KEY_SECRET` is a
   well-formed Secret Manager version resource
   (`projects/{p}/secrets/{s}/versions/{v|latest}`) → fetch the payload
   via the Secret Manager client using Application Default Credentials
   (on Cloud Run: the attached service account; locally:
   `gcloud auth application-default login`).
2. Otherwise → the plain `GEMINI_API_KEY` environment value, keeping local
   development fully functional with no Google project at all.

Operational properties:

* The fetched key is cached in memory for 5 minutes so request-time turns
  do not hit Secret Manager each call; failures are negatively cached for
  30 s to avoid hammering a broken backend.
* A failed Secret Manager lookup **falls back to the environment value with
  a loud error log** — an AI-secret problem must never take down scanning.
* The resource-name pattern is validated before any API call; an empty
  payload is treated as a failure, not as an empty key.

Security properties:

* The secret is never logged, never returned in API responses, and never
  exposed to the frontend; readiness reports only a boolean "configured".
* On Cloud Run the value is injected via `--set-secrets`/mounted env, never
  baked into the image and never committed (SRS Ch11 §4 secrets policy).
* Local `.env` use is restricted to non-secret development defaults; the
  production settings contract fail-fasts on weak JWT secrets regardless
  of this resolver.

## Alternatives considered

* **Secret Manager only, no fallback** — breaks every local/offline
  development workflow and makes CI impractical.
* **Build-time secret injection into the image** — the secret lands in
  image layers; rejected outright.
* **Client-fetched key** — would place a server credential in the browser
  bundle; rejected outright.

## Consequences

* Production (Cloud Run) reads the Gemini key from Secret Manager with a
  bounded-lifetime in-process cache; rotation takes effect within 5 minutes
  without a redeploy.
* Misconfiguration is observable (error log with the resource name and
  failure kind — never the payload) and non-fatal for the core platform.
