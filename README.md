# SentinelGPT

SentinelGPT is an AI-powered vulnerability-analysis platform in which the AI is the primary analytical component. The system automatically ingests findings from authorized security tools, normalizes them, correlates related findings, deduplicates them, assesses severity and risk, prioritizes vulnerabilities, explains findings using available evidence, and generates security reports.

## Core Principles

- **AI-Driven Analysis Pipeline:** Ingestion, normalization, correlation, deduplication, severity/risk assessment, prioritization, explanation, and reporting run automatically; no human-approval step is required to operate the platform.
- **Evidence-Grounded AI:** AI explains deterministic scanner evidence; it does not originate findings or alter canonical severity.
- **Research Evaluation Only:** Human experts participate only during research evaluation, to establish ground truth and measure accuracy, reliability, and reproducibility — never as a required operational step.
- **Strict Authorization:** Mandatory proof of authorization prior to scanning.
- **Defense in Depth:** Egress-restricted ephemeral sandbox scan runtime.

## Ideathon: Google Cloud integration

SentinelGPT extends its existing security platform (FastAPI, PostgreSQL,
Redis, Celery, Docker-sandboxed scanning) with a Google Cloud AI layer.
PostgreSQL remains the source of truth for all security data; the Google
services form the identity/conversation/deployment layer around it.

**Firebase Authentication — federated sign-in.** The React app signs users
in with the Google popup via the Firebase Web SDK and sends the resulting
ID token to `POST /api/v1/auth/firebase`. The backend verifies the token
**server-side** against Google's public JWKs (RS256 signature, `aud`,
`iss`, `exp`, non-empty `sub`) — no Firebase Admin credential is held
anywhere — then maps the verified UID onto SentinelGPT's canonical user
account and issues the platform's existing hardened session cookies
(rotation, reuse detection, CSRF header). All downstream authorization
keys on the canonical user id, never on client-supplied identifiers.
(ADR-0010)

**Gemini — multi-turn conversational security analyst.** Each finding in a
scan detail view opens a chat with an analyst powered by Gemini
(`gemini-2.0-flash` via `google-genai`). Prior turns are replayed as
Gemini `contents`, trusted system instructions travel as
`system_instruction`, and finding/scan context is loaded from PostgreSQL
and attached as a size-capped, delimiter-escaped
`<untrusted_target_data>` block: scanner output is untrusted evidence to
analyze, never instructions to follow. Context windows, message quotas,
and a per-user Redis rate limit bound every prompt. The analyst is
read-only — it can never mutate security state. (ADR-0012)

**Firestore — user-isolated conversation storage.** Conversations persist
as `users/{firebase_uid}/conversations/{id}` documents with a `messages`
subcollection, written and read exclusively by the backend Admin SDK/ADC.
The UID in the path always comes from the verified session, never from
client input; cross-owner conversation ids answer the same 404 as unknown
ids. Client Firestore access is denied by rules
(`infra/firebase/firestore.rules`) — defense in depth on top of the
backend-enforced boundary. Locally, an in-memory store with identical
semantics keeps development Google-free. (ADR-0011)

**Secret Manager — server-side credential retrieval.** The Gemini API key
is resolved at runtime from Secret Manager
(`projects/{p}/secrets/{s}/versions/{v}`) with Application Default
Credentials, cached in-process for 5 minutes so rotation lands without a
redeploy. A failed lookup degrades to the environment value with a loud
log — never a blocked platform. The key is never logged, never returned in
API responses, and never shipped to the frontend; `/healthz` exposes only
a boolean "configured" signal. (ADR-0013)

**Cloud Run — deployment target.** Two services: the FastAPI API (honours
Cloud Run's injected `PORT`, `/healthz` startup + liveness probes, Cloud
SQL PostgreSQL via unix socket, secrets via `--set-secrets`) and an nginx
frontend that serves the SPA and proxies `/api` same-origin — session
cookies stay first-party with no CORS surface. The scanner Celery worker
deliberately runs off Cloud Run (no privileged Docker access there); the
API runs with `SCANNER_EXECUTION_ENABLED=false`, an explicitly supported
mode. Deploy with `scripts/deploy-cloudrun.sh`; see
[docs/ideathon/cloud-run.md](docs/ideathon/cloud-run.md). The repository
is Cloud Run ready; deployment itself requires a Google Cloud project.

Integration setup: [docs/ideathon/setup.md](docs/ideathon/setup.md) ·
Demo walkthrough: [docs/ideathon/demo.md](docs/ideathon/demo.md).

## Project Structure

- `backend/`: FastAPI application, domain services, scanner adapters, AI orchestrator, and database infrastructure.
- `frontend/`: React / TypeScript dashboard and findings interface.
- `infrastructure/`: Deployment manifests, Docker Compose, and environment configuration.
- `tests/`: Automated test suites (unit, integration, security, and property-based tests).
- `docs/srs/`: Complete 15-chapter Software Requirements Specification (SRS v3).

## Quick Start (Phase 0)

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   ```
2. Install dependencies:
   ```bash
   pip install -e .[dev]
   ```
3. Copy environment configuration and adjust values:
   ```bash
   cp .env.example .env
   ```
4. Run tests:
   ```bash
   pytest
   ```
5. Full stack via Docker (frontend on http://localhost:3000, API on
   http://localhost:8000):
   ```bash
   docker compose up --build
   ```
6. Apply database migrations against the running Postgres:
   ```bash
   alembic upgrade head
   ```

### Dependency locking

CI and Docker builds install from the hash-pinned lock files
(`requirements.lock`, `requirements-dev.lock`) per the SRS pinning rule.
Regenerate them inside `linux/python:3.12` after changing `pyproject.toml` —
see the header of either lock file for the exact command.

### Deployment profiles

- Local dev: `docker compose up` (loopback-only ports, debug/hot-reload).
- Public demo: `docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build`
  (Caddy TLS edge; Postgres/Redis never published).

### Local dev with the scanner sandbox

The base `docker compose up` does not start the worker or the scanner
sandbox. To reproduce the full live acceptance (QUEUE → RUNNING →
`REPORT_READY_DEGRADED` against a controlled test target, with the worker
container reporting `healthy` against its Celery broker) follow
`docs/operations/local-dev-with-scanner.md`. The exact recipe:

```bash
cp .env.example .env
./scripts/build-scanner-sandbox-image.sh       # Linux/macOS; on Windows use scripts\build-scanner-sandbox-image.ps1
docker compose -f docker-compose.yml -f docker-compose.override.yml -f docker-compose.local.yml up -d --build
docker compose exec api alembic upgrade head
.venv/Scripts/python.exe scripts/e2e_scan_workflow.py   # or the docker exec equivalent
```

The `local` overlay adds the worker (built from
`infra/docker/worker.Dockerfile`), mounts `/var/run/docker.sock`,
enables `SCANNER_EXECUTION_ENABLED`, and replaces the inherited API
healthcheck with a `celery inspect ping` so the worker container reports
`healthy`.
