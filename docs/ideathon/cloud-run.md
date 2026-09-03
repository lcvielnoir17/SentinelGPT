# Cloud Run deployment (Ideathon requirement 5)

SentinelGPT's web/API layer targets **Cloud Run**; the scanner worker
intentionally does not. This document describes the deployed shape, how to
deploy it, and what is verified versus what requires a live Google Cloud
project.

> Status wording: the repository is **Cloud Run ready** — containerized,
> PORT-correct, health-probed, secret-wired. The services count as
> *deployed* only after `scripts/deploy-cloudrun.sh` (or the equivalent
> `gcloud run deploy` calls) has actually run against your project.

## Deployed shape

```
Browser ──▶ Cloud Run: sentinelgpt-frontend (nginx SPA)
                │  same-origin /api proxy (no CORS, first-party cookies)
                ▼
            Cloud Run: sentinelgpt-api (FastAPI, uvicorn)
                ├─── Cloud SQL (PostgreSQL)      authoritative scan data
                ├─── Firestore (Native)          user-isolated AI conversations
                ├─── Secret Manager              Gemini API key (runtime fetch)
                └─── Gemini API (google-genai)   multi-turn security analyst

Scanner worker (Celery + Docker sandbox): NOT on Cloud Run — it needs a
Docker daemon; run it on a VM/compute with Docker. The Cloud Run API runs
with SCANNER_EXECUTION_ENABLED=false, which is an explicit, tested mode.
```

Why two services: Cloud Run deploys one container per service. The nginx
edge serves the static SPA and proxies `/api` to the API service so browser
requests stay same-origin — session cookies remain first-party and no CORS
surface is exposed.

## Deploy

Prerequisites: `gcloud` CLI, a project with billing, a Firebase project
linked to it (see [setup.md](setup.md)).

```bash
gcloud auth login
gcloud config set project "$PROJECT_ID"

PROJECT_ID=my-project REGION=europe-west1 \
GEMINI_API_KEY=... JWT_SECRET=$(openssl rand -hex 32) PG_PASSWORD=... \
    ./scripts/deploy-cloudrun.sh
```

The script (idempotent):

1. Enables the required APIs (Run, SQL Admin, Secret Manager, Firestore,
   Cloud Build, Artifact Registry).
2. Creates the `sentinelgpt-api` service account with
   `secretmanager.secretAccessor`, `datastore.user` (Firestore),
   `cloudsql.client`.
3. Creates the `gemini-api-key` and `jwt-secret-key` secrets and grants
   the service account access.
4. Creates the Cloud SQL PostgreSQL 16 instance + `sentinelgpt` database.
5. Builds + deploys the API from the repo root (`--source .`), wiring:
   `FIREBASE_PROJECT_ID`, `FIRESTORE_CONVERSATIONS_ENABLED=true`,
   `GEMINI_API_KEY_SECRET=projects/…/secrets/gemini-api-key/versions/latest`,
   `SECRET_MANAGER_ENABLED=true`, `SCANNER_EXECUTION_ENABLED=false`, the
   Cloud SQL unix-socket `DATABASE_URL`, and
   `--set-secrets JWT_SECRET_KEY=jwt-secret-key:latest`.
6. Builds + deploys the frontend with `API_UPSTREAM=<api-url>`.
7. Uploads the deny-all Firestore rules (Firebase CLI if present).
8. Runs `alembic upgrade head` as a one-off Cloud Run job.

Declarative equivalents for review/GitOps live in
`infra/cloud/api-cloudrun.yaml` and `infra/cloud/frontend-cloudrun.yaml`.

## PORT and health behavior (Cloud Run contract)

* **API:** the image honours the injected `PORT`
  (`uvicorn --port "${PORT:-8000}"`); Cloud Run requests `/healthz` on
  8080 with startup + liveness probes. Local compose keeps 8000 unchanged.
* **Frontend:** nginx listens on 8080 (Cloud Run's default); the same
  image serves 3000→8080 in compose via the template.
* Cold starts get `startup-cpu-boost`; autoscaling 0→5.

## Required Google Cloud resources

| Resource | Purpose | Created by |
|---|---|---|
| Cloud Run ×2 | API + frontend services | deploy script |
| Cloud SQL (PostgreSQL 16) | scans/findings/users (source of truth) | deploy script |
| Firestore (Native) | conversations per Firebase UID | manual (setup.md) |
| Secret Manager ×2 | Gemini key, JWT signing key | deploy script |
| Firebase Auth (Google provider) | federated identity | manual (setup.md) |
| Service account `sentinelgpt-api` | runtime identity (ADC) | deploy script |

## What is verified vs. what needs a live project

Verified locally (tests + builds): PORT handling, `/healthz` probes,
Secret Manager resolution logic with a patched client, Firestore store
semantics against the in-memory twin, Firebase token verification against
forged/invalid tokens, frontend build, container build configuration.

Requires a live project (cannot be verified from this repo): actual Cloud
Build, Cloud SQL connectivity from Cloud Run, Firestore production
latency, Gemini live traffic, custom-domain TLS.
