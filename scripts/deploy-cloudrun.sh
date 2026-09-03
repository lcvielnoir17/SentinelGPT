#!/usr/bin/env bash
# =============================================================================
# SentinelGPT Cloud Run deployment (Ideathon requirements 4 + 5)
#
# Deploys the API (FastAPI) and frontend (SPA) to Cloud Run, wiring:
#   * Secret Manager as the Gemini API key source (GEMINI_API_KEY_SECRET)
#   * Firestore for user-isolated conversations (project-level; no runtime
#     config needed beyond FIREBASE_PROJECT_ID)
#   * Cloud SQL (PostgreSQL) as the authoritative database
#   * JWT_SECRET_KEY via --set-secrets (never baked into the image)
#
# Prerequisites:
#   gcloud auth login && gcloud config set project $PROJECT_ID
#   A Firebase project linked to the same Google Cloud project, with
#   Firestore in Native mode (see docs/ideathon/setup.md).
#
# Usage:
#   PROJECT_ID=my-project REGION=europe-west1 ./scripts/deploy-cloudrun.sh
#
# The scanner Celery worker is intentionally NOT deployed here (no
# privileged Docker access on Cloud Run); the API runs with
# SCANNER_EXECUTION_ENABLED=false. See docs/ideathon/cloud-run.md.
# =============================================================================
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?PROJECT_ID is required}"
REGION="${REGION:?REGION is required}"
SA_NAME="${SA_NAME:-sentinelgpt-api}"
SA_EMAIL="${SA_EMAIL:-${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com}"

PG_INSTANCE="${PG_INSTANCE:-sentinelgpt-pg}"
PG_PASSWORD="${PG_PASSWORD:?PG_PASSWORD is required (Cloud SQL API user password)}"
JWT_SECRET="${JWT_SECRET:?JWT_SECRET is required (32+ chars)}"

API_SVC="sentinelgpt-api"
FRONTEND_SVC="sentinelgpt-frontend"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

step "Enabling required APIs"
gcloud services enable \
    run.googleapis.com \
    sqladmin.googleapis.com \
    secretmanager.googleapis.com \
    firestore.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    --project "$PROJECT_ID"

step "Ensuring service account + IAM bindings ($SA_EMAIL)"
gcloud iam service-accounts create "$SA_NAME" --project "$PROJECT_ID" 2>/dev/null || true
for role in \
    roles/secretmanager.secretAccessor \
    roles/datastore.user \
    roles/cloudsql.client
do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member "serviceAccount:${SA_EMAIL}" --role "$role" --quiet >/dev/null
done

step "Creating secrets in Secret Manager (idempotent)"
if ! gcloud secrets describe gemini-api-key --project "$PROJECT_ID" >/dev/null 2>&1; then
    printf '%s' "${GEMINI_API_KEY:?GEMINI_API_KEY is required}" \
        | gcloud secrets create gemini-api-key --data-file=- --project "$PROJECT_ID"
fi
if ! gcloud secrets describe jwt-secret-key --project "$PROJECT_ID" >/dev/null 2>&1; then
    printf '%s' "$JWT_SECRET" \
        | gcloud secrets create jwt-secret-key --data-file=- --project "$PROJECT_ID"
fi
gcloud secrets add-iam-policy-binding gemini-api-key --project "$PROJECT_ID" \
    --member "serviceAccount:${SA_EMAIL}" --role roles/secretmanager.secretAccessor --quiet >/dev/null
gcloud secrets add-iam-policy-binding jwt-secret-key --project "$PROJECT_ID" \
    --member "serviceAccount:${SA_EMAIL}" --role roles/secretmanager.secretAccessor --quiet >/dev/null

step "Creating Cloud SQL PostgreSQL instance (idempotent, may take minutes)"
if ! gcloud sql instances describe "$PG_INSTANCE" --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud sql instances create "$PG_INSTANCE" \
        --database-version=POSTGRES_16 --tier=db-f1-micro --region "$REGION" \
        --storage-auto-increase --project "$PROJECT_ID"
fi
gcloud sql users create "$SA_NAME" --instance "$PG_INSTANCE" --password "$PG_PASSWORD" \
    --project "$PROJECT_ID" 2>/dev/null || \
    gcloud sql users set-password "$SA_NAME" --instance "$PG_INSTANCE" --password "$PG_PASSWORD" \
        --project "$PROJECT_ID"
gcloud sql databases create sentinelgpt --instance "$PG_INSTANCE" --project "$PROJECT_ID" 2>/dev/null || true

step "Building + deploying the API (Cloud Build)"
gcloud run deploy "$API_SVC" \
    --project "$PROJECT_ID" --region "$REGION" \
    --source . \
    --service-account "$SA_EMAIL" \
    --port 8080 \
    --set-env-vars "ENVIRONMENT=production,DEBUG=false,LOG_JSON=true,FIREBASE_PROJECT_ID=${PROJECT_ID},FIRESTORE_CONVERSATIONS_ENABLED=true,GEMINI_API_KEY_SECRET=projects/${PROJECT_ID}/secrets/gemini-api-key/versions/latest,SECRET_MANAGER_ENABLED=true,SCANNER_EXECUTION_ENABLED=false,DATABASE_URL=postgresql+asyncpg://${SA_NAME}:${PG_PASSWORD}@/sentinelgpt?host=/cloudsql/${PROJECT_ID}:${REGION}:${PG_INSTANCE}" \
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest" \
    --allow-unauthenticated \
    --cpu 1 --memory 512Mi --concurrency 40 \
    --verbosity info

API_URL="$(gcloud run services describe "$API_SVC" --project "$PROJECT_ID" --region "$REGION" --format 'value(status.url)')"

step "Building + deploying the frontend (same-origin /api proxy)"
gcloud run deploy "$FRONTEND_SVC" \
    --project "$PROJECT_ID" --region "$REGION" \
    --source frontend \
    --set-env-vars "API_UPSTREAM=${API_URL}" \
    --allow-unauthenticated \
    --cpu 0.5 --memory 256Mi

FRONTEND_URL="$(gcloud run services describe "$FRONTEND_SVC" --project "$PROJECT_ID" --region "$REGION" --format 'value(status.url)')"

step "Deploying deny-all Firestore security rules (defense in depth)"
if command -v firebase >/dev/null 2>&1 && [ -f firebase.json ]; then
    firebase deploy --only firestore:rules --project "$PROJECT_ID"
else
    echo "  (firebase CLI not found; upload infra/firebase/firestore.rules manually)"
fi

step "Applying database migrations (one-off job)"
gcloud run jobs deploy sentinelgpt-migrate \
    --project "$PROJECT_ID" --region "$REGION" \
    --image "REGION-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/${API_SVC}:latest" \
    --set-cloudsql-instances "${PROJECT_ID}:${REGION}:${PG_INSTANCE}" \
    --set-secrets "JWT_SECRET_KEY=jwt-secret-key:latest" \
    --set-env-vars "ENVIRONMENT=production,DATABASE_URL=postgresql+asyncpg://${SA_NAME}:${PG_PASSWORD}@/sentinelgpt?host=/cloudsql/${PROJECT_ID}:${REGION}:${PG_INSTANCE}" \
    --command alembic --args "upgrade,head" \
    --max-retries 1 2>/dev/null || \
    echo "  (create the migrate job later: gcloud run jobs deploy sentinelgpt-migrate ... --command alembic --args upgrade,head)"
gcloud run jobs execute sentinelgpt-migrate --region "$REGION" --project "$PROJECT_ID" --wait 2>/dev/null || true

cat <<EOF

Deployment complete.
  API:      ${API_URL}
  Frontend: ${FRONTEND_URL}

Next steps:
  1. Add the Firebase Web SDK config to the frontend (VITE_FIREBASE_* build
     args) and rebuild/deploy the frontend.
  2. Add ${FRONTEND_URL} to the API's CORS_ORIGINS only if you bypass the
     same-origin proxy.
  3. Run the demo script in docs/ideathon/demo.md.
EOF
