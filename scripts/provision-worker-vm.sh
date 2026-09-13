#!/usr/bin/env bash
# =============================================================================
# SentinelGPT production worker tier (scan execution).
#
# The Cloud Run API cannot execute scans (no Docker daemon for the egress
# sandbox, ADR-0003), so production scan execution runs on a dedicated GCE
# VM hosting: Redis (Celery broker), Cloud SQL Auth Proxy, and the Celery
# worker (prefork pool, bounded concurrency). No Kubernetes, no new
# frameworks — the same Celery app/queues/timeouts as local development.
#
# Prerequisites:
#   gcloud auth login && gcloud config set project $PROJECT_ID
#   scripts/deploy-cloudrun.sh has already run (API, Cloud SQL, secrets).
#   A Firebase project linked to the same Google Cloud project.
#
# Usage:
#   PROJECT_ID=my-project REGION=europe-west1 \
#   REDIS_PASSWORD=... PG_PASSWORD=... JWT_SECRET=... \
#     ./scripts/provision-worker-vm.sh
#
# NOTE: keep REDIS_PASSWORD free of URL-special characters (: / @ ? #) or
# percent-encode them — it is interpolated into redis:// Celery/Redis URLs
# (same constraint as POSTGRES_PASSWORD in .env.example).
#
# Required environment:
#   PROJECT_ID, REGION,
#   REDIS_PASSWORD   (new Redis AUTH password; stored as a Secret Manager
#                     secret, never baked into the image),
#   PG_PASSWORD      (Cloud SQL API-user password — same value used for
#                     scripts/deploy-cloudrun.sh),
#   JWT_SECRET       (same value used for scripts/deploy-cloudrun.sh).
# Optional:
#   ZONE (default ${REGION}-b), MACHINE (e2-medium), BOOT_DISK_GB (30),
#   WORKER_VM (sentinelgpt-worker), SA_NAME/SA_EMAIL, PG_INSTANCE,
#   VPC_CONNECTOR (sentinelgpt-connector),
#   VPC_CONNECTOR_RANGE (10.8.0.0/28, must not overlap the VPC),
#   WORKER_CONCURRENCY (2 Ramadan; each scan can boot sandbox containers),
#   SCANNER_SANDBOX_IMAGE (default sentinelgpt/scanner-sandbox:latest —
#     pin a digest for production),
#   ENABLE_PROD_SCANNING (default false).
#
# Gate discipline: provisioning alone NEVER enables execution. The API keeps
# SCANNER_EXECUTION_ENABLED=false unless ENABLE_PROD_SCANNING=true is set
# explicitly, in which case this script also attaches the VPC connector and
# points the API at the VM Redis. The worker additionally enforces the gate
# at task entry (REJECT instead of execute), so flipping the API flag back
# is a true kill-switch even for already-queued tasks.
# =============================================================================
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?PROJECT_ID is required}"
REGION="${REGION:?REGION is required}"
ZONE="${ZONE:-${REGION}-b}"
REDIS_PASSWORD="${REDIS_PASSWORD:?REDIS_PASSWORD is required (Redis AUTH password for the worker VM)}"
PG_PASSWORD="${PG_PASSWORD:?PG_PASSWORD is required (Cloud SQL API user password, same as deploy-cloudrun.sh)}"
JWT_SECRET="${JWT_SECRET:?JWT_SECRET is required (32+ chars, same as deploy-cloudrun.sh)}"

SA_NAME="${SA_NAME:-sentinelgpt-api}"
SA_EMAIL="${SA_EMAIL:-${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com}"
WORKER_VM="${WORKER_VM:-sentinelgpt-worker}"
MACHINE="${MACHINE:-e2-medium}"
BOOT_DISK_GB="${BOOT_DISK_GB:-30}"
PG_INSTANCE="${PG_INSTANCE:-sentinelgpt-pg}"
VPC_CONNECTOR="${VPC_CONNECTOR:-sentinelgpt-connector}"
VPC_CONNECTOR_RANGE="${VPC_CONNECTOR_RANGE:-10.8.0.0/28}"
WORKER_CONCURRENCY="${WORKER_CONCURRENCY:-2}"
SCANNER_SANDBOX_IMAGE="${SCANNER_SANDBOX_IMAGE:-sentinelgpt/scanner-sandbox:latest}"
ENABLE_PROD_SCANNING="${ENABLE_PROD_SCANNING:-false}"

API_SVC="sentinelgpt-api"
WORKER_IMAGE="sentinelgpt-worker"
AR_REPO="cloud-run-source-deploy"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$1"; }

if [ "$SCANNER_SANDBOX_IMAGE" = "sentinelgpt/scanner-sandbox:latest" ]; then
    warn "SCANNER_SANDBOX_IMAGE is :latest — pin an immutable digest for production."
fi

step "Enabling required APIs"
gcloud services enable \
    compute.googleapis.com \
    vpcaccess.googleapis.com \
    --project "$PROJECT_ID"

step "Storing the Redis password in Secret Manager (idempotent)"
if ! gcloud secrets describe redis-password --project "$PROJECT_ID" >/dev/null 2>&1; then
    printf '%s' "$REDIS_PASSWORD" \
        | gcloud secrets create redis-password --data-file=- --project "$PROJECT_ID"
fi
gcloud secrets add-iam-policy-binding redis-password --project "$PROJECT_ID" \
    --member "serviceAccount:${SA_EMAIL}" --role roles/secretmanager.secretAccessor --quiet >/dev/null
# The worker pulls its image from Artifact Registry with the same service
# account (no keys on disk; ADC comes from the VM metadata server).
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member "serviceAccount:${SA_EMAIL}" --role roles/artifactregistry.reader --quiet >/dev/null
# IAP-tunneled SSH needs no public port 22, but the IAP range must be
# admitted (default projects often lack this rule).
if ! gcloud compute firewall-rules describe allow-iap-ssh \
    --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud compute firewall-rules create allow-iap-ssh \
        --project "$PROJECT_ID" \
        --direction INGRESS --action ALLOW \
        --rules tcp:22 \
        --source-ranges "35.235.240.0/20"
fi

step "Building + pushing the worker image (Cloud Build)"
gcloud builds submit . \
    --config infra/worker/cloudbuild.yaml \
    --substitutions "_REGION=${REGION},_IMAGE=${WORKER_IMAGE},_BASE_IMAGE=${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/${API_SVC}:latest" \
    --project "$PROJECT_ID"

step "Creating the worker VM (idempotent)"
if ! gcloud compute instances describe "$WORKER_VM" --zone "$ZONE" --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud compute instances create "$WORKER_VM" \
        --project "$PROJECT_ID" --zone "$ZONE" \
        --machine-type "$MACHINE" \
        --image-family ubuntu-2204-lts --image-project ubuntu-os-cloud \
        --boot-disk-size "${BOOT_DISK_GB}GB" --boot-disk-type pd-balanced \
        --service-account "$SA_EMAIL" \
        --scopes cloud-platform \
        --tags sentinelgpt-worker \
        --metadata startup-script='#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends docker.io docker-compose-plugin apt-transport-https ca-certificates gnupg
# Google Cloud CLI (for Artifact Registry login as the VM service account;
# stock Ubuntu images do not ship it).
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /etc/apt/keyrings/cloud.google.gpg
echo "deb [signed-by=/etc/apt/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list
apt-get update
apt-get install -y --no-install-recommends google-cloud-cli
systemctl enable --now docker
mkdir -p /opt/sentinelgpt
'
fi

step "Waiting for the VM (IAP tunnel)"
for attempt in $(seq 1 30); do
    if gcloud compute ssh "$WORKER_VM" --zone "$ZONE" --project "$PROJECT_ID" \
        --tunnel-through-iap --quiet --command "sudo docker info >/dev/null 2>&1"; then
        break
    fi
    if [ "$attempt" -eq 30 ]; then
        echo "VM did not become reachable; check the serial console." >&2
        exit 1
    fi
    sleep 10
done

VM_INTERNAL_IP="$(gcloud compute instances describe "$WORKER_VM" --zone "$ZONE" \
    --project "$PROJECT_ID" --format 'value(networkInterfaces[0].networkIP)')"
echo "  worker internal IP: ${VM_INTERNAL_IP}"

step "Deploying the worker stack on the VM"
WORK_ENV="$(mktemp)"
trap 'rm -f "$WORK_ENV"' EXIT
cat > "$WORK_ENV" <<EOF
WORKER_IMAGE=${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}/${WORKER_IMAGE}:latest
DB_USER=${SA_NAME}
DB_PASSWORD=${PG_PASSWORD}
DB_NAME=sentinelgpt
CLOUD_SQL_CONNECTION_NAME=${PROJECT_ID}:${REGION}:${PG_INSTANCE}
REDIS_PASSWORD=${REDIS_PASSWORD}
JWT_SECRET_KEY=${JWT_SECRET}
GEMINI_API_KEY_SECRET=projects/${PROJECT_ID}/secrets/gemini-api-key/versions/latest
SCANNER_SANDBOX_IMAGE=${SCANNER_SANDBOX_IMAGE}
WORKER_CONCURRENCY=${WORKER_CONCURRENCY}
LOG_LEVEL=INFO
EOF
chmod 600 "$WORK_ENV"
# Copy to the SSH user's home first (/opt/sentinelgpt is root-owned); the
# remote block moves both into place with root ownership below.
gcloud compute scp infra/worker/docker-compose.worker.yml \
    "${WORKER_VM}:~/docker-compose.worker.yml" --zone "$ZONE" --project "$PROJECT_ID" \
    --tunnel-through-iap --quiet
gcloud compute scp "$WORK_ENV" \
    "${WORKER_VM}:~/.env.worker.upload" --zone "$ZONE" --project "$PROJECT_ID" \
    --tunnel-through-iap --quiet
# The rendered env holds secret VALUES and must live only on the VM
# (root-owned 0600); the local temp copy is wiped by the EXIT trap above.
gcloud compute ssh "$WORKER_VM" --zone "$ZONE" --project "$PROJECT_ID" \
    --tunnel-through-iap --quiet --command '
set -euo pipefail
cd /opt/sentinelgpt
sudo mv "$HOME/docker-compose.worker.yml" ./docker-compose.yml
sudo mv "$HOME/.env.worker.upload" ./.env.worker
sudo chown root:root .env.worker docker-compose.yml
sudo chmod 600 .env.worker
# Compose interpolates ${VAR} from a sibling .env file only, so link it.
sudo ln -sf .env.worker .env
sudo gcloud auth configure-docker "'"${REGION}"'-docker.pkg.dev" --quiet
sudo docker compose pull worker
sudo docker pull "'"${SCANNER_SANDBOX_IMAGE}"'"
sudo docker compose up -d
sleep 15
sudo docker compose exec -T worker python -m celery -A src.workers.celery_app:celery_app inspect ping -t 10
'

step "Restricting Redis to the VPC connector range"
if ! gcloud compute firewall-rules describe sentinelgpt-worker-redis \
    --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud compute firewall-rules create sentinelgpt-worker-redis \
        --project "$PROJECT_ID" \
        --direction INGRESS --action ALLOW \
        --rules tcp:6379 \
        --source-ranges "$VPC_CONNECTOR_RANGE" \
        --target-tags sentinelgpt-worker
fi

step "Ensuring the Serverless VPC Access connector"
if ! gcloud compute networks vpc-access connectors describe "$VPC_CONNECTOR" \
    --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud compute networks vpc-access connectors create "$VPC_CONNECTOR" \
        --project "$PROJECT_ID" --region "$REGION" \
        --range "$VPC_CONNECTOR_RANGE"
fi

REDIS_BASE="redis://:${REDIS_PASSWORD}@${VM_INTERNAL_IP}:6379"
if [ "$ENABLE_PROD_SCANNING" = "true" ]; then
    step "Enabling production scan execution on the API (explicit opt-in)"
    gcloud run services update "$API_SVC" \
        --project "$PROJECT_ID" --region "$REGION" \
        --vpc-connector "$VPC_CONNECTOR" \
        --set-env-vars "SCANNER_EXECUTION_ENABLED=true,CELERY_BROKER_URL=${REDIS_BASE}/1,CELERY_RESULT_BACKEND=${REDIS_BASE}/2,REDIS_URL=${REDIS_BASE}/0"
else
    warn "ENABLE_PROD_SCANNING is not 'true': infrastructure is ready but the API gate stays OFF."
    cat <<EOF

  To enable execution later (explicit, auditable):
    gcloud run services update ${API_SVC} --project ${PROJECT_ID} --region ${REGION} \\
      --vpc-connector ${VPC_CONNECTOR} \\
      --set-env-vars "SCANNER_EXECUTION_ENABLED=true,CELERY_BROKER_URL=${REDIS_BASE}/1,CELERY_RESULT_BACKEND=${REDIS_BASE}/2,REDIS_URL=${REDIS_BASE}/0"
EOF
fi

cat <<EOF

Worker tier ready.
  VM:       ${WORKER_VM} (${ZONE})
  Redis:    ${VM_INTERNAL_IP}:6379 (AUTH, connector-range only)
  Execution gate: ${ENABLE_PROD_SCANNING}

Verify (see docs/ideathon/worker-tier.md):
  1. Create a target + attestation, then POST /api/v1/scans.
  2. The scan must leave QUEUED (RUNNING, then terminal) instead of
     stalling — watch traffic on the scan queue from the VM:
     docker compose exec worker celery -A src.workers.celery_app:celery_app inspect active
  3. Open a finding with Ask SentinelGPT: the analyst now has real
     scanner-produced evidence to reason about.
EOF
