# Production worker tier (scan execution)

The Cloud Run API **cannot execute scans**: the egress sandbox (ADR-0003)
needs a Docker daemon socket, which Cloud Run never provides. Production
scan execution therefore runs on a dedicated GCE VM. No Kubernetes, no new
frameworks — the same Celery app, queues, and task timeouts as local
development (`docker-compose.local.yml`).

## Shape

```
Browser ──▶ Cloud Run: sentinelgpt-api ──(VPC connector)──▶ GCE: sentinelgpt-worker
   (same-origin /api)      │ SCANNER_EXECUTION_ENABLED=true      ├── redis:7 (broker 6379/1, backend /2, limiter /0)
                           │ Celery send_task                     ├── cloud-sql-proxy → Cloud SQL (no public DB)
                           ▼                                    └── worker (prefork, --concurrency=2)
                     Cloud SQL ← writes ── sandbox: sibling containers, egress = one binding
```

## Threat model (summary)

| Vector | Control |
|---|---|
| Arbitrary scan destinations | Attestation gate at creation **and** execution-time re-check; IP policy over the full record set; binding-derived egress; kernel DROP default with verified rule dump |
| Command injection via scan params | No shell: target → normalized hostname/scheme/port/path → workload args; only validated bindings reach the sandbox |
| Privileged sandbox escape | Workloads exec as UID 65534 (CapEff=0); NET_ADMIN only for rule install; containers capped (`--memory 512m --cpus 1.0`); fail-closed teardown |
| docker.sock = host root | Socket lives on a **dedicated** VM running nothing else; no public SSH (IAP only); Redis bound to internal IP + AUTH + firewall limited to the connector range |
| Credential leakage | No keys on disk: VM SA via metadata (Secret Manager accessor on named secrets only, `cloudsql.client`, AR reader); `.env.worker` is root-only 0600 on the VM; Secret Manager payloads never logged |
| Queue flooding | Serialized per worker (prefetch 1), 900s hard task limit, `worker_max_tasks_per_child=200`; scan creation remains attestation-gated per scan |
| Stale gate | Execution-time gate check: tasks running after disable are REJECTED (`execution_disabled`), never executed |

## Deploy

```bash
PROJECT_ID=... REGION=... REDIS_PASSWORD=... PG_PASSWORD=... JWT_SECRET=... \
  ./scripts/provision-worker-vm.sh
```

This provisions infra but leaves the API gate **OFF**. To enable execution
(explicit, auditable), re-run with `ENABLE_PROD_SCANNING=true`, which
attaches the VPC connector and points the API at the VM Redis. Flipping the
API flag back is a true kill-switch (worker-side REJECT covers queued tasks).

## Operations

```bash
# On the VM (IAP): cd /opt/sentinelgpt
sudo docker compose ps
sudo docker compose exec worker celery -A src.workers.celery_app:celery_app inspect active
sudo docker compose logs -f worker
```

- Concurrency: `WORKER_CONCURRENCY` (default 2 on e2-medium).
- Rotate Redis AUTH: update the `redis-password` secret, rewrite
  `/opt/sentinelgpt/.env.worker` (0600), `docker compose up -d redis`,
  then update the API revision env.
- Sandbox image: pin `SCANNER_SANDBOX_IMAGE` to a digest; pre-pull before
  enabling execution.

## Verification (maps to mission Phases 9–14)

1. Attested target → `POST /api/v1/scans` → scan leaves QUEUED
   (RUNNING → terminal) instead of stalling.
2. Findings persist; scan reaches REPORT_READY/DEGRADED or honest
   REJECTED (never silent QUEUED-forever).
3. Finding → Ask SentinelGPT works against scanner-produced evidence.
4. Cross-tenant scan access stays 404; worker logs contain no secrets.
