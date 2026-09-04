# SentinelGPT — Local dev / demo with the scanner sandbox

This document is the **exact, reproducible** bootstrap sequence to bring up
the full SentinelGPT stack (API + frontend + Postgres + Redis + worker +
scanner sandbox) on a developer machine and to run the live end-to-end
scan acceptance against a controlled test target.

It does **not** redesign the Docker architecture. It composes the existing
committed files in the documented order.

---

## Prerequisites

| Requirement       | Version  | Why                                                       |
|-------------------|----------|-----------------------------------------------------------|
| Docker Engine     | ≥ 24.0   | runs the API, worker, Postgres, Redis, and the sandbox    |
| Docker Compose    | v2 (plugin) | orchestrates the multi-file stack                       |
| Git               | any      | clone the repo                                             |
| OS                | Linux, macOS, or Windows 10/11 with Docker Desktop | sandbox uses Linux bridge networking |
| A C compiler toolchain on the Docker host | — | Debian-slim builder image compiles Python wheels     |

On **Windows / Docker Desktop** the `docker` CLI binary lives inside the
WSL2 Linux VM. The worker container reaches it through
`/var/run/docker.sock`, which Docker Desktop mounts at gid `0` (root).
The shipped `infra/docker/worker.Dockerfile` already adds `appuser` to the
root group so the socket is reachable without elevating the worker
process.

---

## 1. Configure the environment

Copy `.env.example` to `.env` and review. Defaults in `.env.example` are
acceptable for local demo.

```bash
cp .env.example .env
```

Mandatory variables (all fail-fast in `docker-compose.yml` if missing):

- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
- `REDIS_PASSWORD`
- `JWT_SECRET_KEY` (use a strong unique value for any non-throwaway
  deployment; the local default in `.env.example` is fine for demo)

Optional:

- `GEMINI_API_KEY` — leave empty for the deterministic-only demo path. The
  API will report `available=false, provider=none, failureKind=
  provider_unavailable` and scans will land in `REPORT_READY_DEGRADED`
  with deterministic findings intact.

---

## 2. Build the scanner-sandbox runtime image

The Phase-2 sandbox runtime image is **not** built by `docker compose` —
build it once on the host before bringing the stack up:

```bash
# Linux / macOS
./scripts/build-scanner-sandbox-image.sh

# Windows PowerShell
powershell -File scripts\build-scanner-sandbox-image.ps1
```

This produces `sentinelgpt/scanner-sandbox:latest` (python:3.12-slim +
iptables + httpx). ADR-0003 documents the image contents.

Verify the image exists:

```bash
docker images sentinelgpt/scanner-sandbox:latest
```

Expected output:

```
sentinelgpt/scanner-sandbox   latest   <image-id>   <created>   <size>
```

If `prepare()` in `SandboxedScanExecutor` cannot find this image, the
worker raises `SandboxUnavailableError("sandbox image missing: …")`.

> Production note: the image is selected by the `SCANNER_SANDBOX_IMAGE`
> environment variable (default `sentinelgpt/scanner-sandbox:latest`).
> Production deployments should pin an immutable digest
> (e.g. `sentinelgpt/scanner-sandbox:1.4.2@sha256:<digest>`) so a worker
> can never boot a silently-retagged runtime.

---

## 3. Bring up the stack

The committed files compose into a single command. The order is
significant — `docker-compose.local.yml` overrides `docker-compose.yml`
**and** the auto-loaded `docker-compose.override.yml`:

```bash
docker compose \
    -f docker-compose.yml \
    -f docker-compose.override.yml \
    -f docker-compose.local.yml \
    up -d --build
```

What this does:

- `docker-compose.yml` — production-safe base: API, frontend, Postgres,
  Redis. No host port bindings, no worker.
- `docker-compose.override.yml` (auto-loaded by plain `docker compose up`,
  but explicit here for reproducibility) — loopback-only ports
  (`127.0.0.1:8000`, `127.0.0.1:3000`, `127.0.0.1:5432`, `127.0.0.1:6379`),
  hot-reload, debug.
- `docker-compose.local.yml` — adds the worker tier (built from
  `infra/docker/worker.Dockerfile`, mounts `/var/run/docker.sock`,
  `DOCKER_HOST=unix:///var/run/docker.sock`), enables
  `SCANNER_EXECUTION_ENABLED=true` on the API, and installs a Celery
  `inspect ping` healthcheck on the worker.

---

## 4. Verify health

```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml -f docker-compose.local.yml ps
```

Expected:

```
NAME                   STATUS
sentinelgpt-api        Up (healthy)
sentinelgpt-frontend   Up (healthy)
sentinelgpt-postgres   Up (healthy)
sentinelgpt-redis      Up (healthy)
sentinelgpt-worker     Up (healthy)       ← was "unhealthy" before this overlay; now reflects real Celery liveness
```

A **healthy** worker is the proof that `docker-compose.local.yml`'s
healthcheck is in effect. The previous inherited `curl /healthz` from the
API image was meaningless for a Celery process.

API liveness:

```bash
curl -fsS http://127.0.0.1:8000/healthz
```

Redis:

```bash
docker compose exec redis redis-cli -a "${REDIS_PASSWORD}" ping | grep PONG
```

Worker can reach the docker daemon:

```bash
docker compose exec worker docker version --format '{{.Server.Version}}'
```

Scanner-sandbox image visible from the worker:

```bash
docker compose exec worker docker images sentinelgpt/scanner-sandbox --format '{{.Repository}}:{{.Tag}}'
```

---

## 5. Apply database migrations

```bash
docker compose exec api alembic upgrade head
```

(If the API image was built with the auto-loaded dev override, hot-reload
keeps the API process running across the migration.)

---

## 6. Run the live scan acceptance

The committed script exercises the canonical local-dev flow — controlled
test target (`e2e-scan-{suffix}.example.com`, intentionally
non-resolving), full QUEUED→RUNNING→REJECTED lifecycle with
`TargetUnresolvedError` recorded in the audit trail, all
authorization/audit/logout paths:

```bash
docker compose exec api python scripts/e2e_scan_workflow.py
# OR, from the host with the local venv:
.venv/Scripts/python.exe scripts/e2e_scan_workflow.py   # Windows
./.venv/bin/python scripts/e2e_scan_workflow.py          # Linux/macOS
```

Expected last lines:

```
========================================================================
SUMMARY
========================================================================
ALL CHECKS PASSED
```

This script proves:

- target + authorization attestation creation
- scan creation (QUEUED → enqueued to Celery)
- worker pickup (`Task ... received` → `scan_job_task_started` →
  `scan_job_task_finished` → `Task ... succeeded`)
- terminal REJECTED state with the controlled-target failure reason
  (`TargetUnresolvedError`) persisted in the engine-execution row
- empty findings list (`[]`) is the truthful answer for an unresolved
  target — not a bug, the deterministic findings path is only invoked on
  a successful exchange
- JSON + CSV report envelopes still return 200 with the canonical schema
- `SCAN_REQUESTED` + `SCAN_STATE_TRANSITION` audit entries persist with
  `ownerUserId` in metadata
- 401 for unauthenticated access, 404 for cross-tenant access (no
  existence leak), 200 for owner access

---

## 7. Exercise the successful path against a controlled test target

The script above uses an unresolvable hostname on purpose — it covers the
REJECTED branch. To see the **full QUEUED→RUNNING→REPORT_READY_DEGRADED
lifecycle with deterministic findings**, register a target you have
written authorization to scan. The IANA-reserved test domain
**`example.com`** (RFC 2606) is the canonical example; it is documented
as the test target by IANA and accepts HTTPS on port 443 with public,
globally routable addresses that pass the scan-time IP policy.

```bash
# from the host, against the API on 127.0.0.1:8000
.venv/Scripts/python.exe -c '
import httpx, uuid, time
email = f"demo-{uuid.uuid4().hex[:8]}@example.com"
password = "correct-horse-battery-staple-1A!"
with httpx.Client(base_url="http://127.0.0.1:8000", timeout=60) as c:
    c.post("/api/v1/auth/register", json={"email": email, "password": password})
    c.post("/api/v1/auth/login",  json={"email": email, "password": password})
    r = c.post("/api/v1/targets",  json={"hostname": "example.com", "url": "https://example.com/"})
    tid = r.json()["id"]
    c.post(f"/api/v1/targets/{tid}/attestations", json={"method": "SELF_ATTESTATION"})
    r = c.post("/api/v1/scans", json={"targetId": tid, "scanProfile": "quick-check"})
    sid = r.json()["id"]
    for _ in range(120):
        s = c.get(f"/api/v1/scans/{sid}").json().get("status")
        if s in ("REPORT_READY", "REPORT_READY_DEGRADED", "REJECTED", "CANCELLED"):
            print("FINAL:", s)
            break
        time.sleep(1.0)
    rep = c.get(f"/api/v1/scans/{sid}/report?format=json").json()
    print("engines:", [(e["engine_code"], e["status"]) for e in rep["engines"]])
    print("findings:", len(rep["findings"]))
'
```

Expected:

- Lifecycle terminal: `REPORT_READY_DEGRADED`
- Engines: `[("headers-analyzer", "SUCCEEDED")]`
- Findings: 6 deterministic security-header findings (LOW/INFO),
  persisted and returned by `GET /api/v1/scans/{id}/findings`

**`REPORT_READY_DEGRADED`** is the **expected** terminal state when
`GEMINI_API_KEY` is empty: the deterministic scanner chain succeeds and
the findings are persisted; the AI assessment layer reports
`available=false, provider=none, failureKind=provider_unavailable` and
explanations fall back to the deterministic path
(`validationStatus=fallback_used`).

If `GEMINI_API_KEY` is set, the same scan reaches `REPORT_READY` and
explanations are AI-generated.

---

## 8. Tear down

```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml -f docker-compose.local.yml down
```

Volumes (Postgres data, Redis data) are preserved. Add `-v` to wipe them.

---

## Troubleshooting

- **Worker reports `unhealthy`.** The committed healthcheck is
  `celery inspect ping`. If you see `curl: (7) Failed to connect to
  localhost port 8000` in the worker's health log, you are running a
  pre-overlay image. Rebuild with `… up -d --build worker`.
- **`SandboxUnavailableError("… binary not found")`.** The worker image
  was not rebuilt against the new `infra/docker/worker.Dockerfile`.
  Rebuild: `docker compose … build --no-cache worker`.
- **`SandboxUnavailableError("sandbox image missing: …")`.** Step 2 did
  not run. Build `sentinelgpt/scanner-sandbox:latest`.
- **Both the API and the worker report Celery tasks going to
  `celery@<hostname>`.** A stray host-side Celery worker is consuming
  tasks. Stop it; the Docker worker is the canonical processor in this
  stack.

---

## Reference: file layout

| File                                  | Role                                                          |
|---------------------------------------|---------------------------------------------------------------|
| `docker-compose.yml`                  | production-safe base (API, frontend, Postgres, Redis)         |
| `docker-compose.override.yml`         | local-dev override (loopback ports, debug, hot-reload)         |
| `docker-compose.local.yml`            | adds worker, mounts docker.sock, Celery healthcheck, enables scanner gate |
| `docker-compose.production.yml`       | Caddy TLS edge for the public demo                            |
| `infra/docker/scanner-sandbox.Dockerfile` | builds `sentinelgpt/scanner-sandbox:latest`              |
| `infra/docker/worker.Dockerfile`      | derives the worker image from `sentinelgpt-api`, installs the static docker CLI, joins `appuser` to gid 0 |
| `scripts/build-scanner-sandbox-image.sh` | Linux/macOS helper for the scanner-sandbox image         |
| `scripts/build-scanner-sandbox-image.ps1` | Windows PowerShell equivalent                            |
| `scripts/e2e_scan_workflow.py`        | canonical local-dev scan acceptance script                    |
| ADR-0003 (`docs/adr/0003-…`)          | security model of the egress sandbox                          |

---

## Why a separate `local` overlay rather than baking it into base

`docker-compose.yml` is the production-safe base — no worker, no socket
mount, no `SCANNER_EXECUTION_ENABLED`. `docker-compose.production.yml`
must not inherit any of that. Keeping `docker-compose.local.yml` as a
separate, explicit `-f` overlay preserves the production path's invariant
that no `docker.sock` mount can ever be present on a deployed instance.