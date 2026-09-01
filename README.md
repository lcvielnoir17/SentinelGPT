# SentinelGPT

SentinelGPT is an AI-powered vulnerability-analysis platform in which the AI is the primary analytical component. The system automatically ingests findings from authorized security tools, normalizes them, correlates related findings, deduplicates them, assesses severity and risk, prioritizes vulnerabilities, explains findings using available evidence, and generates security reports.

## Core Principles

- **AI-Driven Analysis Pipeline:** Ingestion, normalization, correlation, deduplication, severity/risk assessment, prioritization, explanation, and reporting run automatically; no human-approval step is required to operate the platform.
- **Evidence-Grounded AI:** AI explains deterministic scanner evidence; it does not originate findings or alter canonical severity.
- **Research Evaluation Only:** Human experts participate only during research evaluation, to establish ground truth and measure accuracy, reliability, and reproducibility — never as a required operational step.
- **Strict Authorization:** Mandatory proof of authorization prior to scanning.
- **Defense in Depth:** Egress-restricted ephemeral sandbox scan runtime.

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
