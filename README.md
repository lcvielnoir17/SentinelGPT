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
