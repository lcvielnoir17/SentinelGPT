# SentinelGPT

SentinelGPT is an AI-assisted vulnerability assessment and intelligence platform designed as an analyst-support system. It correlates heterogeneous findings from multiple authorized security tools, enriches them with contextual information, and uses evidence-grounded AI to assist human analysts in prioritization, explanation, and triage.

## Core Principles

- **Analyst-Support System:** Human analysts remain responsible for reviewing and approving security decisions.
- **Evidence-Grounded AI:** AI explains deterministic scanner evidence; it does not originate findings or alter canonical severity.
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
3. Copy environment configuration:
   ```bash
   cp .env.example .env
   ```
4. Run tests:
   ```bash
   pytest
   ```
