# Software Requirements Specification
## AI-Assisted Vulnerability Assessment Platform

**Document Type:** Software Requirements Specification (SRS)
**Chapter:** 3 — Technology Stack & Coding Standards
**Version:** 2.0 (Revised Draft)
**Status:** For Review
**Prerequisite:** Chapter 1 (Foundations), Chapter 2 (System Architecture)

> **Note on continuity with Chapter 2:** Chapter 2 described the architecture in technology-neutral terms to establish the *shape* of the system first. This chapter pins down the concrete technology choices. Where a specific stack is mandated (Python, FastAPI, SQLAlchemy, Alembic, Gemini, Katana, Nuclei, Nikto), those choices are treated as fixed constraints for the remainder of this SRS and all subsequent design documents. One deviation from Chapter 2 is called out explicitly: the AI layer now targets **Google Gemini** as the LLM provider rather than a generic "LLM provider API" — the evidence-grounding and validation architecture from Chapter 2, Section 6 remains unchanged and applies identically to Gemini.

---

## Table of Contents

1. Technology Stack Overview
2. Backend Stack
3. Scanner Tooling Stack
4. AI Stack
5. Database & Migration Stack
6. Frontend Stack
7. Infrastructure & DevOps Stack
8. Technology-to-Architecture Mapping
9. Coding Standards — Python/Backend
10. Coding Standards — API Design
11. Coding Standards — Database & Migrations
12. Coding Standards — Frontend
13. Coding Standards — Scanner Integration
14. Coding Standards — AI Integration
15. Testing Standards
16. Version Control & Branching Strategy
17. Documentation Standards
18. Security Coding Standards

---

## 1. Technology Stack Overview

### Research-aligned implementation rule

The implementation must preserve the boundary between **fact generation** and **AI interpretation**. Scanner adapters and deterministic correlation/enrichment code establish canonical evidence and relationships; Gemini is used only for evidence-grounded interpretation, explanation, and narrative synthesis. Any model output that could alter canonical findings, severity, lifecycle status, or authorization state must be rejected by the application.

| Layer | Technology | Status |
|---|---|---|
| Backend Language/Framework | **Python 3.12+ / FastAPI** | Fixed |
| ORM | **SQLAlchemy 2.x** | Fixed |
| Database Migrations | **Alembic** | Fixed |
| AI / LLM Provider | **Gemini** | Fixed |
| Web Crawler Engine | **Katana** | Fixed |
| Vulnerability Scanner Engine | **Nuclei** | Fixed |
| Web Server Scanner Engine | **Nikto** | Fixed |
| Relational Database | PostgreSQL | Recommended (Chapter 2 alignment) |
| Job Queue / Async Task Runner | Celery + Redis (or RQ + Redis) | Recommended |
| Cache | Redis | Recommended |
| Object Storage | S3-compatible storage | Recommended |
| Frontend Framework | React (TypeScript) | Recommended |
| Containerization & Orchestration | **Docker Compose, single host** | **MVP (this is what gets built)** |
| Orchestration (at scale) | Kubernetes (or managed container service) | **Future — not required for MVP, not blocked on by it (Chapter 12)** |
| CI/CD | GitHub Actions (or equivalent) | Recommended |

The five items in **Fixed** status are non-negotiable constraints for this project per direct requirement and drive several architectural decisions below (notably: Python subprocess/async orchestration around CLI-based scanners, and Gemini-specific prompt/response handling in the AI layer). Everything marked **MVP** in this chapter is what actually gets built first; everything marked **Future** is architecturally anticipated (nothing here would need to be redesigned to add it later) but is explicitly not required to ship a working, demoable, portfolio-quality platform. See Chapter 12, Section 1 for the full MVP-vs-future breakdown.

---

## 2. Backend Stack

### 2.1 Core Framework
- **Python 3.12+** — chosen version floor to guarantee access to modern typing features (`TypedDict`, structural pattern matching, improved async performance) used throughout the coding standards below.
- **FastAPI** — serves as the API Gateway layer described in Chapter 2, Section 8. FastAPI is selected (by requirement) for its native async support (critical given scan orchestration is I/O-bound), automatic OpenAPI schema generation, and first-class Pydantic integration for request/response validation.
- **Pydantic v2** — used for all request/response schemas and for the internal `Finding`/`Scan` data contracts referenced in Chapter 2. Pydantic models double as the authoritative schema definition surfaced in FastAPI's auto-generated OpenAPI docs.
- **Uvicorn (with Gunicorn as process manager in production)** — ASGI server for running FastAPI.

### 2.2 Async & Concurrency
- **`asyncio`** as the concurrency backbone for the API tier (non-blocking DB calls, non-blocking calls out to Celery/Redis).
- **Celery** (or RQ, see Section 7) for the scan worker tier — scan execution is long-running, CPU/I-O mixed, and process-isolatable, which fits Celery's task-queue model better than in-process asyncio tasks. This is the concrete implementation of the "Job Queue → Scan Worker Pool" flow from Chapter 2, Section 1.

### 2.3 Supporting Libraries (non-fixed, recommended)
| Purpose | Library |
|---|---|
| DNS lookups | `dnspython` |
| WHOIS lookups | `python-whois` (or shell-out to system `whois` with strict input sanitization) |
| SSL/TLS inspection | `sslyze` (Python-native) — invoked from the same sandboxed scan-engine pattern as Katana/Nuclei/Nikto |
| HTTP client (headers analysis, crawler support calls) | `httpx` (async-native, pairs naturally with FastAPI) |
| PDF generation | `WeasyPrint` or `ReportLab` |
| Structured logging | `structlog` |

---

## 3. Scanner Tooling Stack

Per Chapter 2, Section 5 (pluggable engine registry), each of the following fixed tools is wrapped as an independent scan engine module conforming to the shared engine interface (`run()`, `normalizeOutput()`, `riskWeight`). All three are **CLI-based Go binaries**, which means the Python backend interacts with them via **sandboxed subprocess execution**, not native library calls — this is the central integration pattern for this stack and is elaborated in Section 13.

| Tool | Role in Platform | Maps to Engine |
|---|---|---|
| **Katana** | Web crawler — discovers pages, endpoints, forms, JS-linked assets within the authorized target. | `crawler` engine |
| **Nuclei** | Template-based vulnerability scanner — detects known CVEs, misconfigurations, exposed panels, outdated software fingerprints using community/custom templates. | `vulnerability` engine (primary) |
| **Nikto** | Web server scanner — checks for dangerous files, outdated server software, server misconfigurations. | `vulnerability` engine (secondary/complementary) or a dedicated `webserver-scan` engine |

**Design implication:** because Nuclei and Nikto both contribute to the "vulnerability" category but with different methodologies (template-matching vs. signature-based server checks), their raw outputs are normalized into the **same canonical `Finding` schema** before reaching the AI layer, tagged with a `source_engine` field (`nuclei` or `nikto`) so duplicate/overlapping findings can be deduplicated or cross-referenced rather than shown twice with conflicting severity.

**Header analysis, SSL inspection, DNS, and WHOIS** are not covered by Katana/Nuclei/Nikto and remain Python-native engines (using `httpx`, `sslyze`, `dnspython`, `python-whois` respectively) per Section 2.3, run through the same sandbox as the Go-binary tools.

---

## 4. AI Stack

- **Gemini** is the fixed LLM provider for the AI Orchestration Service (Chapter 2, Section 6). The orchestration logic, evidence-grounding, and response-validation architecture defined in Chapter 2 remain provider-agnostic in *design* but are implemented concretely against Gemini's API in this stack.
- **Structured output enforcement:** Gemini's structured/JSON output mode (function-calling or JSON-schema-constrained generation, depending on the specific Gemini model/version in use) is used to enforce the constrained response schema described in Chapter 2, Section 6.2 — the model is instructed and schema-constrained to only reference `findingId`s supplied in the prompt context.
- **Model selection principle (MVP-pinned):** for the MVP, **both** tiers are pinned to free-tier-eligible Gemini models — a Flash-Lite-class model for per-finding explanations (high volume, lower complexity) and a Flash-class model for executive-summary synthesis (lower volume, needs slightly more cross-finding reasoning). Neither tier depends on a Pro-class or other paid-only model; the two-tier *structure* is what's architecturally load-bearing (Chapter 9, Section 7), and the specific model name behind each tier is a one-line config value, not a hardcoded assumption — swapping either tier to a different Gemini model later (paid or not) requires no redesign.
- **Free-tier budget awareness:** free-tier Gemini quotas run on the order of low-double-digit requests per minute and roughly 1,000+ requests per day (subject to change — verify current limits before relying on a specific number). A `full-assessment` scan generating 15–35 Gemini calls (per-finding + one executive summary) comfortably fits this for realistic student/demo usage; Chapter 9, Section 7's bounded-concurrency dispatch is specifically tuned to stay under the *per-minute* ceiling, not just the daily one.
- **Python SDK:** the official `google-genai` (or successor) Python client library is the only sanctioned integration path — no direct raw HTTP calls to Gemini endpoints from application code, so that SDK-level retry/backoff and safety settings are consistently applied. All calls implement exponential-backoff retry on rate-limit (`429`) responses and degrade to Chapter 9's deterministic fallback path rather than failing the scan outright if retries are exhausted.

---

## 5. Database & Migration Stack

- **SQLAlchemy 2.x** (fixed) — used exclusively in its modern declarative + `Mapped[...]` typed style, not the legacy 1.x query API, to keep model definitions statically type-checkable.
- **Alembic** (fixed) — sole mechanism for schema changes. No manual/ad-hoc DDL against any environment above local development.
- **PostgreSQL** (recommended) — chosen for the relational entity model established in Chapter 2, Section 7 (Users, Organizations, Targets, Scans, Findings, AIExplanations, Reports, AuditLogEntries), and for native support of JSONB columns (useful for storing variable-shaped raw tool output alongside the normalized relational `Finding` schema).
- **Async DB access:** SQLAlchemy's async engine (`asyncpg` driver) is used to keep the FastAPI request path non-blocking, consistent with Section 2.2.

---

## 6. Frontend Stack

- **React (TypeScript)** — implements the feature-domain folder structure defined in Chapter 2, Section 4. Used consistently throughout Chapter 7 and treated as the project's practical frontend choice; formally it remains "recommended" rather than one of the eight explicitly fixed technologies, but no alternative is contemplated anywhere else in this SRS.
- **API contract generation:** frontend TypeScript types and API client functions are **generated from FastAPI's OpenAPI schema** (`/api/v1/openapi.json`, Chapter 5, Section 17) via `openapi-typescript` (or equivalent) as a build step — never hand-maintained duplicate interfaces. This replaces the earlier "kept in sync manually" approach; see Chapter 7, Section 7 for the workflow.
- **State/data-fetching:** a query-caching library (e.g., TanStack Query) for server-state (scans, findings, reports) separate from local UI state.
- **Real-time updates:** native WebSocket client (or SSE client) to consume the scan-progress channel described in Chapter 2, Section 8.
- **Styling:** a component/design-system approach (Tailwind CSS or equivalent) to support the accessibility target in NFR-12 (Chapter 1).

---

## 7. Infrastructure & DevOps Stack

| Concern | MVP ($0 budget) | Future (if the project ever scales) |
|---|---|---|
| Containerization | Docker | Docker (unchanged) |
| Orchestration | **Docker Compose, single host** (own machine for dev; one free-tier VM — e.g. Oracle Cloud Always Free, Fly.io, Render free tier — for a public demo) | Kubernetes (or managed equivalent) — enables horizontal scaling per Chapter 2, Section 14; see Chapter 12 |
| Job Queue Broker | Redis (as Celery broker), same container also serving as cache (Chapter 2, Section 1) — logically separated by Redis DB index, one piece of infrastructure | Same, potentially split into dedicated instances at higher load |
| Secrets Management | A git-ignored `.env` file (never committed; documented in `.gitignore`), loaded via Pydantic `BaseSettings` (Chapter 6, Section 5) | Cloud provider secrets manager (AWS/GCP Secrets Manager) or HashiCorp Vault |
| Object Storage | Local Docker volume, accessed through a storage-abstraction interface (Chapter 12, Section 1) so the report/scanner code never knows the difference | S3-compatible bucket — swapping in requires only a new storage-client implementation behind the same interface |
| CI/CD | GitHub Actions — fast PR-gate tier (lint, type-check, unit tests, SAST, dependency scan) | Same tool, additional nightly/release-only workflow tier for expensive suites (Chapter 14, Section 2) |
| Observability | Structured logging (`structlog`) to stdout, readable via `docker compose logs`; optionally a free-tier error tracker (e.g., Sentry's free plan) for exception visibility | Centralized log aggregator + Prometheus-compatible metrics/Grafana dashboards |

Every row's Future column is a drop-in replacement behind an interface already established elsewhere in this SRS (the storage abstraction, the `SandboxRunner` abstraction in Chapter 6/8/12, the secrets-loading `BaseSettings` pattern) — none of it requires redesigning application code, only swapping what's behind the interface.

---

## 8. Technology-to-Architecture Mapping

Quick cross-reference back to Chapter 2's component list, now with concrete technology assigned:

| Chapter 2 Component | Chapter 3 Technology |
|---|---|
| API Gateway / Backend Service | FastAPI (Python) |
| Auth Service | FastAPI module + `passlib`/`argon2-cffi` for hashing, `python-jose`/`PyJWT` for tokens |
| Job Queue | Redis (Celery broker) |
| Scan Worker Pool | Celery workers (Python) |
| Sandboxed Scan Runtime | Docker container invoking Katana / Nuclei / Nikto / Python-native engines via subprocess |
| AI Orchestration Service | Python service using `google-genai` SDK against Gemini |
| Primary Database | PostgreSQL via SQLAlchemy 2.x (async) |
| Database Migrations | Alembic |
| Object Storage | S3-compatible bucket |
| Cache | Redis |
| Audit Log Store | Append-only PostgreSQL table (restricted grants) or dedicated write-once log service |

---

## 9. Coding Standards — Python/Backend

- **Style guide:** PEP 8, enforced via `ruff` (lint) and `black` (formatting) in pre-commit hooks and CI — no manual style debates in code review.
- **Type hints are mandatory** on all function signatures and class attributes; `mypy` (or `pyright`) run in strict mode in CI. Given SQLAlchemy 2.x's typed `Mapped[...]` support and Pydantic v2's native typing, the codebase should have near-complete static type coverage.
- **Project layout** follows the domain-driven structure from Chapter 2, Section 3 (`api/`, `domain/`, `scanning/`, `ai/`, `reporting/`, `infrastructure/`, `workers/`).
- **Naming conventions:**
  - Modules/files: `snake_case.py`
  - Classes: `PascalCase`
  - Functions/variables: `snake_case`
  - Constants: `UPPER_SNAKE_CASE`
  - Pydantic schema classes suffixed by purpose: `ScanCreateRequest`, `ScanResponse`, `FindingRead`
- **Dependency injection:** FastAPI's native `Depends()` system is the standard mechanism for injecting DB sessions, current-user context, and service instances into route handlers — no global mutable state.
- **No business logic in route handlers.** Route handlers in `api/routes/` are thin: parse/validate input (via Pydantic), call into `domain/` services, return response models. All actual logic (scan lifecycle rules, attestation checks, scoring) lives in `domain/`.
- **Error handling:** raise domain-specific exceptions (e.g., `AuthorizationAttestationMissingError`) caught by a centralized FastAPI exception handler that maps them to structured HTTP error responses (Chapter 2, Section 11) — never let raw exceptions/stack traces reach the client.

---

## 10. Coding Standards — API Design

- **Versioned routes:** all endpoints under `/api/v1/...`; breaking changes require a new version prefix, not in-place modification.
- **Resource-oriented REST conventions:** `POST /targets`, `POST /scans`, `GET /scans/{id}`, `GET /scans/{id}/findings`, `GET /reports/{id}` — verbs only for actions without a clean resource mapping (e.g., `POST /scans/{id}/cancel`).
- **Consistent response envelope** for errors: `{ "error": { "code": "...", "message": "...", "requestId": "..." } }`.
- **OpenAPI schema is the source of truth** for the API contract; FastAPI's auto-generated schema (from Pydantic models) must stay accurate — no undocumented/manually-patched endpoints.
- **Long-running operations return `202 Accepted`** with a resource ID and status URL (per Chapter 2, Section 8's request-accepted pattern) — never a synchronous block on scan completion.
- **Pagination** required on all list endpoints (scan history, findings, audit logs) using cursor-based or offset/limit pagination consistently applied.

---

## 11. Coding Standards — Database & Migrations

- **Every schema change goes through an Alembic migration file** — no direct manual DDL against staging/production, even for "quick fixes."
- **Migrations are reviewed like code** (in the same PR as the model change) and must include a tested downgrade path where feasible.
- **SQLAlchemy models** live in `infrastructure/database/` with one module per aggregate (e.g., `scan_models.py`, `finding_models.py`), separate from the domain entities in `domain/` — the domain layer should not import SQLAlchemy directly, keeping business logic persistence-agnostic (repository pattern).
- **Repositories, not raw queries, in domain/service code.** Query construction lives in `infrastructure/database/repositories/`; services call repository methods (`scan_repository.get_by_id(...)`) rather than building SQLAlchemy queries inline.
- **Indexing standard:** every foreign key column is indexed by default; additional indexes added deliberately based on query patterns (e.g., `scans(target_id, created_at)` for history views), documented in the migration's commit message.
- **Audit log table constraints:** enforced at the database permission level as append-only (`INSERT`-only grant for the application role; no `UPDATE`/`DELETE` grants at all), not merely by application-layer convention.

---

## 12. Coding Standards — Frontend

- **TypeScript strict mode** enabled project-wide; no implicit `any`.
- **Feature-folder structure** per Chapter 2, Section 4 — shared/reusable UI in `shared/components`, feature-specific UI stays within its feature folder.
- **API access only through the centralized `apiClient`** (Chapter 2, `services/apiClient.ts`) — no ad-hoc `fetch()` calls scattered through components. `apiClient` reads the in-memory access token (Chapter 2, Section 9) to set the `Authorization` header, transparently calls `/auth/refresh` and retries once on a `401`, and never touches the refresh cookie directly (the browser manages that). All request/response types come from the generated OpenAPI client (Section 6) — no hand-written duplicate interfaces.
- **Component naming:** `PascalCase` for components, `useCamelCase` for hooks.
- **No inline secrets or API keys** in frontend code — the Gemini API key and all backend secrets are never exposed client-side; the frontend only ever talks to the Platform's own API Gateway.
- **Accessibility:** semantic HTML, ARIA labels on interactive/report elements, keyboard-navigable dashboards, in line with NFR-12.

---

## 13. Coding Standards — Scanner Integration

Since Katana, Nuclei, and Nikto are external CLI binaries rather than Python libraries, their integration follows a strict, uniform pattern to keep the "pluggable engine" contract from Chapter 2 intact:

- **Subprocess execution only within the sandbox container** (never from the API or worker process directly) — the worker dispatches a sandboxed job; it does not `subprocess.run()` a scanner binary in its own process space.
- **Pinned tool versions.** Katana, Nuclei, and Nikto versions are pinned in the sandbox Docker image (explicit version tags, not `:latest`), with updates going through the same CI/security-review pipeline as application code changes, since scanner-tool updates can change output format or introduce new template behavior.
- **Nuclei templates are version-controlled and reviewed.** Custom or curated Nuclei template sets used by the Platform are stored in-repo (or a pinned template-repo commit), not pulled dynamically and unreviewed at scan time, to keep scan behavior deterministic and auditable.
- **Command construction never uses raw string interpolation** with user-supplied target values — target URLs/domains are validated (Chapter 2, Section 13 — SSRF prevention) and passed as discrete subprocess arguments (e.g., Python's `subprocess.run([...], shell=False)`), never through `shell=True` string concatenation, to eliminate command-injection risk.
- **Output parsing is isolated per tool.** Each of `KatanaEngine`, `NucleiEngine`, `NiktoEngine` has its own `normalizeOutput()` implementation converting tool-specific JSON/text output into the canonical `Finding` schema — parsing logic for one tool must never leak into another's module.
- **Timeouts are mandatory** on every subprocess invocation, with a hard kill if exceeded, to prevent a single hung tool invocation from stalling an entire scan job indefinitely.
- **Exit-code and stderr handling:** non-zero exit codes are captured and recorded as partial-failure findings (per Chapter 2's `PARTIALLY_COMPLETE` scan state) rather than silently ignored or treated as fatal for the whole scan.

---

## 14. Coding Standards — AI Integration

- **All Gemini calls go through the single `llmClient` wrapper** (Chapter 2's `ai/llmClient.ts` equivalent, implemented in Python as `ai/gemini_client.py`) — no direct SDK calls scattered across the codebase, so retry/backoff, timeout, and safety-setting configuration stay centralized.
- **Prompt templates are version-controlled files** (not inline strings scattered through code), stored under `ai/prompt_builders/`, so prompt changes are reviewable diffs with their own change history.
- **Every Gemini request includes only structured `Finding` context**, never a raw/full scan dump, per the evidence-grounding principle in Chapter 2, Section 6.1.
- **Evidence is explicitly delimited and marked untrusted.** Every prompt template's system instructions state, verbatim, that the supplied evidence is data extracted from the scanned target and must never be treated as instructions, regardless of its content (Chapter 9, Section 3) — this applies even though evidence is already normalized/structured, since a structured field can still contain attacker-influenced text (e.g., a response header value).
- **AI claims must reference specific evidence, not just gesture at a finding.** The structured response schema requires each claim to carry `evidenceReferences` pointing to real `finding_evidence.id` values (Chapter 9, Section 4); the validator confirms those IDs exist, belong to the finding in question, and were actually part of the context sent for that call — not merely present somewhere in the database.
- **Schema validation is mandatory on every AI response** before persistence — the response validator (Chapter 2, Section 6.2) is a required step in the pipeline, not optional/bypassable for any code path, including manual/admin-triggered re-analysis.
- **Fallback explanations are pre-written, reviewed, deterministic templates** stored in code (not themselves AI-generated at request time), so a Gemini outage or validation failure degrades to a known-safe, human-reviewed explanation rather than an unpredictable one.
- **Rate-limit resilience is mandatory, not optional.** Every Gemini call path implements bounded concurrency, exponential-backoff retry on `429`, and a graceful fall-through to the deterministic fallback path if retries are exhausted (Chapter 9, Section 7) — the architecture never assumes unlimited or always-available Gemini capacity, which matters concretely on a free-tier quota.
- **Cost/latency tiering convention** (Section 4): explicitly configure which Gemini model tier a given prompt builder uses, documented alongside the prompt template itself — pinned to free-tier-eligible models for the MVP.

---

## 15. Testing Standards

| Test Type | Scope | Tooling |
|---|---|---|
| Unit tests | Domain logic, scan-state machine transitions, `normalizeOutput()` parsers, prompt builders (input→prompt structure, not live LLM calls) | `pytest` |
| Integration tests | API endpoints against a test DB (via `pytest` + test containers), Alembic migration up/down verification | `pytest`, `testcontainers` |
| Scanner engine tests | Katana/Nuclei/Nikto wrappers tested against controlled, intentionally-vulnerable local test targets (never live third-party sites) | `pytest` + local Docker test fixtures |
| AI validation tests | Response-validator logic tested against both well-formed and deliberately malformed/ungrounded mock Gemini responses, to verify the fallback path actually triggers | `pytest` with mocked Gemini client |
| Security tests | SAST (e.g., `bandit` for Python), dependency vulnerability scanning (e.g., `pip-audit`), container image scanning | CI pipeline gate |
| Frontend tests | Component tests, critical user-flow tests (login → scan → report) | Vitest/Jest + Testing Library, Playwright/Cypress for E2E |
| Coverage target | ≥ 80% on `domain/` and `scanning/` normalization logic; AI validator logic at 100% branch coverage given its trust-critical role | Enforced in CI |

**Non-negotiable test gate:** no PR touching `authorizationAttestationGuard`, the scan-state machine, or the AI response validator merges without passing tests specifically covering the negative/rejection paths (missing attestation, invalid AI output, SSRF-attempt target) — these are the Platform's core trust guarantees.

---

## 16. Version Control & Branching Strategy

- **Trunk-based development** with short-lived feature branches (`feature/<ticket-id>-short-description`), merged via reviewed pull requests — no long-lived divergent branches.
- **Branch naming:** `feature/...`, `fix/...`, `chore/...`, `security/...` (security-flagged branches get mandatory security-team review).
- **Commit convention:** Conventional Commits style (`feat:`, `fix:`, `chore:`, `security:`, `docs:`) to support automated changelog generation.
- **Required PR checks before merge:** lint, type-check, unit + integration tests, SAST, dependency scan — all must pass; at least one reviewer approval, two for changes touching `scanning/`, `ai/response_validators/`, or `infrastructure/secrets/`.
- **No direct commits to `main`/`release` branches** — enforced via branch protection rules.
- **Alembic migrations and their corresponding model changes are committed together** in the same PR, never split across separate PRs, to avoid drift between migration history and model definitions.

---

## 17. Documentation Standards

- **Docstrings mandatory** on all public functions/classes in `domain/`, `scanning/`, and `ai/` modules (Google-style or NumPy-style docstrings, consistently chosen project-wide).
- **API documentation** is auto-generated from FastAPI's OpenAPI schema and treated as always-current (enforced by the "no undocumented endpoints" rule in Section 10) rather than maintained as separate hand-written API docs.
- **Architecture Decision Records (ADRs):** any deviation from this chapter's fixed stack, or any significant new architectural choice (e.g., choosing Celery vs. RQ, choosing a specific Redis topology), is recorded as a short ADR in-repo (`/docs/adr/`), so the reasoning is preserved for future maintainers.
- **Runbooks** required for operational procedures with security implications: sandbox image update process, Gemini API key rotation, Nuclei template update/review process, incident response for a suspected unauthorized-scan attempt.
- **README per module** in `scanning/engines/<engine-name>/` describing the wrapped tool's version, invocation pattern, and known output-format quirks — critical given three of the four vulnerability-facing engines are external CLI tools whose behavior can shift between versions.

---

## 18. Security Coding Standards

These standards apply on top of (not instead of) the architectural security controls defined in Chapter 2, Section 13:

- **No `shell=True` in any subprocess invocation**, ever — enforced via a `bandit` CI rule specifically targeting this pattern given the Platform's reliance on CLI-based scanner tools (Section 13).
- **No direct Docker socket access from worker code.** Sandbox provisioning goes through the `SandboxRunner` abstraction (Chapter 6, Section 8; Chapter 8, Section 2) — a `DockerSandboxRunner` implementation for the MVP, a `KubernetesSandboxRunner` for later — so a Celery worker process never holds unrestricted access to `/var/run/docker.sock`, which is effectively host-root-equivalent if ever misconfigured or exposed.
- **All user-supplied target values pass through a single, shared validation/normalization function** before being used in any scan engine invocation, DNS lookup, or WHOIS query — no engine is permitted to implement its own ad-hoc target parsing, to keep the SSRF-prevention logic (Chapter 2, Section 13) in exactly one place.
- **Secrets never logged.** Gemini API keys, DB credentials, and object storage credentials are excluded from all log output via structured-logging field redaction (`structlog` processors), verified in CI via a log-scrubbing test.
- **Dependency pinning:** all Python dependencies pinned via `poetry.lock` / `requirements.txt` with hashes; Katana/Nuclei/Nikto versions pinned in the Dockerfile as noted in Section 13.
- **Principle of least privilege in code:** database repository methods are scoped per aggregate (e.g., a `FindingRepository` cannot delete `User` records) — this is enforced structurally by the repository pattern (Section 11), not just by convention.
- **Authorization checks happen server-side only.** No security-relevant decision (attestation validity, role permission, scan-quota check) is ever made by trusting a client-supplied flag; the backend independently re-verifies on every request, even if the frontend already gated the action in the UI.
- **Rate-limit and quota checks are re-validated at the point of execution** (job dequeue time), not only at request-acceptance time, to close the gap between "request accepted" and "job actually runs" (Chapter 2, Section 13 — FR-22).

---

*End of Chapter 3. Chapter 4 (Data Model & Schema Design) will translate the entities from Chapter 2's ER diagram into concrete SQLAlchemy models and Alembic migration definitions consistent with the standards set here.*
