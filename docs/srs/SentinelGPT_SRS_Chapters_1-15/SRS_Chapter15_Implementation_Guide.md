# Software Requirements Specification
## AI-Assisted Vulnerability Assessment Platform

**Chapter 15 — Implementation Guide**
**Version:** 1.0 (Draft) | **Status:** For Review
**Prerequisite:** Chapters 1–14

> This closing chapter converts Chapters 1–14 from a specification into an actionable, phased build plan — what to build first, why in that order, and how each phase is verified as done before starting the next.

---

## Table of Contents

1. Build Philosophy & Ordering Rationale
2. Phase 0: Environment & Foundations
3. Phase 1: Identity, Targets & Authorization
4. Phase 2: Scanner Engine Integration
5. Phase 3: AI Analysis Integration
6. Phase 4: Reporting & Dashboard
7. Phase 5: Security Hardening, Scale & Launch Readiness
8. Developer Onboarding Checklist
9. Definition of Done (Per Phase)
10. Milestone Summary Table

---

## 1. Build Philosophy & Ordering Rationale

Three principles drive the ordering below, all traceable to earlier chapters:

1. **Authorization before capability.** The attestation model (Chapter 4, Section 8; Chapter 5, Section 5) is built and enforced *before* any real scanning capability exists — never bolted on after scanning already works, since Chapter 1's core ethical positioning depends on this being structurally load-bearing from day one, not a later addition.
2. **One engine, fully correct, before all engines.** Rather than stub out all seven scan engines shallowly, the plan builds one Python-native engine (headers) and one external-tool engine (Nuclei) end-to-end — through normalization, persistence, and the real-time UI — before adding the rest, so the pluggable-engine contract (Chapter 8, Section 1) is validated against reality early, when it's still cheap to adjust.
3. **AI grounding before AI polish.** The evidence-grounding/validation pipeline (Chapter 9) is built and tested with the fallback path exercised deliberately *before* prompt quality is refined — the safety mechanism must exist and be proven before the feature it protects is allowed to reach users.

---

## 2. Phase 0: Environment & Foundations

**Goal:** a running skeleton — no scanning yet — proving the architecture's shape end-to-end.

- Repository scaffolding matching Chapter 3, Sections 3–4's folder structure.
- Docker Compose local environment (Chapter 12, Section 3): `api`, `postgres`, `redis`, `frontend` skeleton.
- FastAPI app boots, `/healthz`/`/readyz` respond (Chapter 6, Section 10).
- Alembic initialized; first migration creates the lookup tables and core identity tables from Chapter 4 (`user`, `organization`, `organization_membership`).
- CI pipeline stood up (Chapter 14, Section 2) — even before there's much to test, the lint/type-check/CI-gate skeleton exists so every subsequent PR is held to standard from the start, not retrofitted later.
- Basic frontend shell with routing (Chapter 7, Section 1) and a working login screen against a stubbed auth endpoint.

**Exit criterion:** a developer can `docker compose up`, register/login, and see an empty authenticated dashboard shell.

---

## 3. Phase 1: Identity, Targets & Authorization

**Goal:** the full authorization chain works before any scan can be requested.

- Complete Auth Service: registration, login, MFA enrollment/verification, token refresh (Chapter 2, Section 9; Chapter 11, Section 8).
- `target` and `authorization_attestation` tables and endpoints (Chapter 4, Section 4.4/8; Chapter 5, Sections 4–5), including self-attestation (`SELF_ATTESTATION` method only in this phase).
- SSRF-prevention target-normalization function (Chapter 2/3/11, Section 6) — built and tested here, since every later phase depends on it.
- `authorizationAttestationGuard` middleware (Chapter 6, Section 2) — wired but with nothing yet to guard except a placeholder `POST /scans` stub that immediately returns `501 Not Implemented` behind the guard, so the guard's enforcement is provably in place before real scanning exists.
- Organization/membership endpoints (Chapter 5, Section 3) and role-based access control.
- Audit log table and the `INSERT`-only DB role permission (Chapter 4, Section 10; Chapter 11) — audit logging begins from this phase's very first attestation event, not retrofitted later.

**Exit criterion:** a user can register a target and submit/confirm an attestation; attempting to bypass the attestation guard via direct API call is provably rejected (a dedicated integration test, per Chapter 13, Section 3).

---

## 4. Phase 2: Scanner Engine Integration

**Goal:** a real scan runs, end to end, through the sandbox, for two representative engines — then expands to all seven.

- Sandbox image (Chapter 12, Section 4) with Katana, Nuclei, Nikto, and the Python-native engine runtime, egress-restricted (Chapter 8, Section 2; Chapter 11, Section 6).
- `scan`, `scan_engine`, `scan_engine_execution`, `finding`, `finding_evidence` tables and the Scan Orchestrator (Chapter 4, Section 5; Chapter 8, Sections 1 & 4).
- **First vertical slice:** `headers-analyzer` (simplest, Python-native) implemented fully — engine wrapper, normalization, fingerprinting (Chapter 8, Section 6), persistence, and the `quick-check` scan profile — proven working against controlled local test targets (Chapter 13, Section 4) before moving on.
- **Immediately after the first slice works — a minimal "raw findings" view, not the full dashboard.** A bare list: scan status, findings with severity and title, nothing else — built the moment `headers-analyzer` produces real data, well before AI (Phase 3) or the polished dashboard (Phase 4) exist. This is a deliberate correction to the phasing below: without it, there's no demoable, "it's alive" milestone until auth, all seven engines, *and* all of AI are done — a long stretch with nothing to look at, which matters for solo-project momentum as much as for stakeholder demos. The full dashboard (trend charts, severity distribution, cross-scan comparison) still waits for Phase 4, once there's enough data across multiple scans to make those visualizations meaningful — this early view is intentionally throwaway-simple, not a first draft of it.
- **Second vertical slice:** `nuclei` (representative of the external-CLI-tool pattern) implemented fully, validating the subprocess-execution and sandbox-integration pattern (Chapter 3, Section 13; Chapter 8, Section 3.2) that the remaining engines will follow.
- Real-time progress channel (Chapter 5, Section 13; Chapter 7, Section 5) built against these two engines.
- Remaining engines (`katana`, `nikto`, `ssl-inspector`, `dns-lookup`, `whois-lookup`) added following the extensibility checklist (Chapter 8, Section 10) — each is now a comparatively mechanical addition given the pattern is proven.
- `standard` and `full-assessment` scan profiles activated once all engines are in place.
- Finding-lifecycle tracking (`finding_status_history`, Chapter 4, Section 6.2) and the `rescan`/`compare` endpoints (Chapter 5, Section 6).

**Exit criterion:** a `full-assessment` scan against a controlled test target completes, populates findings across all seven engines, and a second scan of the same target correctly computes `PERSISTENT`/`RESOLVED`/`NEW` lifecycle status.

---

## 5. Phase 3: AI Analysis Integration

**Goal:** findings become understandable — with the safety net proven before the feature is trusted.

- `ai_explanation`, `executive_summary` tables (Chapter 4, Section 7); Gemini client wrapper (Chapter 3, Section 14; Chapter 6, Section 4).
- Context assembler and per-finding prompt templates (Chapter 9, Sections 2–3).
- **Response validator built and tested first**, against mocked malformed/ungrounded responses (Chapter 13, Section 5), with the fallback-template system (Chapter 9, Section 6) fully populated for every `finding_category` — before the first real Gemini call is wired into the live pipeline.
- Live Gemini integration for per-finding explanation + remediation, with model tiering (Chapter 9, Section 7).
- Executive summary synthesis (Chapter 9, Section 8), including the lifecycle-delta narrative once Phase 2's comparison data is available to draw on.
- Traceability verification (Chapter 9, Section 11) — the "three questions" test becomes part of this phase's own acceptance testing, not deferred.

**Exit criterion:** every finding from a real scan carries either a `VALIDATED` AI explanation or a clearly labeled `FALLBACK_USED` one — never an unvalidated or missing explanation — verified via the traceability test suite (Chapter 13, Section 5).

---

## 6. Phase 4: Reporting & Dashboard

**Goal:** users can act on and share what the platform found.

- Report Data Assembler and PDF pipeline via WeasyPrint (Chapter 10, Sections 1–3), producing the full report template (cover, executive summary, coverage statement, findings, remediation appendix, disclaimer footer).
- JSON/CSV export formatters (Chapter 10, Section 4).
- Async report generation flow and object-storage integration with signed URLs (Chapter 10, Sections 5–6).
- Dashboard aggregate/trend endpoints and UI (Chapter 5, Section 11; Chapter 7) — this is where Phase 2's lifecycle-tracking data and Phase 3's AI severity framing become visible as the risk-trend view promised in Chapter 1, US-13.
- Scan history UI with filtering (Chapter 1, US-15).

**Exit criterion:** a user can generate, download, and share a PDF report that a non-technical reviewer (per the UAT persona scripts, Chapter 13, Section 10) can understand without assistance.

---

## 7. Phase 5: Security Hardening, Scale & Launch Readiness

**Goal:** the platform is ready to demo, submit, and run unattended for real (if modest) usage — defensibly, not necessarily at enterprise scale.

**Required for MVP launch:**
- MVP deployment live (Chapter 12, Section 1 — Docker Compose on one free-tier VM, Caddy/nginx TLS), CI's fast tier plus nightly tier both green (Chapter 14, Section 2).
- Pre-launch review focused on the sandbox isolation boundary and attestation-enforcement path (Chapter 11, Section 3) — a thorough self-review or peer review is a reasonable substitute for a paid external pentest at this stage; the two highest-value invariants (sandbox has no DB path, no scan without confirmed attestation) are both directly testable via the negative-path tests already required in Phase 1/2.
- Vulnerability disclosure policy published; Terms of Use and disclaimer language finalized (Chapter 1, Section 7; Chapter 11, Section 9) — this doesn't require a lawyer for a student project, but it does require the language to actually exist and be accurate.
- Rate-limiting/quota visibility (Chapter 5, Section 15) finalized, including the AI-cost-specific caps from Chapter 9, Section 7 — this is the control that keeps a public demo from silently exceeding a free-tier Gemini quota.
- Full UAT pass and release exit criteria (Chapter 13, Section 10) satisfied.

**Deferred — Future, Production Scale (not blockers, not required to call the MVP done):**
- Kubernetes deployment (Chapter 12, Section 5), autoscaling/KEDA (Chapter 12, Section 8), service mesh/mTLS.
- Progressive/canary rollout (Chapter 14, Section 5) — meaningless without the Kubernetes traffic-routing it depends on.
- Formal external penetration test and a full incident-response tabletop exercise — valuable, worth doing if the project ever handles real user data at scale, but not a precondition for a working, honestly-scoped portfolio demo.
- Notification system (email/in-app, FR-23) — genuinely nice-to-have, not load-bearing for the core "scan → understand → fix" loop.

**Exit criterion (MVP):** all Chapter 13, Section 10 release exit criteria pass; the sandbox-isolation and attestation-enforcement self-review finds no unresolved critical issue; the platform runs live on the Chapter 12, Section 1 deployment via the Chapter 14 process. Everything in the deferred list above can be picked up later without redesigning anything already built — that's the entire point of having designed to the future shape (Chapters 2, 4, 6, 8, 12) while building to the MVP one.

---

## 8. Developer Onboarding Checklist

For any engineer joining the project after Phase 0:

1. Read Chapters 1–3 (Foundations, Architecture, Tech Stack & Standards) in full before writing code — this is the shared vocabulary the rest of the SRS assumes.
2. `docker compose up` the local environment (Chapter 12, Section 3); confirm the seed-data dashboard loads.
3. Run the full local test suite (`pytest`, frontend tests) to confirm a clean baseline before making changes.
4. Read the module-level `README.md` for whichever area they're contributing to first (`scanning/engines/<x>/README.md` per Chapter 3, Section 17, if working in that area).
5. Review the module dependency rules (Chapter 6, Section 11) and branching/PR conventions (Chapter 3, Section 16; Chapter 14, Section 4) before opening a first PR.
6. For anyone touching `scanning/`, `ai/`, or auth/attestation code: read Chapter 11 (Security) in full — these areas carry the 2-reviewer requirement for a reason.

---

## 9. Definition of Done (Per Phase)

A phase is not "done" on feature completion alone. Every phase above must additionally satisfy:

- [ ] All CI gates green (Chapter 14, Section 2) for all code merged in the phase.
- [ ] Unit + integration test coverage targets met for new code (Chapter 3, Section 15).
- [ ] Any new trust-critical path (auth, attestation, SSRF validation, AI validation) has explicit negative-path tests (Chapter 13, Section 3).
- [ ] Relevant chapter(s) of this SRS updated if implementation diverged from the original design (an ADR filed per Chapter 3, Section 17 for any deliberate deviation).
- [ ] Demo-able in staging against controlled test targets, not just passing automated tests.
- [ ] No new critical/high SAST or dependency-scan findings outstanding.

---

## 10. Milestone Summary Table

| Phase | Primary Deliverable | Key Risk Retired |
|---|---|---|
| 0 — Foundations | Running skeleton, CI/CD scaffolding | Architectural assumptions validated early |
| 1 — Identity & Authorization | Attestation-gated target registration | Unauthorized-scanning risk (R-01) addressed before scanning exists |
| 2 — Scanner Engine | Full multi-engine scanning with lifecycle tracking | Sandbox/SSRF risk (R-03, R-04) and tool-integration risk retired |
| 3 — AI Analysis | Grounded, validated, traceable AI explanations | Hallucination risk (R-02) retired via proven validator + fallback |
| 4 — Reporting & Dashboard | Shareable reports, trend dashboard | Core user value (US-09–US-15) delivered end-to-end |
| 5 — Hardening & Launch | Production-grade deployment, pen-tested | Launch-readiness and legal/compliance risk (R-05, R-06) addressed |

---

*End of Chapter 15, and of this Software Requirements Specification (Chapters 1–15). Together, these chapters define not only what the AI-Assisted Vulnerability Assessment Platform does, but why it is structured the way it is — a platform whose database, API, scanning subsystem, AI layer, and deployment model are all built around the reality that a vulnerability assessment is a recurring, evolving, authorization-bound relationship between a target and its owner, not a single disposable transaction.*
