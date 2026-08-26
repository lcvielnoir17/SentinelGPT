# ADR-0009: Scan Lifecycle, Authorization & API Boundary

**Status:** Implemented (v1 lifecycle + attestation authorization live; execution gate OPEN only through the Phase 7 composition root)
**Date:** 2026-08-27
**Extends:** ADR-0003/0006/0007

## Lifecycle (SRS Chapter 2 §10 codes, unchanged)

```text
PENDING_ATTESTATION → QUEUED → RUNNING → SCAN_COMPLETE|PARTIALLY_COMPLETE
                                        ↘ REJECTED
QUEUED/RUNNING-side exits: CANCELLED (pre-RUNNING only), REJECTED
SCAN_COMPLETE/PARTIALLY_COMPLETE → AI_ANALYSIS → REPORT_READY|REPORT_READY_DEGRADED
```

`domain/scans/lifecycle.py` validates every edge; invalid transitions raise
409 `SCAN_INVALID_STATE`. Terminal states accept nothing.

## Authorization boundary — registration ≠ authorization

A target becomes scannable ONLY while it holds a CONFIRMED, unexpired
`authorization_attestation` (SRS Ch. 4 §8). Phase 7 ships SELF_ATTESTATION
(auto-confirm); revocation is immediate and historical. The gate fires TWICE:

1. `POST /scans` → 403 `ATTESTATION_NOT_CONFIRMED` without one;
2. **re-check at RUNNING transition** inside the background job — a revoked/
   expired attestation flips the scan to REJECTED before any engine work.

Every scan row stores the SPECIFIC `authorization_attestation_id` that
authorized it (audit trail).

## Execution decision — gate opened deliberately

The library default remains `enable_execution=False`
(`scanning/runner.py`). The composition root
(`domain/scans/pipeline.py`) is the single place constructing the executor
with `enable_execution=True`, wiring the exact Phases 2–6 chain:

    PlatformDnsResolver → resolution+policy → DockerEgressSandbox
    (privilege-dropped) → sandbox-bound transport → analysis engine

Entry criteria verified before opening (all satisfied):
authorization boundary ✓ · tenant isolation ✓ · sandbox mandatory ✓ ·
transport sandbox-bound ✓ · engine via EngineServices only ✓ · resolver-only
DNS ✓ · kernel egress ✓ · redirect revalidation ✓ · AI downstream ✓ ·
fail-closed paths ✓ · negative tests for gate default ✓.

Additionally, background jobs are scheduled by the API ONLY when
`settings.scanner_execution_enabled=True` (default False) — a second,
operations-level switch so first deploys cannot execute scans accidentally.

## Persistence (migration 0004)

Minimal SRS-shaped schema: `scan_profile` lookup (seeded), `scan`, `scan`,
`authorization_attestation`, `scan_engine_execution` (subset), `scan_finding`,
`scan_ai_assessment` (JSONB canonical payload). Lookups from Phase 0 were
already seeded. Findings remain authoritative; assessments are documents
referencing them (`is_available=false` + `failure_kind` when degraded).

## Concurrency

Optimistic transitions: `try_transition(scan_id, from→to)` updates rows only
when still in the expected status; losing claimants abort. Worker crash in
RUNNING leaves the row RUNNING (documented; manual requeue is out of scope
until a worker layer exists).

## Cancellation — honest limitation

CANCELLED is reachable only pre-RUNNING. In-flight termination of the
blocking pipeline is not yet supported; cancelling a RUNNING scan returns
409 instead of faking state.

## Failure semantics

Pipeline crash ⇒ FAILED execution (type-name-only error) + scan REJECTED.
AI unavailable ⇒ REPORT_READY_DEGRADED with unavailable-assessment document.
Findings are never lost to AI or transport failures.

## API boundary

`/scans` (POST 202/GET list/detail/cancel/findings/assessment) and
`/targets/{id}/attestations` + `/attestations/{id}/revoke`, camelCase DTOs,
`CurrentUser` auth, DomainError envelopes, cross-tenant reads masked as 404.
Frontend intentionally deferred.
