# ADR-0007: First Scanner Engine & Execution-Gate Posture

**Status:** Implemented (engine live-proven; production execution gate remains CLOSED by default)
**Date:** 2026-08-26
**Extends:** ADR-0003/0004/0005/0006

## Engine: HttpSecurityAnalysisEngine

Passive-only analysis of ONE logical response obtained exclusively through
the Phase 4 sandbox-aware transport:

    execute(context, services)
      → services.http_client_factory()   # SandboxHttpClient, sandbox-bound
      → HttpScanRequest.authorize(...)   # pinned destination from binding
      → one GET to OriginSpec(scheme,port,path)
      → observations → deterministic findings

Capabilities the engine does NOT have (structurally, not by convention):
DNS resolution, sockets, subprocesses, Docker access, its own transport
instance, egress-policy mutation, or destinations beyond the validated pin.

## Checks implemented (all passive)

| Area | Behavior |
|---|---|
| Security headers | CSP/HSTS/XCTO/XFO/Referrer-Policy/Permissions-Policy: absence ⇒ LOW (first four) or INFO finding, confidence HIGH; nonstandard XCTO value ⇒ LOW; presence ⇒ observation only |
| Cookies | Set-Cookie hygiene: missing Secure / HttpOnly ⇒ LOW; SameSite unspecified ⇒ INFO, invalid ⇒ INFO; cookie VALUES unconditionally redacted |
| Transport | scheme/TLS-verified status, redirect hop count, size + truncation flag as observations; HSTS-over-HTTP noted as ineffective |
| Server info | server/x-powered-by/x-generator/x-framework ⇒ INFO observations |

## Finding model

`domain/scanning/findings.py`: `Observation` → `Finding` with enums
Severity(INFO…CRITICAL) and Confidence(LOW/MEDIUM/HIGH); deterministic
SHA-256-derived IDs over identity fields (stable across runs/processes);
evidence clamped at 512 chars and control-character-stripped; stable JSON
serialization (`sort_keys`) for the future AI layer.

## Request policy

Exactly ONE logical request per attempt (`HttpLimits.max_requests`, new
field, contract-enforced ≥1) plus transport-managed redirects counted
against `max_redirects`. No crawling, no speculative path probing.

## Execution-gate posture — REMAINS CLOSED BY DEFAULT

`SandboxedScanExecutor(enable_execution=False)` is the library default:
passing a real engine STILL raises `SCANNER_EXECUTION_BLOCKED`. Rationale
for not opening now:

1. No API surface/lifecycle exists yet to authorize WHO may request scans
   and WHERE results go; opening the gate today would expose unauthenticated
   scan triggering.
2. Production runtime parity (ADR-0004) is still design-stage.
3. Negative tests prove the default-closed invariant, including that the
   secure chain itself is identical in test mode (`prepare()` +
   `build_services()` are gate-independent), so enabling later is a
   composition-root flag flip plus review — no code change inside the chain.

## Isolation evidence

Live suite runs two contexts against different validated hostnames and
asserts neither result serialization contains the other's identity;
cookie-value redaction asserted against seeded secrets.
