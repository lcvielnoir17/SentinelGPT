# ADR-0002: Scanner Security Boundary (Pre-Execution Architecture)

**Status:** Accepted (partially implemented — see control status table)
**Date:** 2026-08-25
**Supersedes:** nothing · **Extends:** ADR-0001

## Context

ADR-0001 fixed the SSRF layering model: registration stays lexical; scan-time
DNS re-resolution and network-level enforcement are mandatory before any
scanner executes. This ADR defines the concrete architecture that satisfies
those requirements and records what is implemented versus designed-only.

## Architecture

```
Stored Target
  ↓ scan request
Scan-time resolution (fresh, complete)     [HostnameResolver protocol]
  ↓ all A + AAAA records
IP policy over EVERY record                [evaluate_ip / evaluate_all]
  ↓ fail-closed
ValidatedTargetBinding                     [immutable; validated address set]
  ↓ optional pin
ScanNetworkContext                         [binding-derived deny-by-default
  ↓                                         DefaultDenyEgressPolicy]
ScannerEngine.execute                      [gated: SCANNER_EXECUTION_BLOCKED]
```

Redirect contract: every redirect destination re-enters the pipeline
(normalize → classify → fresh resolve → validate all → NEW binding → NEW
context). Relative paths stay on the validated origin. Redirects never ride
the origin's validation.

## Control status

| Control | Status |
|---|---|
| Scan-time DNS resolution (fresh, all A+AAAA) | **IMPLEMENTED** (as injected contract + orchestrating service; real DNS adapter lands with Phase 2 sandbox work) |
| Validation of every resolved address | **IMPLEMENTED** (`ip_policy.evaluate_all`, fail-closed over the full record set) |
| IP policy (loopback/RFC1918/link-local/multicast/reserved/unspecified/metadata/v4-mapped/ULA/not-global) | **IMPLEMENTED** (`domain/scanning/ip_policy.py`) |
| DNS rebinding detection | **IMPLEMENTED** at application layer (`ensure_still_valid` set-equality re-check); **NOT YET ENFORCED AT NETWORK LEVEL** |
| IP pinning | **IMPLEMENTED** as an application abstraction (`with_pinned` + deny-by-default context); connection-level pinning applies when engines exist |
| Redirect revalidation | **IMPLEMENTED** as policy/service; exercised only with synthetic destinations |
| Egress policy | **IMPLEMENTED** as application abstraction (`DefaultDenyEgressPolicy` derived solely from the binding); **NOT YET ENFORCED AT NETWORK LEVEL** |
| Engine execution gate | **IMPLEMENTED** (`SCANNER_EXECUTION_BLOCKED`, 501, precedes any destination evaluation; static guard keeps the boundary package network-inert) |
| Network namespace / nftables / container egress isolation | **NOT IMPLEMENTED — Phase 2 prerequisite** |

## Why application-layer checks alone are insufficient

A Python policy object cannot constrain code that ignores it: any future bug
or bypass in engine code could perform its own lookups or connect elsewhere.
Defense therefore terminates in a NETWORK mechanism (deny-by-default egress
for the sandbox runtime, SRS Chapter 11 §6 layer 3 / Chapter 8 §2). Until that
mechanism exists and negative integration tests prove internal destinations
are unreachable *through the scanner path*, no engine may execute — enforced
today by the execution gate rather than by trust.

## Consequences

- The current phase structurally cannot produce an outbound scan request:
  there are no engine implementations, and every execution path raises first.
- Real DNS adapters, HTTP layers, sandboxes, and engines arrive together in
  Phase 2 under these interfaces, each behind this same boundary.
- Registration-time lexical validation remains unchanged (ADR-0001).
