# ADR-0005: HTTP Scanner Connection & Redirect Security Design

**Status:** Accepted (design + contract types implemented in `domain/scanning/http_contract.py`; real transport deliberately NOT implemented)
**Date:** 2026-08-26
**Extends:** ADR-0001/0002/0003

## Principle

The future HTTP client NEVER resolves names and NEVER chooses destinations.
Its entire world is:

    ConnectionTarget(address=pinned IP, port, scheme, hostname=validated name)

produced only by `ConnectionTarget.for_context(validated context)` from the
binding's `pinned_address`, re-checked against the live egress policy. The
kernel sandbox remains the outer authority; these rules govern what the
in-sandbox HTTP layer is allowed to *attempt*.

## Resolved decisions

| Concern | Decision | Enforced by |
|---|---|---|
| Host header vs connection IP | Connect to the PINNED IP; send `Host: <validated hostname>` (+ port suffix when non-default). The hostname is identity-for-the-server, never a lookup. | contract: `ConnectionTarget.hostname` is read-only provenance |
| DNS inside HTTP layer | FORBIDDEN. No resolver handle exists on any contract type. Any name→IP need must go back through `ScanTargetResolutionService` (full pipeline). | static guard + type surface |
| TLS SNI (https) | SNI = validated hostname. | Phase-4 adapter requirement (documented here) |
| Certificate validation | REQUIRED, verified against the validated hostname (not the IP). A mismatch fails as `ControlledTransportError(TLS_ERROR)`; no "verify against pin" relaxation, no insecure modes. | Phase-4 adapter + tests TBD |
| Absolute redirects | Location host re-enters normalize → fresh resolve → validate EVERY record → NEW binding → NEW context; the client then pins to THAT context before continuing. Never rides prior authorization. | existing `RedirectValidationService` (kernel-proven in integration suite) |
| Relative redirects | Stay on the validated origin; same context reused; destination still the pinned IP with new path/query. | contract `RedirectChain` + service semantics |
| Protocol-relative (`//host`) | Treated as absolute-with-empty-scheme → BLOCKED fail-closed today. Revisit only with explicit scheme-inheritance design + review. | existing service behavior |
| Ports | Explicit ports allowed; default per scheme otherwise. Port is NOT part of the egress authorization (authorization is address-scoped /32); abuse is bounded by the kernel allow-list and target-owner consent model. Documented tradeoff. | contract defaults |
| IPv4/IPv6 targets | Both supported; v6 uses bracketed Host/SNI handling in adapter; kernel already DROPs all non-listed families. | sandbox (proven) |
| Rebinding BETWEEN redirects | Each absolute hop performs FRESH resolution + full-record validation; additionally `ensure_still_valid` runs at hop boundaries in Phase 4 wiring. Drift anywhere ⇒ blocked envelope. | resolution service (tested) |
| Redirect limits | `HttpLimits.max_redirects` (default 10); exhaustion raises within the blocked family. | `RedirectChain` (tested) |
| Redirect loops | Repeat (location) within one chain ⇒ immediate block; loops therefore cannot consume unbounded time or requests. | `RedirectChain` (tested) |
| Connect timeout | `HttpLimits.connect_timeout_s` default 5s; adapter maps expiry to `ControlledTransportError(CONNECT_TIMEOUT)`. | limits type |
| Read timeout | `HttpLimits.read_timeout_s` default 15s between body progress; maps to READ_TIMEOUT kind. | limits type |
| Response size | Hard ceiling at `max_response_bytes` (default 2 MiB): adapters stream-count and CLAMP with an explicit `truncated=True` flag on the response (never unbounded memory). Redirect responses that arrive clamped are refused outright — clamped bytes must not drive routing. | contract + transport (ADR-0006) |

## Deliberately UNRESOLVED (recorded, not guessed)

1. Cookie jar semantics for authenticated scans (scope, persistence,
   cross-host leakage) — needs product input before Phase 4.
2. Non-HTTP payloads (WebSockets, upgrades, ALPN) out of scope until an
   engine requires them; the contract admits only GET/HEAD/POST/OPTIONS.
3. HSTS / downgrade handling across scheme hops: current rule treats
   https→http absolute redirects as legal-but-revalidated; whether to forbid
   downgrades entirely is a policy question deferred to Phase 4 review.
4. Exact retry/idempotency policy for transport failures mid-body.
5. Per-attempt total wall-clock budget (sum of timeouts is bounded but not
   globally capped yet).

None of these are silently assumed; each lands as a reviewed change to this
ADR plus contract code before any real client ships.

## Status

Contract types, sealed construction paths, and offline behavioral tests are
committed. NO stdlib/third-party network client exists in the scanner
domain; the execution gate remains closed.
