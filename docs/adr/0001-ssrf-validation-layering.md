# ADR-0001: SSRF Validation Layering (Registration vs Scan Time)

**Status:** Accepted
**Date:** 2026-08-25
**Scope:** Target registration SSRF boundary; scan-execution prerequisites

## Context

SRS Chapter 11 Section 6 mandates four SSRF defense layers:

1. Registration-time rejection of targets that resolve to private/loopback/link-local/metadata ranges.
2. Re-resolution at scan time (anti DNS-rebinding).
3. Sandbox network-layer egress allow-list.
4. Redirect-following re-validation.

The Target API (Phase 1) must register targets before any scanner exists. The
independent audit (CONDITIONAL PASS) found lexical bypasses and noted that no
DNS resolution occurs at registration.

## Decision

1. **Registration-time validation stays lexical** (`target_normalization.py`):
   canonical hostname forms (trailing-dot stripped), IP-literal range
   classification, rejection of all non-canonical numeric host forms
   (`127.1`, `0x7f.0.0.1`, `0177.0.0.1`, integer-encoded IPv4), and a
   metadata/private-name blocklist (`metadata.google.internal`, `metadata.goog`,
   `*.internal`, `*.local`, `localhost*`).

2. **Registration-time DNS resolution is deliberately NOT implemented.** A
   single lookup in a synchronous request is TOCTOU-prone (the rebinding window
   SRS Chapter 11 Section 6 layer 2 exists to close) and would provide false
   assurance while layers 2-4 are absent.

3. **MANDATORY RELEASE BLOCKERS before any scanner executes a network request**
   (Chapter 15 Phase 2 entry criteria):
   - Scan-time DNS re-resolution with private-range validation of every resolved
     address immediately before engine dispatch (403 `TARGET_RESOLUTION_BLOCKED`,
     SRS Chapter 5 Section 14), repeated at redirect boundaries.
   - Sandbox egress allow-list enforcing the resolved target IP at the network
     layer (Chapter 8 Section 2 / Chapter 11 Section 6 layer 3).

## Consequences

- The registration-time SRS guarantee implemented today is **lexical only**;
  this ADR records that limitation explicitly rather than implying Ch11 layer 1
  is fully satisfied.
- Equivalent DNS names are treated as one identity ("example.com." ==
  "example.com"), keeping target uniqueness meaningful.
- Any PR introducing scan execution without items in section 3 must be rejected
  in review regardless of other test outcomes.
