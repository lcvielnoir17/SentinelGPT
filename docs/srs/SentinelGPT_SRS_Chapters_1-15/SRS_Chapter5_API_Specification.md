# Software Requirements Specification
## AI-Assisted Vulnerability Assessment Platform

**Document Type:** Software Requirements Specification (SRS)
**Chapter:** 5 — API Specification
**Version:** 2.0 (Revised Draft)
**Status:** For Review
**Prerequisite:** Chapters 1–4 (Foundations, Architecture, Tech Stack & Standards, Database Design)

> **Scope of this chapter:** this defines the concrete REST contract the FastAPI backend exposes to the frontend (and, in future, to third-party integrations per Chapter 1's roadmap). Every endpoint here maps directly to an entity or flow from Chapter 4's schema and follows the conventions locked in Chapter 3, Sections 10 and 18 (versioned routes, resource-oriented design, `202 Accepted` for long-running work, server-side-only authorization checks). Endpoints are grouped by lifecycle stage — identity, authorization, scan execution, findings, AI output, reporting, audit — mirroring the scan lifecycle established in Chapter 4 rather than an arbitrary feature list.

---

## Table of Contents

1. API Design Conventions
2. Authentication & Session Endpoints
3. Organization & Membership Endpoints
4. Target Endpoints
5. Authorization Attestation Endpoints
6. Scan Endpoints
7. Scan Engine Execution Endpoints (Granular Status)
8. Finding Endpoints
9. AI Explanation & Executive Summary Endpoints
10. Report Endpoints
11. Dashboard & History Endpoints
12. Audit Log Endpoints
13. Real-Time Channel (WebSocket/SSE) Specification
14. Error Response Catalog
15. Rate Limiting & Quota Headers
16. Pagination Standard
17. OpenAPI & Versioning Policy

---

## 1. API Design Conventions

- **Base path:** `/api/v1/`
- **Format:** JSON request/response bodies exclusively; `Content-Type: application/json`.
- **Auth:** Short-lived access and refresh JWTs are delivered only through `HttpOnly; Secure; SameSite=Strict` cookies. JavaScript never reads either token and clients do not manually inject an `Authorization` header. `POST /auth/refresh` rotates the refresh token server-side and reissues both cookies. This single pattern is used throughout the API.
- **IDs:** all resource identifiers are UUIDs (per Chapter 4 schema), represented as strings in JSON.
- **Timestamps:** ISO 8601 UTC (`2026-08-08T09:15:00Z`) throughout.
- **Idempotency:** state-changing `POST` endpoints that trigger side effects with cost or irreversibility (scan creation, report generation) accept an optional `Idempotency-Key` header; a repeated key within a 24-hour window returns the original response rather than re-executing the action.
- **Long-running operations:** any operation that cannot complete within a normal request/response cycle (scan execution, report generation, AI analysis) returns `202 Accepted` with a resource `id` and a `status` field — clients track completion via polling `GET` or the real-time channel (Section 13), never via a blocking request.
- **Response envelope (success):** resources are returned directly (no wrapper envelope) for `GET`/single-resource responses; list endpoints use the pagination envelope in Section 16.
- **Response envelope (error):** see Section 14 — always `{ "error": { "code", "message", "requestId" } }`.

---

## 2. Authentication & Session Endpoints

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| POST | `/auth/register` | Create a new user account | `{ email, password }` | `201` — `{ id, email, createdAt }` |
| POST | `/auth/login` | Authenticate, receive tokens (or MFA challenge) | `{ email, password }` | `200` — `{ user, expiresIn }` + `Set-Cookie: accessToken` and `Set-Cookie: refreshToken` (both HttpOnly), or `200` — `{ mfaRequired: true, mfaChallengeToken }` |
| POST | `/auth/mfa/verify` | Complete MFA challenge | `{ mfaChallengeToken, code }` | `200` — `{ user, expiresIn }` + `Set-Cookie: accessToken` and `Set-Cookie: refreshToken` (both HttpOnly) |
| POST | `/auth/refresh` | Rotate access token using the refresh cookie | — (refresh token read from the HttpOnly cookie; requires header `X-Refresh-Request: 1`, Chapter 2 Section 9's CSRF mitigation) | `200` — `{ user, expiresIn }` + `Set-Cookie: accessToken` and `Set-Cookie: refreshToken` (both rotated) |
| POST | `/auth/logout` | Revoke current refresh token | — | `204` + clearing `accessToken` and `refreshToken` cookies |
| GET | `/auth/me` | Fetch current authenticated user | — | `200` — `{ id, email, mfaEnabled, organizations: [...] }` |
| POST | `/auth/mfa/enroll` | Begin MFA enrollment (returns provisioning secret/QR data) | — | `200` — `{ secret, otpauthUrl }` |

**Design notes (traceable to Chapter 2, Section 9):**
- Neither JWT is present in a response JSON body. Both access and refresh tokens are delivered only through `Set-Cookie` response headers and are automatically attached by the browser as cookies; neither is readable by frontend JavaScript.
- `expiresIn` reflects the short-lived access token policy (~15 min).
- Failed login attempts are rate-limited and logged per `audit_log_entry` (`action_code = AUTH_LOGIN_FAILED`) to support brute-force detection, though only aggregate/anonymized detail is exposed to the client (no user enumeration via differing error messages between "unknown email" and "wrong password" — both return an identical `401`).
- Refresh-token reuse (a rotated-out token presented again) revokes the entire token family server-side and returns `401`, forcing re-login — the concrete implementation of Chapter 2, Section 9's theft-detection behavior.

---

## 3. Organization & Membership Endpoints

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| POST | `/organizations` | Create an organization | `{ name }` | `201` — organization object; creator is auto-assigned `ADMIN` |
| GET | `/organizations/{orgId}` | Get organization details | — | `200` |
| GET | `/organizations/{orgId}/members` | List members | — | `200` — paginated list (Section 16) |
| POST | `/organizations/{orgId}/members` | Invite a member | `{ email, role }` | `201` — membership object (pending until accepted, if invite flow is enabled) |
| PATCH | `/organizations/{orgId}/members/{userId}` | Change a member's role | `{ role }` | `200` |
| DELETE | `/organizations/{orgId}/members/{userId}` | Remove a member | — | `204` |

**Authorization rule (server-enforced, per Chapter 3, Section 18):** all `/organizations/{orgId}/...` endpoints independently re-verify that the requesting user is a member (and, for mutating endpoints, an `ADMIN`) of `orgId` — never inferred from a client-supplied role claim.

---

## 4. Target Endpoints

Maps to Chapter 4, Section 4.4 (`target`).

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| POST | `/targets` | Register a new target | `{ hostname, url, ownerOrganizationId? }` | `201` — target object, `status: "PENDING_ATTESTATION"` (target exists but is unscannable until attestation is confirmed) |
| GET | `/targets` | List targets owned by the current user/org | Query: `organizationId?`, `includeArchived?` | `200` — paginated list |
| GET | `/targets/{targetId}` | Get target detail (includes current attestation status) | — | `200` |
| PATCH | `/targets/{targetId}` | Update target metadata (not hostname/URL, which is immutable — a URL change is a new target) | `{ isArchived? }` | `200` |
| DELETE | `/targets/{targetId}` | Archive (soft-delete) a target | — | `204` — sets `isArchived = true`; per Chapter 4, Section 13, hard delete is never permitted while scans reference it |

**Validation note:** `url`/`hostname` pass through the shared target-normalization/SSRF-prevention function (Chapter 2, Section 13; Chapter 3, Section 18) at creation time — private IP ranges, localhost, and cloud metadata addresses are rejected with `422` before a `target` row is ever created.

---

## 5. Authorization Attestation Endpoints

Maps to Chapter 4, Section 8.

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| POST | `/targets/{targetId}/attestations` | Submit a new attestation for a target | `{ method: "SELF_ATTESTATION", evidenceFileRef? }` | `201` — attestation object, `status: "PENDING_REVIEW"` or `"CONFIRMED"` depending on method (self-attestation may auto-confirm per policy; future methods like DNS-TXT require a verification step) |
| GET | `/targets/{targetId}/attestations` | List attestation history for a target | — | `200` — paginated list, most recent first |
| GET | `/attestations/{attestationId}` | Get a single attestation's detail | — | `200` |
| POST | `/attestations/{attestationId}/revoke` | Revoke an active attestation | `{ reason }` | `200` — `status: "REVOKED"`; any `scan_schedule` referencing the now-unattested target is auto-paused |
| POST | `/attestations/{attestationId}/verify` | (Future method support) Trigger verification check, e.g. DNS-TXT lookup | — | `200` — `{ status }` |

**Server-side gate (mirrors Chapter 4, Section 8's rule):** `POST /scans` (Section 6) is rejected with `403` and error code `ATTESTATION_NOT_CONFIRMED` unless the target has at least one attestation with `status = CONFIRMED` and (`expiresAt` null or future) — re-checked again at job-dequeue time by the worker, not just at API-request time.

---

## 6. Scan Endpoints

Maps to Chapter 4, Section 5.2 (`scan`).

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| POST | `/scans` | Initiate an asynchronous scan | `{ targetId, scanProfile: "quick-check" \| "standard" \| "full-assessment" }` | `202` — `{ id, status: "QUEUED", targetId, scanProfile, createdAt }`; clients poll `GET /scans/{scanId}` or subscribe to the scan stream. |
| GET | `/scans/{scanId}` | Get scan detail, including derived aggregate status | — | `200` — full scan object (Section 6.1 below) |
| GET | `/scans` | List scans (history) | Query: `targetId?`, `status?`, `dateFrom?`, `dateTo?` | `200` — paginated list |
| POST | `/scans/{scanId}/cancel` | Cancel a queued or running scan | — | `200` — `status: "CANCELLED"` |
| POST | `/scans/{scanId}/rescan` | Create a new scan of the same target, auto-linked via `parentScanId` | `{ scanProfile? }` (defaults to parent's profile) | `202` — new scan object |
| GET | `/scans/{scanId}/compare/{otherScanId}` | Compare two scans of the same target | — | `200` — `{ new: [...], persistent: [...], resolved: [...], regressed: [...] }` (derived from Chapter 4, Section 6.2's lifecycle-status logic) |

### 6.1 Scan Response Shape

```json
{
  "id": "b7a1...",
  "targetId": "3f9e...",
  "scanProfile": "full-assessment",
  "status": "PARTIALLY_COMPLETE",
  "parentScanId": null,
  "initiatedBy": "user-uuid",
  "queuedAt": "2026-08-08T09:00:00Z",
  "startedAt": "2026-08-08T09:00:05Z",
  "completedAt": null,
  "engineExecutions": [
    { "engine": "katana", "status": "SUCCEEDED", "toolVersion": "1.x.x" },
    { "engine": "nuclei", "status": "SUCCEEDED", "toolVersion": "3.x.x" },
    { "engine": "nikto", "status": "FAILED", "toolVersion": "2.x.x" },
    { "engine": "headers-analyzer", "status": "SUCCEEDED", "toolVersion": "internal-1.0" }
  ],
  "findingCounts": { "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 4 }
}
```

`status` here is the derived aggregate from Chapter 4, Section 5.2 — computed from `engineExecutions`, not independently settable via the API.

---

## 7. Scan Engine Execution Endpoints (Granular Status)

Maps to Chapter 4, Section 5.3 — exposed separately from the scan object above so clients needing fine-grained per-tool status (e.g., a detailed progress UI) don't have to parse the nested array on every poll.

| Method | Path | Purpose | Success Response |
|---|---|---|---|
| GET | `/scans/{scanId}/engine-executions` | List all engine executions for a scan | `200` — array of `{ id, engine, status, exitCode, startedAt, completedAt, errorMessage }` |
| GET | `/scans/{scanId}/engine-executions/{executionId}` | Get one engine execution's detail | `200` — includes `rawOutputDownloadUrl` (signed, time-limited object storage URL) for advanced/debugging use |

---

## 8. Finding Endpoints

Maps to Chapter 4, Section 6.

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| GET | `/scans/{scanId}/findings` | List findings for a scan | Query: `severity?`, `category?`, `sourceEngine?` | `200` — paginated list |
| GET | `/findings/{findingId}` | Get a single finding, including evidence and (if generated) its AI explanation | — | `200` |
| GET | `/targets/{targetId}/findings/history` | Get the lifecycle history of findings for a target across all scans, grouped by `fingerprint` | Query: `status?` (`NEW`/`PERSISTENT`/`RESOLVED`/`REGRESSED`) | `200` — paginated list |
| GET | `/scans/{scanId}/relationships` | List all `finding_relationship` edges for a scan (Chapter 4, Section 15.3) | Query: `type?` (`DUPLICATE`/`RELATED`/`CORRELATED`) | `200` — paginated list of `{ id, findingIdA, findingIdB, type, triggeredByRule }` |
| GET | `/scans/{scanId}/risk-clusters` | List risk clusters for a scan (Chapter 4, Section 15.4) | — | `200` — paginated list of `{ id, title, severity, memberFindingIds, narrative? }` |
| GET | `/risk-clusters/{riskClusterId}` | Get a single risk cluster's detail, including its AI-generated narrative if available | — | `200` |

### 8.1 Finding Response Shape

```json
{
  "id": "c1d2...",
  "scanId": "b7a1...",
  "fingerprint": "sha256:...",
  "category": "OUTDATED_TLS",
  "severity": "HIGH",
  "title": "TLS 1.0 still enabled",
  "affectedAsset": "https://example.com",
  "sourceEngine": "ssl-inspector",
  "lifecycleStatus": "PERSISTENT",
  "evidence": [
    { "id": "ev-001", "type": "CERTIFICATE_DETAIL", "content": "Supported protocols: TLSv1.0, TLSv1.1, TLSv1.2" }
  ],
  "relatedFindingIds": ["c1d3..."],
  "riskClusterIds": ["rc-004"],
  "aiExplanation": {
    "claims": [
      { "text": "TLS 1.0 remains enabled alongside newer protocol versions", "evidenceReferences": ["ev-001"] }
    ],
    "remediation": "...",
    "validationStatus": "VALIDATED"
  }
}
```

`aiExplanation.claims[].evidenceReferences` point to `evidence[].id` values on this same object — a client can render each claim next to the exact evidence it cites, and the values are guaranteed valid because the response validator checked them before this row was ever persisted (Chapter 9, Section 5).

---

## 9. AI Explanation & Executive Summary Endpoints

Maps to Chapter 4, Section 7. Most AI content is delivered inline via `GET /findings/{findingId}` and `GET /scans/{scanId}` (executive summary), but dedicated endpoints exist for re-generation and standalone retrieval.

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| GET | `/scans/{scanId}/executive-summary` | Get the executive summary for a scan | — | `200` — `{ summaryText, topPriorityFindingIds, generatedAt, modelName }` |
| POST | `/findings/{findingId}/explanation/regenerate` | Re-trigger AI explanation for a single finding (e.g., after a fallback was used and Gemini is available again) | — | `202` — `{ status: "PENDING" }`; result delivered via real-time channel (Section 13) or subsequent `GET` |
| GET | `/findings/{findingId}/explanation` | Get a finding's AI explanation directly | — | `200` — includes `validationStatus` so the client can visually distinguish `VALIDATED` from `FALLBACK_USED` output (Chapter 2, Section 6.2) |

**Note:** there is no endpoint to directly `POST` or edit AI explanation text — explanations are only ever produced by the AI Orchestration Service pipeline (Chapter 2/3), never hand-authored through the API, preserving the evidence-grounding guarantee end-to-end.

---

## 10. Report Endpoints

Maps to Chapter 4, Section 9.

| Method | Path | Purpose | Request Body | Success Response |
|---|---|---|---|---|
| POST | `/scans/{scanId}/reports` | Generate a report for a completed (or partially-complete) scan | `{ format: "PDF" \| "JSON" \| "CSV" }` | `202` — `{ id, status: "GENERATING" }` |
| GET | `/reports/{reportId}` | Get report metadata | — | `200` — `{ id, scanId, format, status, downloadUrl?, generatedAt }` |
| GET | `/scans/{scanId}/reports` | List all reports generated for a scan | — | `200` — paginated list |

`downloadUrl` is a short-lived, signed URL into object storage (never a direct DB-served binary), consistent with Chapter 2's storage architecture.

---

## 11. Dashboard & History Endpoints

| Method | Path | Purpose | Success Response |
|---|---|---|---|
| GET | `/dashboard/summary` | Aggregate risk posture across all targets owned by the current user/org | `200` — `{ totalTargets, activeScans, severityDistribution, recentScans: [...] }` |
| GET | `/dashboard/trends` | Risk trend over time (satisfies Chapter 1, US-13) | Query: `targetId?`, `periodDays?` — `200` — time-series of severity counts |
| GET | `/targets/{targetId}/scans` | Scan history for a specific target | `200` — paginated list (also reachable via `GET /scans?targetId=`) |

---

## 12. Audit Log Endpoints

Maps to Chapter 4, Section 10. Access restricted to `ADMIN` role within an organization (or the individual account owner for personal-tier accounts).

| Method | Path | Purpose | Success Response |
|---|---|---|---|
| GET | `/audit-log` | Query audit entries | `200` — paginated list, filterable by `entityType`, `entityId`, `actionCode`, `dateFrom`/`dateTo` |
| GET | `/audit-log/{entryId}` | Get a single audit entry | `200` |

**Meta-audit note (per Chapter 2, Section 12.2):** every call to `GET /audit-log*` itself generates an `AUDIT_LOG_ACCESSED` entry — this endpoint's own usage is self-logging.

---

## 13. Real-Time Channel (WebSocket/SSE) Specification

Implements Chapter 2, Section 8's real-time progress pattern. Endpoint: `wss://.../api/v1/scans/{scanId}/stream` (or SSE fallback at `GET /api/v1/scans/{scanId}/stream` with `Accept: text/event-stream`).

### 13.1 Event Types

| Event | Payload | Emitted When |
|---|---|---|
| `scan.status_changed` | `{ scanId, status }` | The derived aggregate scan status transitions (Chapter 4, Section 5.2) |
| `engine_execution.status_changed` | `{ scanId, executionId, engine, status }` | Any individual engine execution changes state |
| `finding.created` | `{ scanId, findingId, severity, category }` | A new finding row is persisted mid-scan (allows progressive UI population rather than waiting for full completion) |
| `ai_explanation.ready` | `{ findingId, validationStatus }` | Per-finding AI explanation completes (validated or fallback) |
| `executive_summary.ready` | `{ scanId }` | Executive summary synthesis completes |
| `report.ready` | `{ reportId, scanId, format }` | Report generation completes |
| `scan.error` | `{ scanId, message }` | Unrecoverable scan-level error (distinct from a single engine failure, which is `PARTIALLY_COMPLETE`, not an error event) |

Connections are authenticated via the same bearer token as REST calls (passed as a query parameter or subprotocol header at connection time, per standard WebSocket auth patterns) and scoped to only the `scanId` the requesting user is authorized to view.

---

## 14. Error Response Catalog

Consistent envelope (Chapter 3, Section 10):

```json
{
  "error": {
    "code": "ATTESTATION_NOT_CONFIRMED",
    "message": "Target does not have a confirmed authorization attestation.",
    "requestId": "req_9f3a..."
  }
}
```

| HTTP Status | `code` | Meaning |
|---|---|---|
| 400 | `VALIDATION_ERROR` | Malformed request body/params |
| 401 | `UNAUTHENTICATED` | Missing/invalid/expired token |
| 403 | `FORBIDDEN` | Authenticated but lacks permission for this resource |
| 403 | `ATTESTATION_NOT_CONFIRMED` | Scan creation blocked — no valid attestation (Chapter 4, Section 8) |
| 403 | `TARGET_RESOLUTION_BLOCKED` | Target resolves to a disallowed range (SSRF prevention, Chapter 2/3) |
| 404 | `NOT_FOUND` | Resource does not exist or is not visible to the requester |
| 409 | `CONFLICT` | e.g., duplicate target registration, concurrent state transition conflict |
| 422 | `UNPROCESSABLE_TARGET` | Hostname/URL fails normalization/validation rules |
| 429 | `RATE_LIMITED` | Per-user/per-target scan-frequency cap exceeded (FR-22) |
| 500 | `INTERNAL_ERROR` | Unexpected server error — never includes stack trace/internal detail in the response body |
| 503 | `SCAN_CAPACITY_EXCEEDED` | Job queue backpressure threshold reached (Chapter 2, Section 14) — response includes `retryAfterSeconds` |

---

## 15. Rate Limiting & Quota Headers

Every response includes standard rate-limit visibility headers so clients (and users) can see their standing before hitting `429`:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1723107600
```

Scan-specific quotas (distinct from general API rate limiting) are surfaced via `GET /dashboard/summary` (`scanQuota: { used, limit, resetsAt }`) so the UI can proactively warn a user approaching their cap rather than only failing at submission time.

**AI-cost-specific limits (Chapter 9, Section 7; Chapter 1, FR-22):** these exist as much to protect a free-tier Gemini quota as to prevent abuse, and both purposes are served by the same configurable values (never hardcoded, per Chapter 3's config-driven approach):
- `MAX_FINDINGS_SENT_TO_AI_PER_SCAN` — caps per-finding Gemini calls even if an unusually noisy scan produces far more findings than typical, protecting the per-minute rate ceiling.
- `MAX_EVIDENCE_SIZE_PER_CLAIM` — bounds how much evidence text is included per prompt, keeping token usage (and therefore both latency and free-tier cost) predictable.
- `MAX_AI_REQUESTS_PER_SCAN` — a hard ceiling independent of finding count, as a final backstop.
Findings beyond these caps still persist and appear in reports with `validation_status = FALLBACK_USED` (Chapter 9, Section 6) rather than being dropped — the cap limits AI *cost*, never data completeness.

---

## 16. Pagination Standard

All list endpoints use cursor-based pagination:

**Request:** `GET /scans?limit=25&cursor=eyJpZCI6...`

**Response:**
```json
{
  "items": [ ... ],
  "pageInfo": {
    "nextCursor": "eyJpZCI6...",
    "hasNextPage": true
  }
}
```

`limit` defaults to 25, capped at 100. Cursor-based (rather than offset-based) pagination is used specifically because scan/finding tables are high-insert-volume and offset pagination would be prone to skipped/duplicated rows under concurrent writes.

---

## 17. OpenAPI & Versioning Policy

- The OpenAPI schema is auto-generated from FastAPI route definitions and Pydantic models and published at `/api/v1/openapi.json`, with interactive docs at `/api/v1/docs`. Frontend types are generated from this schema; they are not manually duplicated.
- **Breaking changes** (removing a field, changing a field's type, changing required-ness in a backward-incompatible way) require a new version prefix (`/api/v2/...`); the prior version remains available for a defined deprecation window.
- **Non-breaking additions** (new optional fields, new endpoints) ship within the existing `/api/v1/` namespace without a version bump.
- Every response includes an `X-API-Version` header for client-side diagnostics, independent of the URL path version.

---

*End of Chapter 5. Chapter 6 (AI Prompt Engineering & Validation Design) will detail the concrete prompt templates, structured-output schemas, and response-validation rules referenced throughout this chapter's AI-related endpoints (Section 9), building on the evidence-grounding architecture from Chapter 2, Section 6 and the Gemini integration standards from Chapter 3, Section 14.*
