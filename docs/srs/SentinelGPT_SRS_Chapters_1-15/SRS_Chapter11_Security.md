# Software Requirements Specification
## AI-Assisted Vulnerability Assessment Platform

### Security invariant
No authorization, authentication, scanner, correlation, or AI component may bypass the established trust boundaries. In particular, access and refresh tokens follow one documented pattern: both are short-lived/rotating JWT credentials delivered only through secure HttpOnly cookies and tracked server-side where revocation is required; JavaScript never reads or stores either token.


**Chapter 11 — Security**
**Version:** 2.0 (Revised Draft) | **Status:** For Review
**Prerequisite:** Chapters 1–10

> This platform performs security scanning for a living — its own security posture is not a supporting concern, it is the product's credibility. This chapter consolidates the controls scattered through Chapters 2–10 into a single threat model and adds the governance layer (SDLC practices, incident response, disclosure policy) not covered elsewhere.

---

## Table of Contents

1. Threat Model (STRIDE)
2. Platform Self-Application of the OWASP Top 10
3. Secure SDLC Practices
4. Secrets Management & Rotation
5. Sandbox Escape Prevention
6. SSRF Defense in Depth
7. Data Classification & Protection
8. Authentication & Session Security Detail
9. Vulnerability Disclosure Policy (For This Platform)
10. Third-Party & Dependency Risk Management
11. Incident Response Plan
12. Compliance Considerations

---

## 1. Threat Model (STRIDE)

| Threat Category | Primary Risk in This Platform | Mitigating Controls (cross-referenced) |
|---|---|---|
| **Spoofing** | Attacker impersonates a legitimate user or org admin | MFA (Ch2 §9), short-lived tokens + refresh rotation, brute-force lockout |
| **Tampering** | Attacker modifies scan findings, AI explanations, or audit records in transit/storage | TLS everywhere (NFR-01), append-only audit log with `INSERT`-only DB grant (Ch4 §10, Ch4 §13), immutable reports (Ch10 §6) |
| **Repudiation** | User denies having initiated an unauthorized scan, or platform cannot prove authorization was checked | Versioned attestation entity + audit log linking every scan to a specific attestation (Ch4 §5.2, §8, §10) |
| **Information Disclosure** | Scan results (which reveal a target's vulnerabilities) leak to unauthorized parties; internal infrastructure exposed via SSRF; correlated risk-cluster data (Ch4 §15) is a higher-value leak target than any single finding, since it pre-packages relationships an attacker would otherwise have to work out themselves | Org-scoped access control on all resources (Ch5 §3–8), signed time-limited storage URLs (Ch5 §10, Ch10 §6), SSRF defenses (Section 6 below); risk clusters inherit `finding` data classification (Section 7) at minimum |
| **Denial of Service** | Abuse of the scan-initiation endpoint to exhaust worker capacity, or a scan target's response used to exhaust platform resources | Rate limiting + scan-frequency caps (FR-22), sandbox resource limits (Ch8 §2), bounded timeouts (Ch8 §7), queue backpressure (Ch2 §14) |
| **Elevation of Privilege** | A `MEMBER`-role user performs an `ADMIN`-only action; a scan payload escapes its sandbox to reach platform infrastructure | Server-side-only authorization re-verification on every request (Ch3 §18), sandbox isolation + egress allow-list (Ch8 §2) |

---

## 2. Platform Self-Application of the OWASP Top 10

| OWASP Category | This Platform's Specific Exposure | Control |
|---|---|---|
| Broken Access Control | Org-scoped resources (targets, scans, findings) accessed cross-tenant | Every route independently re-verifies org/ownership (Ch3 §18, Ch5 §3) — never trusts a client-supplied org context |
| Cryptographic Failures | Sensitive scan/attestation data, credentials | TLS 1.2+, encryption at rest, field-level encryption for MFA secrets/attestation evidence (Ch2 §13, Ch4) |
| Injection | Command injection into scanner subprocess calls; SQL injection | No `shell=True`, discrete subprocess args only (Ch3 §13, §18); SQLAlchemy parameterized queries exclusively, no raw string SQL |
| Insecure Design | Scanning-as-a-weapon (SSRF), unauthorized scanning by design gaps | Authorization-attestation-first architecture is a *design-level* control, not a bolt-on check (Ch4 §8, Ch5 §5) |
| Security Misconfiguration | Overly permissive sandbox egress, verbose error responses | Egress allow-list per scan (Ch8 §2), centralized error handler never leaking internals (Ch2 §11, Ch6 §9) |
| Vulnerable & Outdated Components | Katana/Nuclei/Nikto and Python dependency staleness | Pinned versions + reviewed update process (Ch8 §8), dependency scanning in CI (Section 10 below) |
| Identification & Authentication Failures | Credential stuffing, session fixation | Argon2/bcrypt hashing, MFA, rate-limited login, short-lived + rotated tokens (Ch2 §9, Section 8 below) |
| Software & Data Integrity Failures | Unreviewed Nuclei template updates altering scan behavior silently; unsigned CI artifacts | Version-controlled, reviewed template updates (Ch8 §8); CI artifact/image scanning (Section 10, Ch12/14) |
| Security Logging & Monitoring Failures | Inability to reconstruct "who scanned what, when, under what authorization" | Dual logging architecture — operational + append-only audit (Ch2 §12) |
| Server-Side Request Forgery (SSRF) | The Platform's core function is to make server-side requests to user-supplied targets | Dedicated in-depth treatment, Section 6 below — this is the Platform's single highest-relevance OWASP risk given its purpose |

---

## 3. Secure SDLC Practices

- **Design-phase security review** required for any change touching: the scan orchestrator, sandbox provisioning, the attestation-guard middleware, the AI response validator, or authentication — flagged via the branch-naming/review-weight convention already established (Chapter 3, Section 16: 2 required reviewers for these areas).
- **Threat-model updates**: this chapter's STRIDE table (Section 1) is a living document — any new feature that introduces a new trust boundary (e.g., a future third-party integration marketplace, Chapter 1's Future Enhancements) requires a corresponding STRIDE entry before merge, not after.
- **Security champions model**: at least one engineer per major subsystem (scanning, AI, backend core) is designated to review security-relevant PRs in that area with elevated scrutiny, supplementing (not replacing) the automated CI gates.
- **Pre-production security testing**: before any major release, a scoped internal review (or, budget permitting, an external assessment) specifically targets the sandbox isolation boundary and the attestation-enforcement path — the two controls whose failure would be most damaging (Chapter 1, R-01, R-04).
- **Correlation rule review**: new or modified `correlation_rule` entries (Chapter 4, Section 15; Chapter 8, Section 11) go through the same review bar as a Nuclei template update (Section 10 below) — a rule is detection logic, and an overly broad or poorly-scoped rule could manufacture false urgency (an inflated `cluster_severity_floor_id`) as easily as a missing one could hide a real pattern.

---

## 4. Secrets Management & Rotation

| Secret | Storage | Rotation Policy |
|---|---|---|
| Gemini API key | Secrets manager (Ch3 §7) | Rotated on a scheduled cadence and immediately upon suspected exposure; rotation is a documented runbook (Ch3 §17) |
| Database credentials | Secrets manager, injected at deploy time | Rotated per environment-promotion cycle; no shared credentials across environments |
| Object storage credentials | Secrets manager, scoped per service (API vs. worker) | Least-privilege scoped keys — the API's storage credential cannot delete objects, only the report worker's write path can |
| JWT signing key | Secrets manager | Supports key rotation with a grace-period overlap (old key still validates existing unexpired tokens during rollover) |
| MFA secrets, attestation evidence | Field-level encrypted at the application layer before persistence (Ch4) | Encryption key itself lives in the secrets manager, separate from the database |

No secret is ever committed to source control, embedded in a container image layer, or logged (Chapter 3, Section 18 — enforced via a log-scrubbing CI test).

---

## 5. Sandbox Escape Prevention

Building on Chapter 8, Section 2's sandbox design:

- **Defense in depth, not a single control**: container-level isolation (namespaces, cgroups) + network-level egress filtering + no persistent volume + resource limits + wall-clock timeout — an attacker attempting to escape via any one weakness still faces the others.
- **No privileged container execution.** The sandbox never runs with elevated container privileges or host-mounted volumes.
- **Read-only root filesystem** for the sandbox image where feasible, with only explicitly writable ephemeral paths (e.g., a scoped `/tmp` for tool working files) — minimizing the sandbox's own attack surface for persistence or lateral movement even if a scanning tool itself were compromised via a malicious target response.
- **Regular sandbox image rebuilds** (not just on tool-version bumps) to pick up base-OS security patches, tracked via the same image-scanning pipeline as any other container (Chapter 12, Section 7).

---

## 6. SSRF Defense in Depth

Given this is the Platform's most purpose-relevant risk (Section 2), it receives layered, independent controls rather than a single check:

1. **Input validation layer** (Chapter 2/3): target hostname/URL rejected at registration time if it resolves to a private IP range (RFC1918), loopback, link-local, or known cloud metadata address (`169.254.169.254` and equivalents).
2. **Re-resolution at scan time**: DNS resolution is re-checked immediately before each scan (not only at target-registration time) to catch DNS-rebinding attempts, where a hostname resolves to a public IP at registration but is switched to an internal IP by the time the scan actually runs.
3. **Sandbox network-layer egress allow-list** (Chapter 8, Section 2): even if the above two layers were somehow bypassed, the sandbox container's network policy independently restricts egress to only the resolved target IP for that specific scan — a defense that doesn't rely on application-code correctness at all.
4. **No redirect-following blank check**: HTTP redirects encountered during crawling/scanning are validated against the same private-range/metadata-address block list before being followed — an attacker cannot use an open redirect on an authorized target to pivot a scan toward an internal address.

---

## 7. Data Classification & Protection

| Data Class | Examples | Protection Level |
|---|---|---|
| **Highly sensitive** | Password hashes, MFA secrets, attestation evidence documents, Gemini/infra API keys | Field-level or secrets-manager encryption, most restrictive access, never logged |
| **Sensitive** | Scan findings (reveal a target's vulnerabilities), risk clusters and finding relationships (Ch4 §15 — a pre-correlated view of a target's weaknesses), WHOIS registrant data, audit log entries | Encrypted at rest, org-scoped access control, signed time-limited access for exported artifacts |
| **Internal** | Operational logs, performance metrics | Access restricted to engineering/ops roles, PII-scrubbed |
| **Public-safe** | Marketing content, public documentation | No special handling |

Scan findings are treated as **sensitive by default**, not merely "the user's own data" — because a report or export, if it reached the wrong hands, would function as an attack roadmap against the target. This classification directly justifies the signed-URL/no-public-link policy in Chapter 5/10. Risk clusters (Chapter 8, Section 11) are classified **at least as sensitively as the findings they group** — arguably more so, since a cluster does the attacker's correlation work for them; no cluster or relationship data is ever included in a public-safe or unauthenticated context.

---

## 8. Authentication & Session Security Detail

Extending Chapter 2, Section 9 — this is not an alternative description, it is the same architecture restated with security rationale. **There is exactly one token-storage pattern in this system, used everywhere:**
- Passwords hashed with Argon2id (preferred) or bcrypt with a modern cost factor; no reversible encryption of passwords under any circumstance.
- **Access token**: short-lived (~15 min) signed JWT delivered only as an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. JavaScript never reads or stores it, and API requests do not manually inject an `Authorization` header.
- **Refresh token**: longer-lived, stored server-side as revocable, rotated on every use, and delivered as a separate `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to the auth routes. Refresh-token reuse (a rotated-out token presented again) revokes the whole token family and forces re-login — the concrete detection mechanism for token theft.
- **CSRF mitigation for the refresh/logout endpoints** (the only endpoints a cookie alone authenticates): `SameSite=Strict` is the primary defense; a required `X-Refresh-Request: 1` header — which a cross-site form POST cannot set — is a lightweight secondary layer. A full double-submit CSRF-token scheme is documented as a future hardening, not required for the MVP's threat model (Chapter 2, Section 9).
- Account lockout: progressive delay after repeated failed logins, full temporary lockout after a threshold, with lockout events written to the audit log.
- MFA strongly encouraged (and eventually required) for `ADMIN` organization roles given their elevated blast radius (member management, org-wide target/attestation visibility).

---

## 9. Vulnerability Disclosure Policy (For This Platform)

Distinct from the platform's *product function* (helping users assess their own targets) — this governs how someone who finds a flaw **in the Platform itself** should report it:

- A published, easy-to-find security contact (e.g., `security@<domain>`) and/or a disclosure form, separate from general customer support.
- Commitment to acknowledge reports within a defined window (e.g., 2 business days) and provide status updates through resolution.
- A safe-harbor statement for good-faith security researchers testing the Platform's own infrastructure (not the scanning feature against arbitrary third-party targets, which remains governed by the Platform's Terms of Use regardless of who is testing).
- No legal action against researchers who follow the disclosure policy in good faith and avoid data destruction, privacy violation, or service disruption.

This is explicitly listed as an item the Legal/Compliance stakeholder (Chapter 1, Section 7) must review and publish before general-availability launch.

---

## 10. Third-Party & Dependency Risk Management

- **Python dependencies**: `pip-audit` (or equivalent) run in CI on every PR and on a scheduled cadence against `main`, flagging known-vulnerable packages (Chapter 3, Section 15).
- **Container base images and Katana/Nuclei/Nikto binaries**: image and binary provenance verified (checksums/signatures where the upstream project provides them) before pinning a new version (Chapter 8, Section 8).
- **Gemini SDK and API**: tracked against Google's own security advisories; SDK version pinned and updated through the standard dependency-update review process, not auto-updated silently.
- **Nuclei template supply chain**: treated with particular care (Chapter 8, Section 8) since templates are effectively executable detection logic from a fast-moving community source — the Platform's curated/pinned subset is the control boundary, not blind trust in upstream.
- **SBOM (Software Bill of Materials)** generation as part of the CI/CD pipeline (Chapter 14) to maintain an audit-ready inventory of all dependencies, supporting both security response speed and future compliance needs (Section 12 below).

---

## 11. Incident Response Plan

| Phase | Action |
|---|---|
| **Detection** | Monitoring/alerting (Chapter 2, Section 12.1) on anomalous patterns: spike in failed-login attempts, an attestation-guard bypass attempt, sandbox resource-limit violations, unexpected egress-block events |
| **Triage** | On-call engineer classifies severity; a suspected sandbox escape or authorization-bypass is treated as highest severity regardless of apparent immediate impact, given the platform's specific risk profile |
| **Containment** | Ability to immediately disable a specific scan engine, pause all scanning platform-wide, or revoke a specific user/org's access via the feature-flag mechanism (Chapter 6, Section 5) without a full deployment |
| **Eradication & Recovery** | Root-cause fix follows the standard secure-SDLC review bar (Section 3); affected users notified per the data-protection obligations in NFR-16 if any data exposure is confirmed |
| **Post-incident review** | Blameless retrospective; STRIDE threat model (Section 1) updated if the incident reveals a gap; a new automated test/control is added to CI wherever feasible so the same class of issue cannot silently regress |

---

## 12. Compliance Considerations

- The Platform does not itself issue compliance certifications (Chapter 1, Out-of-Scope) but its own handling of user data should be designed to **not become a compliance blocker** for customers who are themselves subject to frameworks like GDPR, SOC 2, or PCI-DSS.
- **Data residency/retention** controls (Chapter 4/10) and the append-only audit log (Section 1, Chapter 4 §10) are specifically structured so that, if a future compliance-evidence-pack feature (Chapter 1, Future Enhancements) is built, the underlying data model and controls already satisfy the typical evidentiary requirements (who did what, when, under what authorization) rather than needing retrofitting.
- Legal review (Chapter 1 stakeholder list) is required before launch on: Terms of Use authorized-use language, the vulnerability disclosure policy (Section 9), and jurisdiction-specific data-protection obligations relevant to the platform's initial launch markets.

---

*End of Chapter 11. Chapter 12 (DevOps & Docker) covers how the controls in this chapter — sandbox isolation, secrets management, pinned dependencies — are actually built, deployed, and operated.*