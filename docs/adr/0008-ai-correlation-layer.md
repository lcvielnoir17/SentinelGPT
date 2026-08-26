# ADR-0008: AI Correlation & Evidence Analysis Layer

**Status:** Implemented (compute-only; provider isolated; scanner execution gate unchanged)
**Date:** 2026-08-26
**Extends:** ADR-0007 (engine) and the deterministic findings model

## Context

Phase 5 produces deterministic `HttpAnalysisResult`s (observations +
findings). SentinelGPT's SRS anticipates an evidence-grounded AI explanation
layer on top (`settings.gemini_api_key` was provisioned for exactly this).
The risk: an LLM can invent evidence, overwrite findings, or become a
backdoor into scanning/network capability.

## Decision

A strictly **downstream, compute-only** layer:

```text
HttpAnalysisResult
  → EvidenceSet            [domain/scanning/analysis/evidence.py]
      immutable; deterministic metadata only (elapsed_ms excluded);
      canonical stable JSON; evidence_set_id = SHA-256(canonical)[:16];
      read-only finding index (MappingProxyType)
  → CandidateGroups        [correlation.py]  rule-seeded, offline,
      one cluster per Phase 5 family + catch-all; IDs verbatim from evidence
  → versioned prompts      [prompts.py] PROMPT/OUTPUT_SCHEMA_VERSION = v1;
      payload = canonical evidence + seed groups; instructions forbid
      invented findings/IDs and mandate SUPPORTED/INFERRED/UNSUPPORTED
      semantics (new taxonomy — no prior SRS/ADR terms existed)
  → EvidenceAnalyzer PROTOCOL [service.py]
      ScriptedAnalyzer (deterministic tests/baseline)
      GeminiEvidenceAnalyzer [infrastructure/ai/gemini_provider.py]
        google-genai 2.19.0 (locked), JSON mode, explicit timeout,
        API key/model via Settings conventions, size-capped responses,
        full SDK-error → typed-failure mapping
  → ResponseValidator [validator.py] FAIL-CLOSED:
      schema/type/enum checks; unknown finding_id references force
      EvidenceStatus.UNSUPPORTED + unsupported_claim_count; empty groups
      dropped; oversized payloads rejected; validator never mutates evidence
  → Assessment | AssessmentUnavailable
      caller ALWAYS receives the original EvidenceSet alongside either.
```

## Evidence integrity

* Provider-declared claim statuses are honored ONLY after reference
  validation; unknown IDs force UNSUPPORTED regardless of declared status.
* Unsupported claims are preserved visibly with a count — never dropped
  silently, never merged into supported content.
* Assessments carry `assessment_id` derived from
  `(evidence_set_id, provider, model, schema versions, canonical body)`.

## Non-determinism honesty

LLM output is explicitly non-deterministic:
`ProviderMetadata.nondeterministic = True` always for Gemini; schema
versions recorded per assessment. Determinism claims are limited to what IS
deterministic: evidence ID, prompt bytes, and scripted-provider runs.

## Security boundary

| Zone | Rule |
|---|---|
| `domain/scanning/analysis/` | NO network/process tokens; NO imports of google-genai, EngineServices, SandboxFactory/EgressPolicy, HostnameResolver, ScanNetworkContext (static guard test) |
| `infrastructure/ai/` | Only the AI SDK; socket/subprocess/DNS/Docker/raw-HTTP-client tokens forbidden (static guard test) |
| Everything else | unchanged zones |

The analyzer receives serialized evidence strings — never target handles,
never EngineServices, never sandbox internals. There is no code path from
the AI layer to the network stack or to the scanner chain.

## Failure behavior (fail-safe)

`AiAnalysisService.analyze` maps every failure onto
`AnalysisFailureKind ∈ {PROVIDER_UNAVAILABLE, AUTHENTICATION_FAILED, TIMEOUT,
MALFORMED_RESPONSE, SCHEMA_INVALID, LIMIT_EXCEEDED, UNEXPECTED}` returning
`AssessmentUnavailable(evidence_set_id, kind, sanitized detail, created_at)`
while returning the ORIGINAL evidence object untouched. Unexpected
exceptions preserve only the exception TYPE name (no message leakage).

## Cookies / persistence / scope

No persistence (compute-only, Alembic stays at 0003); no cookie state; no
scanner engines added; execution gate untouched.

## Consequences & remaining gaps

* Adding providers = implement the two-method protocol in
  `infrastructure/ai/`; zero domain changes.
* In-flight cancellation of provider calls follows each adapter's timeout;
  no shared token yet.
* Prompt-injection hardening (adversarial evidence text) is future work;
  current mitigation is schema+ID validation and bounded fields.
