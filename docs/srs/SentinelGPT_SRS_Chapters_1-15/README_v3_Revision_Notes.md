# SentinelGPT SRS v3 — Revision Notes

## Purpose
This revision incorporates the latest research-direction corrections: SentinelGPT is positioned as an AI-powered vulnerability-analysis platform in which the AI is the primary analytical component, not an autonomous pentesting agent. The pipeline operates automatically; human experts participate only in research evaluation to establish ground truth and measure accuracy/reliability.

## Major changes
1. **Primary research contribution clarified:** multi-tool observation normalization, finding correlation/deduplication, and contextual prioritization; analyst efficiency and grounded explanation are evaluation outcomes.
2. **Observation layer introduced:** raw scanner output → normalized observations → candidate findings → correlation → prioritization → AI explanation → reporting; no human-approval step exists in the operational pipeline (human review appears only in evaluation).
3. **Ground truth and baselines added:** individual scanner, rule-based aggregation, and SentinelGPT-assisted conditions; controlled/seeded test cases required for defensible evaluation.
4. **AI boundary reinforced:** Gemini interprets evidence and explains deterministic results; it does not originate findings, merge findings, or overwrite canonical severity.
5. **Contextual risk score reframed:** any weighted score is a transparent, versioned baseline—not a universal security truth and not an opaque LLM score.
6. **Authentication contradiction corrected:** both access and refresh tokens use HttpOnly/Secure/SameSite=Strict cookies; frontend JavaScript never receives or stores JWTs.
7. **API contract reinforced:** REST `/api/v1`, FastAPI-generated OpenAPI, asynchronous `POST /scans` returning a scan ID, with polling or stream-based status updates.
8. **Cross-finding relationships remain centralized:** `finding_relationship` is the sole relationship persistence mechanism; duplicate/corroboration/correlation relationships retain provenance.
9. **MVP/production boundary preserved:** Docker Compose/single-host operation is the MVP; Kubernetes and autoscaling remain future-scale architecture.
10. **Implementation plan updated:** early findings UI and a dedicated research evaluation slice are added before final reporting/polish.
11. **FastAPI/Python consistency improved:** backend architecture examples in Chapter 2 are aligned with the fixed Python/FastAPI stack.

## Deliberately not added
- Autonomous exploitation
- Attack-tree/UCB planning as a core SentinelGPT requirement
- Task Difficulty Assessment as a required MVP component
- Claims of replacing penetration testers
- Claims that SentinelGPT is the first AI vulnerability scanner

These topics may remain in related-work discussion but are not required implementation claims.
