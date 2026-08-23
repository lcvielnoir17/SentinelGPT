# SentinelGPT SRS v2.0 — Revision Notes

This package contains the revised Chapters 1–15 for the SentinelGPT project.

## Main alignment changes
- Repositioned SentinelGPT as a human-supervised vulnerability-intelligence/analysis platform rather than an autonomous pentester.
- Made the research pipeline explicit: authorized scan → evidence → normalization → deterministic correlation/deduplication → enrichment → evidence-grounded AI interpretation → validation → human verification → prioritized reporting.
- Clarified that scanners establish evidence and the AI layer interprets supplied evidence; AI does not originate canonical findings, severity, lifecycle state, authorization, or new relationships.
- Made `finding_relationship` the single canonical persistence mechanism for relationships between findings.
- Added explicit research evaluation objectives covering correlation, prioritization, analyst efficiency, AI trustworthiness, and reproducibility.
- Clarified the MVP scanner scope and kept additional enterprise tools as optional/future integrations.
- Clarified the JWT/refresh-token security invariant.
- Kept Docker Compose as the MVP deployment target and Kubernetes/scale features as future production targets.
- Scoped property-based testing to target normalization/SSRF validation, fingerprint generation, and scanner-output parsers.
- Clarified PR versus nightly/release CI cadence.
- Reordered implementation around vertical slices so the evidence-to-intelligence path becomes demonstrable early.

## Source policy
These revisions refine the supplied SRS chapters and the previously identified architecture-review corrections. They do not replace the 15-chapter structure.
