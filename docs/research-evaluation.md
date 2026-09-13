# Research Evaluation — Reproducibility Package (M15)

How to reproduce the SentinelGPT research evaluation from a clean
local checkout. No database, network, cloud, live targets, or secrets
are required at any step.

## Research question

Do SentinelGPT's deterministic stages — observation normalization,
fingerprint correlation/deduplication, max-rank severity, lifecycle
derivation, and v2 contextual prioritization — measurably improve over
raw scanner output (Baseline A) and naive rule-based processing
(Baseline B), judged against controlled ground truth?

Out of scope for this package: live-target accuracy, Gemini live
accuracy (doubles only — see below), and any compliance certification.

## 1. Environment

- Python 3.12 and the repository checkout. The research package uses
  the standard library plus the pure deterministic domain functions
  (`backend/src/domain/scans/fingerprinting.py`,
  `lifecycle_finding.py`, `priority.py`, `domain/compliance/catalog.py`).
- It never imports scanner execution, repositories, workers, network
  clients, settings, or AI providers (pinned by
  `test_research_package_boundary_static`, extended in M15 tests).

## 2. Dataset (`backend/src/research/dataset.json`)

- Version: `sgpt.research.v1` (constant `DATASET_VERSION` in
  `backend/src/research/schema.py`). The loader rejects any other
  version, so history cannot be silently re-evaluated under a new
  schema.
- Pipeline code version: `sgpt.research.pipeline.v1` (constant
  `PIPELINE_VERSION` in `backend/src/research/evaluate.py`); metric
  code version: `sgpt.research.metrics.v1` (constant
  `METRIC_VERSION` in `backend/src/research/metrics.py`). Both are
  stamped on every evaluation result alongside the dataset version
  and a SHA-256 of the exact dataset bytes evaluated.
- 54 synthetic fixtures across twelve categories: normalization
  (exact/evidence/order/location/optional-field/whitespace),
  correlation (category-split, near-match, unrelated, multi-member,
  cross-engine), lifecycle (increase, decrease, new-in-rescan,
  reappearance, regression, resolution, persistence), severity
  (critical, info, ladder), priority (P1 boundary at score 75,
  ties, CVE/CVSS/tech signals), enrichment (missing, multiple,
  duplicate, conflicting), technology (alone, +CVSS, version-absent),
  HTTP/TLS (CORS, certificates, panels, headers, cookies, TLS),
  remediation (TODO/IN_PROGRESS/DONE/DEFERRED persistence),
  compliance assessment states, and adversarial evidence (severity
  instruction, command text, compliance claim, homoglyph split).
  observations (required), optional `scan_b`, optional `history`
  (prior lifecycle keyed by member observation), optional
  `technologies`, optional `remediation` (informational only), and
  `ground_truth` (canonical groups with members/severity/category/
  lifecycle/priority + expected compliance pairs).
- Ground truth distinguishes RAW OBSERVATION from CANONICAL FINDING:
  scanner output is never treated as truth; canonical groups are
  hand-specified expectations the real pipeline functions must meet.
- Ordering inside the file is irrelevant: the loader sorts by fixture
  id, so diffs stay minimal and runs stay stable.

## 3. Baselines (all consume identical observations)

- **Baseline A (scanner-only):** one finding per observation,
  as-reported severity, lifecycle always NEW. It cannot deduplicate,
  resolve, or regress — that inability is the honest point of
  comparison, not a handicap.
- **Baseline B (rule-based):** exact normalized-title groups per
  category, first-seen severity, `derive_lifecycle_status` without
  history, static severity→priority map
  (CRITICAL→P1, HIGH→P2, MEDIUM→P3, LOW/INFO→P4).
- **SentinelGPT:** real `generate_fingerprint_from_finding`
  grouping, max-rank severity (ties → earliest member), lifecycle
  derivation with fixture history, `calculate_priority_v2` with
  CVE/CVSS/technology signals, curated compliance mapping.

Fairness rules: every pipeline consumes byte-identical observations;
baselines never see fingerprints, priority internals, lifecycle
history semantics, or compliance metadata (a test asserts baseline
outputs contain none of these); Baseline B is defined by its own
coherent rules (exact-title groups, first-seen severity, static
priority map) — never as "SentinelGPT minus a feature". Leakage
controls: ground truth pins intended rule behavior in member/field
terms only (the dataset contains zero computed fingerprints — a test
scans for 64-hex strings); fixture titles carry no verdict words;
evaluation scores all pipelines through identical code paths.

## 4. Metrics (exact formulas in `backend/src/research/metrics.py`)

Grouping precision/recall/F1 over exact member-set matches (partial
overlaps match nothing); duplicate reduction `1 − groups/obs`;
severity/priority agreement over matches; Kendall tau-b over
priority ranks (pairs tied either side skipped); regression and
resolution detection rates; false-positive/false-negative rates;
citation validity and evidence grounding (scripted AI replies through
the real M12 validator). Empty denominators report `None`, never 0 —
except grouping F1, which is 0.0 when both sides are defined-but-zero
(the standard zero-division convention) and 1.0 only on vacuous
both-empty truth.

## 5. How to run

```bash
.venv/Scripts/python.exe scripts/run_research_evaluation.py
.venv/Scripts/python.exe scripts/run_research_evaluation.py --out research-results
```

Artifacts: `evaluation.json` (canonical sorted-keys encoding) and
`evaluation.csv` (long format: fixture,pipeline,metric,value, plus
`error:<kind>` rows carrying per-fixture mismatch-kind counts).
Re-running yields byte-identical files; divergence means behavior
changed. A nonzero exit (2) with a one-line stderr message means a
missing/malformed dataset — never a traceback for expected errors.

## 6. Expected deterministic behavior

- 54 fixtures evaluate; SentinelGPT grouping F1 is 1.0 on the curated
  set (the set is designed solvable — see threats below).
- Baseline A grouping F1 is 0.0 wherever duplicates exist and its
  resolution rate is 0.0 everywhere.
- Baseline B splits title variants, misses history-dependent
  regressions, and disagrees on first-seen severity — each listed
  verbatim under a classified mismatch kind.
- Every disagreement appears in per-fixture `mismatches` with an
  error taxonomy (`false_positive`, `false_negative`,
  `wrong_grouping_split`, `wrong_grouping_merge`,
  `severity_mismatch`, `lifecycle_mismatch`,
  `priority_level_mismatch`, `missed_regression`,
  `missed_resolution`); aggregates are means recomputed from fixture
  values (a test re-derives them), with micro-averaged pooled rates
  alongside the macro means.

## 7. AI evaluation boundary

Core reproducibility uses deterministic doubles: scripted provider
replies are checked by the real M12 response validator (valid
citations accepted; unknown IDs, invented CVEs/controls, and
certification claims rejected). This measures validator + grounding
mechanics, NOT live Gemini accuracy — never claim live accuracy from
these numbers.

Optional recorded transcripts (`backend/src/research/transcripts/`,
format `sgpt.transcript.v1`) capture a past provider answer with its
evidence hash and model identity (`synthetic-test-double` /
`scripted-reply-v1` in the seeds — model metadata is never
fabricated). Offline replay re-derives the evidence, verifies the
hash, and re-runs the M12 validator: hash mismatches, unknown IDs,
and unsupported claims fail the replay without ever calling a
provider. A live-provider experiment would need recorded transcripts
from the real model, temperature control, and transcript quarantine
from deterministic content — supported structurally, out of scope to
run.

## 8. Threats to validity

- Synthetic fixtures: no transfer claim to live targets, and the
  expanded set still does not represent real-world prevalence.
- Exact-match grouping metric punishes near-misses fully (split/merge
  taxonomy makes the failure mode inspectable, not forgiven).
- Priority ground truth pins current v2 outputs; algorithm changes
  require re-pinning expectations (by design, not silently).
- The dataset is solvable by construction; it demonstrates the
  framework runs honestly (wins, ties, and losses are all
  representable — baselines lose visibly, and micro-averages keep
  large fixtures from hiding small-fixture failures), not that
  SentinelGPT wins universally.
- CVE/CVSS signals are fixture-supplied, not scanner-discovered.
- Ground truth is hand-authored against documented rules, then
  verified by executing the real functions — independence holds
  because expectations encode intended rule behavior (including
  known-quirky rules like max-rank severity and unknown-lifecycle
  conservatism), while failures would surface as listed mismatches.
  A leakage test pins that the dataset contains no computed
  fingerprints.

## 9. Limitations

- 54 fixtures, 6 finding categories (only fingerprintable ones).
- No timing/perf measurement; no live-provider runs (transcript
  replay is structural readiness, not evidence).
- Compliance expectations cover mapping retrieval and assessment
  states, not full-framework audits.
- Reports/PDFs are not part of the evaluation surface.
