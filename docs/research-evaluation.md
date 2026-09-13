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
  `PIPELINE_VERSION` in `backend/src/research/evaluate.py`), stamped
  on every evaluation result alongside the dataset version.
- 14 synthetic fixtures. Each fixture: stable `hostname`, `scan_a`
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
`evaluation.csv` (long format: fixture,pipeline,metric,value).
Re-running yields byte-identical files; divergence means behavior
changed. A nonzero exit (2) with a one-line stderr message means a
missing/malformed dataset — never a traceback for expected errors.

## 6. Expected deterministic behavior

- 14 fixtures evaluate; SentinelGPT grouping F1 is 1.0 on the curated
  set (the set is designed solvable — see threats below).
- Baseline A grouping F1 is 0.0 wherever duplicates exist and its
  resolution rate is 0.0 everywhere.
- Baseline B splits the title variant (`title-variants-merge`,
  recall 0.0) and misses the history-dependent regression
  (`regression`, lifecycle mismatch listed verbatim).
- Every disagreement appears in per-fixture `mismatches`; aggregates
  are means recomputed from fixture values (a test re-derives them).

## 7. AI evaluation boundary

Core reproducibility uses deterministic doubles: scripted provider
replies are checked by the real M12 response validator (valid
citations accepted; unknown IDs, invented CVEs/controls, and
certification claims rejected). This measures validator + grounding
mechanics, NOT live Gemini accuracy — never claim live accuracy from
these numbers. A live-provider experiment would need recorded
transcripts, model version pinning, and temperature control, and is
explicitly out of scope.

## 8. Threats to validity

- Synthetic fixtures: no transfer claim to live targets.
- Exact-match grouping metric punishes near-misses fully.
- Priority ground truth pins current v2 outputs; algorithm changes
  require re-pinning expectations (by design, not silently).
- The dataset is solvable by construction; it demonstrates the
  framework runs honestly (wins, ties, and losses are all
  representable — baselines lose visibly), not that SentinelGPT wins
  universally.
- CVE/CVSS signals are fixture-supplied, not scanner-discovered.

## 9. Limitations

- 14 fixtures, 6 finding categories (only fingerprintable ones).
- No timing/perf measurement; no live-provider runs.
- Compliance expectations cover mapping retrieval only.
- Reports/PDFs are not part of the evaluation surface.
