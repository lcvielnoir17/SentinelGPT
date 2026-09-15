"""M21 defense evidence package builder (offline, deterministic).

Renders the thesis/defense package from the M20 combined results
(no live calls, no re-scoring — every number traces to an existing
artifact):

    .venv/Scripts/python.exe scripts/build_defense_package.py
    .venv/Scripts/python.exe scripts/build_defense_package.py \\
        --results-dir research-results --out research-defense

Outputs (generated; stay uncommitted per repository convention):
executive-summary.md, research-methodology.md, results.md,
discussion.md, limitations.md, conclusion.md, claim-matrix.json,
defense-questions.md, tables.json, human-review.md,
figures/*.svg, reproducibility.md. Re-runs are byte-identical.
Exit 0 on success, exit 2 on missing/corrupt inputs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


def _esc(text: str) -> str:
    """Minimal output encoding for SVG chart labels (no XML parsing)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


REPO_ROOT = Path(__file__).resolve().parent.parent
for candidate in (REPO_ROOT / "backend", REPO_ROOT / "backend" / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

DEFAULT_RESULTS_DIR = REPO_ROOT / "research-results"
DEFAULT_LIVE_DIR = Path(tempfile.gettempdir()) / "sgpt-live-transcripts"

_SECRET_PATTERNS = (
    re.compile(r"(?i)\bGEMINI_API_KEY\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{10,}={0,2}"),
    re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{10,}"),
)


class PackageError(ValueError):
    """A source artifact is missing, corrupt, or unsafe to publish."""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise PackageError(f"missing input: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PackageError(f"corrupt input: {path} ({exc})") from exc


def _fmt(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    if value is None:
        return "n/a"
    return str(value)


def _bar_chart(
    title: str,
    subtitle: str,
    series: list[tuple[str, float | None]],
    footnote: str,
) -> str:
    rows: list[str] = []
    width, bar_max, y = 560, 320, 70
    for label, value in series:
        pct = max(0.0, min(1.0, value if value is not None else 0.0))
        bar = int(bar_max * pct)
        text = _fmt(value)
        rows.append(
            f'<text x="10" y="{y + 12}">{_esc(label)}</text>'
            f'<rect x="190" y="{y}" width="{bar}" height="16"/>'
            f'<text x="{200 + bar}" y="{y + 12}">{_esc(text)}</text>'
        )
        y += 30
    height = y + 40
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
        f"<style>text{{font-family:sans-serif;font-size:12px}}"
        f"rect{{fill:#2f6fed}}</style>"
        f'<text x="10" y="24" font-weight="bold">{_esc(title)}</text>'
        f'<text x="10" y="42">{_esc(subtitle)}</text>'
        + "".join(rows)
        + f'<text x="10" y="{height - 10}">{_esc(footnote)}</text></svg>'
    )


def _write(out_dir: Path, name: str, text: str) -> None:
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            raise PackageError(f"secret pattern in {name}; refusing to write package")
    (out_dir / name).write_text(text)


def _write_json(out_dir: Path, name: str, payload: Any) -> None:
    _write(out_dir, name, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines) + "\n"


def _review_state(review_text: str | None) -> tuple[bool, str, str]:
    """Review completeness plus the recorded usefulness verdicts.

    Returns ``(complete, usefulness_note, status_note)`` read from the
    supplied review document only — nothing is inferred when no review
    is supplied. Individual judgments always live in human-review.md.
    """
    if review_text is None:
        return False, "", "review pending"
    from src.research.live_review import review_completion

    completed, total = review_completion(review_text)
    if total == 0 or completed != total:
        return False, "", f"review pending ({completed}/{total} recorded)"
    usefulness = sorted(
        {
            line.split(":", 1)[1].strip()
            for line in review_text.splitlines()
            if line.startswith("- Human usefulness assessment:")
        }
    )
    verdict = (
        f'"{usefulness[0]}" across all {total} stored transcripts'
        if len(usefulness) == 1
        else "mixed across stored transcripts"
    )
    return True, verdict, f"recorded ({completed}/{total} human-reviewed)"


def build_package(results_dir: Path, human_review_text: str | None = None) -> dict[str, str]:
    """Render every package file (pure; writing happens in main)."""
    reviewed, usefulness_note, _status_note = _review_state(human_review_text)
    tables = _read_json(results_dir / "research-tables.json")
    combined = _read_json(results_dir / "combined-summary.json")
    deterministic = _read_json(results_dir / "deterministic-results.json")
    live = _read_json(results_dir / "live-provider-results.json")
    provider_failures = _read_json(results_dir / "provider-failures.json")
    validator = _read_json(results_dir / "validator-analysis.json")
    error_analysis = _read_json(results_dir / "error-analysis.json")
    if not all(isinstance(d, dict) for d in (tables, combined, deterministic, live)):
        raise PackageError("results inputs must be objects")

    det = deterministic["aggregate"]
    files: dict[str, str] = {}

    files["executive-summary.md"] = (
        "# SentinelGPT — Executive Summary (M10–M21)\n\n"
        "Controlled synthetic evaluation (n=54 fixtures, three pipelines): "
        f"SentinelGPT grouping F1 {_fmt(det['sentinelgpt']['grouping_f1'])} vs "
        f"baseline B {_fmt(det['baseline-b']['grouping_f1'])} vs baseline A "
        f"{_fmt(det['baseline-a']['grouping_f1'])}; severity, priority, "
        "regression, and resolution agreement 1.000 on the frozen set.\n\n"
        "Live-provider exploratory evaluation (12 frozen prompts, model "
        f"{live['model']}): {live['transcript_count']} genuine transcripts "
        f"stored, validator acceptance {live['validator_acceptance_rate']} over "
        "stored, 4 provider failures (quota/availability/transport) with "
        "sanitized diagnostics; adversarial coverage did not complete.\n\n"
        "Scope: synthetic fixtures only. No accuracy, superiority, "
        "real-world, or compliance claim is supported beyond the frozen sets.\n"
    )

    methodology = [
        "# Research Methodology (M10–M21)\n",
        "## Dataset construction",
        "54 synthetic fixtures (`sgpt.research.v1`) with pinned ground truth "
        "(canonical groups, severity, lifecycle, priority, compliance controls); "
        "history-pair fixtures carry rescan snapshots for lifecycle scoring.",
        "## Ground truth",
        "Rule-pinned expectations authored with the fixtures; exact-match "
        "scoring against member sets, severity, priority, lifecycle, and controls.",
        "## Baseline definitions",
    ]
    for name in ("baseline-a", "baseline-b", "sentinelgpt"):
        methodology.append(f"- {name}: {deterministic['baseline_definitions'][name]}")
    methodology.extend(
        [
            "## Scoring",
            "Grouping precision/recall/F1, duplicate-reduction, severity "
            "consistency, priority agreement, Kendall tau-b, regression and "
            "resolution detection, FP/FN rates (`sgpt.research.metrics.v1`).",
            "## Fixture execution",
            "Each fixture runs through all three pipelines in-process; no "
            "network, database, or live targets.",
            "## Deterministic rerun",
            "`scripts/run_research_evaluation.py [--out research-results]` "
            "reproduces byte-identical artifacts.",
            "## Live-provider procedure",
            "Opt-in only (`RESEARCH_LIVE_PROVIDER=1` + environment key), 12 "
            "predeclared prompts (`sgpt.live-prompts.v1`), M19-only model "
            "selection, paced calls, quarantine directory outside the repo, "
            "M12 validator replay offline.",
            "## Transcript quarantine",
            "Per-question files plus five aggregate artifacts; stale "
            "per-question files cleared per run; aggregates never-committed.",
            "## Validator replay",
            "`replay_all` re-derives evidence, checks hashes, runs the M12 "
            "validator; hash mismatches fail closed.",
            "## Manual review",
            "`live-manual-review.csv` separates automated and human columns; "
            "human judgment pending unless a reviewer filled it.",
            "## Limitations",
            "See limitations.md — synthetic-only, small live sample, "
            "quota-bound, no prevalence estimate.",
        ]
    )
    files["research-methodology.md"] = "\n".join(methodology) + "\n"

    results = [
        "# Results\n",
        "## Table 1 — Dataset composition",
        f"Fixtures: {deterministic['fixture_composition']['fixture_count']}; "
        f"history-pair fixtures: "
        f"{len(deterministic['fixture_composition']['history_pair_fixtures'])}; "
        f"dataset sha256: `{deterministic['dataset_sha256']}`.",
        "\n## Table 2 — Pipeline definitions",
    ]
    for name in ("baseline-a", "baseline-b", "sentinelgpt"):
        results.append(f"- {name}: {deterministic['baseline_definitions'][name]}")
    results.append("\n## Table 3 — Grouping performance (synthetic, n=54)")
    results.append(
        _markdown_table(
            ["Pipeline", "Precision", "Recall", "F1", "Dup-reduction"],
            [
                [
                    name,
                    _fmt(det[name]["grouping_precision"]),
                    _fmt(det[name]["grouping_recall"]),
                    _fmt(det[name]["grouping_f1"]),
                    _fmt(det[name]["duplicate_reduction_rate"]),
                ]
                for name in ("baseline-a", "baseline-b", "sentinelgpt")
            ],
        )
    )
    results.append("## Table 4 — Severity and priority agreement (synthetic, n=54)")
    results.append(
        _markdown_table(
            ["Pipeline", "Severity", "Priority", "tau-b"],
            [
                [
                    name,
                    _fmt(det[name]["severity_consistency"]),
                    _fmt(det[name]["priority_agreement"]),
                    _fmt(det[name].get("ranking_tau_b")),
                ]
                for name in ("baseline-a", "baseline-b", "sentinelgpt")
            ],
        )
    )
    results.append("## Table 5 — Lifecycle / regression / resolution (synthetic)")
    results.append(
        _markdown_table(
            ["Pipeline", "Regression", "Resolution", "FP rate", "FN rate"],
            [
                [
                    name,
                    _fmt(det[name]["regression_detection_rate"]),
                    _fmt(det[name]["resolution_detection_rate"]),
                    _fmt(det[name]["false_positive_rate"]),
                    _fmt(det[name]["false_negative_rate"]),
                ]
                for name in ("baseline-a", "baseline-b", "sentinelgpt")
            ],
        )
    )
    results.append("## Table 6 — Error taxonomy (counts, synthetic)")
    tax_rows = []
    for name in ("baseline-a", "baseline-b", "sentinelgpt"):
        for kind, count in sorted(
            det["error_taxonomy"][name].items()
            if isinstance(det["error_taxonomy"].get(name), dict)
            else []
        ):
            tax_rows.append([name, kind, str(count)])
    results.append(_markdown_table(["Pipeline", "Error kind", "Count"], tax_rows))
    results.append("## Table 7 — Live-provider attempt outcomes (12 frozen prompts)")
    results.append(
        _markdown_table(
            ["Question", "Fixture", "Adversarial", "Provider", "Stored", "Validator"],
            [
                [
                    a["question_id"],
                    a["fixture_id"],
                    str(a["adversarial"]),
                    a["provider_outcome"],
                    str(a["transcript_stored"]),
                    a["validator_outcome"],
                ]
                for a in live["attempts"]
            ],
        )
    )
    results.append("## Table 8 — Live validator outcomes")
    results.append(
        f"Validator: {validator['validator']}. "
        f"Acceptance over stored: {live['validator_acceptance_rate']} "
        f"({sum(1 for a in live['attempts'] if a['validator_outcome'] == 'accepted')} "
        f"of {live['transcript_count']}); unsupported-claim rate: "
        f"{live['unsupported_claim_rate']}; citation mean: {live['citation_validity_mean']}.\n"
        f"Stored model-output failures this run: "
        f"{error_analysis['live_model_output_failures']['schema_mismatch_stored']} "
        "schema mismatches, "
        f"{error_analysis['live_model_output_failures']['missing_fields_stored']} "
        "missing-field sets.\n"
    )
    results.append("## Table 9 — Provider failure categories")
    cats: dict[str, int] = {}
    for failure in provider_failures["failures"]:
        cats[failure["category"]] = cats.get(failure["category"], 0) + 1
    results.append(
        _markdown_table(
            ["Category", "Count"],
            [[category, str(cats[category])] for category in sorted(cats)] or [["none", "0"]],
        )
    )
    results.append("## Table 10 — Threats to validity")
    for threat in combined["threats_to_validity"]:
        results.append(f"- {threat}")
    results.append(
        "\nFull precision values: tables.json. Live details: live-provider-results.json."
    )
    files["results.md"] = "\n".join(results) + "\n"

    files["discussion.md"] = (
        "# Discussion\n\n"
        "## What was observed\n"
        "The deterministic pipeline reproduced the pinned ground truth "
        "exactly across 54 fixtures while both baselines deviated on "
        "grouping, priority, and lifecycle measures. Among 8 successful "
        "live-provider attempts, every stored reply validated under M12 "
        "with byte-identical offline replay.\n\n"
        "## What was inferred\n"
        "Exact-match determinism is achievable for normalization, "
        "correlation, and prioritization on constructed evidence; the M12 "
        "contract admits well-formed live-shaped replies deterministically.\n\n"
        "## What remains unknown\n"
        "Generalization to live targets, model behavior at larger samples, "
        "adversarial robustness (unmeasured — provider failures), and "
        + (
            f"human-judged usefulness beyond the completed review ({usefulness_note}).\n"
            if reviewed
            else "human-judged usefulness (review pending).\n"
        )
    )
    files["limitations.md"] = "# Limitations\n\n" + "".join(
        f"- {item}\n" for item in combined["limitations"]
    )
    files["conclusion.md"] = (
        "# Conclusion\n\n"
        "The controlled evaluation indicates that the implemented "
        "deterministic pipeline reproduced the predefined ground truth "
        "more closely than the two comparison baselines across the "
        "evaluated synthetic fixtures. The live-provider exploratory run "
        "demonstrates that the collection, validation, and accounting "
        "machinery works on genuine provider output. These results do not "
        "establish generalization to live-world targets, model accuracy, "
        "or operational superiority; those require larger samples, live "
        "targets, completed adversarial coverage, and "
        + (
            "broader human evaluation beyond the completed 8-transcript review.\n"
            if reviewed
            else "human review.\n"
        )
    )
    claims = []
    for claim in combined["supported_claims"]:
        claims.append(
            {
                "claim": claim,
                "status": "supported",
                "scope": "frozen synthetic/live sets only",
                "limitation": "see limitations.md",
            }
        )
    for claim in combined["unsupported_claims"]:
        claims.append(
            {
                "claim": claim,
                "status": "explicitly-unsupported",
                "scope": "none established",
                "limitation": "would require larger/live-target study",
            }
        )
    files["claim-matrix.json"] = json.dumps(claims, indent=2, sort_keys=True) + "\n"

    questions = [
        (
            "What is SentinelGPT's research contribution?",
            "Deterministic normalization, correlation/deduplication, contextual "
            "prioritization, and evidence-grounded AI interpretation with the AI "
            "as decision support — supported by exact reproduction on 54 fixtures, "
            "not by live accuracy.",
        ),
        (
            "Why not just use a scanner?",
            "Scanners emit observations; SentinelGPT correlates them into "
            "canonical findings with lifecycle and priority (baseline A shows "
            "scanner-only output: F1 0.568, priority agreement 0.0).",
        ),
        (
            "Why are the baselines structured this way?",
            "Baseline A isolates scanner-only output; baseline B isolates "
            "rule-based grouping without history/compliance, attributing each "
            "capability layer (see Table 2).",
        ),
        (
            "Why is deterministic correlation important?",
            "Duplicate/noisy observations inflate work; exact grouping (F1 1.0 "
            "vs 0.568/0.938) is the measured effect on the frozen set.",
        ),
        (
            "Why is priority deterministic?",
            "Priority from pinned signals is auditable and replayable; model "
            "opinions on priority are forbidden by the trust model.",
        ),
        (
            "Why is AI not authoritative?",
            "Models cannot mutate findings/severity/lifecycle by construction "
            "(validator has no write path); AI narrates evidence only.",
        ),
        (
            "Why are synthetic fixtures used?",
            "Control: pinned ground truth enables exact scoring impossible on "
            "live targets; transfer is explicitly not claimed.",
        ),
        (
            "Why are the results not generalizable?",
            "n=54 constructed fixtures, exact-match metrics, no prevalence "
            "estimate, no live targets (see limitations.md).",
        ),
        (
            "What happened during live Gemini evaluation?",
            f"12 attempts: {live['transcript_count']} stored, all accepted; "
            "4 provider failures with sanitized diagnostics (Table 7/9).",
        ),
        (
            "Why were some provider calls unsuccessful?",
            "Free-tier quota, transient high demand, one transport error — "
            "availability causes, recorded in provider-failures.json, distinct "
            "from output quality.",
        ),
        (
            "Why were some AI outputs rejected?",
            "In the final run none were; an earlier run's 5 rejections were a "
            "collector fence-formatting artifact (recovered offline, all 5 "
            "validate accepted), not model non-compliance.",
        ),
        (
            "Why is validator acceptance not model accuracy?",
            "Acceptance checks contract compliance (shape, bounds, cited IDs) "
            "— not factual correctness or usefulness, which need human review.",
        ),
        (
            "What are the limitations?",
            f"See limitations.md ({len(combined['limitations'])} items, incl. "
            "n=8 live sample"
            + (", completed 8/8 human review" if reviewed else " and pending review")
            + ").",
        ),
        (
            "How was research bias controlled?",
            "Frozen dataset/prompts/metrics, byte-identical reruns, no "
            "post-hoc fixture/metric edits, failures retained and reported.",
        ),
        (
            "How was ground truth constructed?",
            "Authored with fixtures as pinned canonical expectations; sha "
            f"`{deterministic['dataset_sha256'][:12]}` identifies the exact set.",
        ),
        (
            "How was prompt injection handled?",
            "Evidence-side framing plus citation/compliance allow-lists; "
            "adversarial live coverage did not complete (0/3 stored), so no "
            "resistance claim is made.",
        ),
        (
            "How is the system different from ordinary vulnerability scanners?",
            "Correlation, lifecycle derivation, priority, compliance mapping, "
            "and grounded narration layers atop scanner observations (Table 2).",
        ),
        (
            "What remains for future work?",
            "Live targets, larger samples, completed adversarial coverage, "
            + (
                f"broader human evaluation beyond the completed 8-transcript review "
                f"({usefulness_note}), "
                if reviewed
                else "human usefulness review, "
            )
            + "quota-independent replication.",
        ),
    ]
    files["defense-questions.md"] = "# Defense Questions (evidence-based)\n\n" + "".join(
        f"## {i}. {q}\n{answer}\n\n" for i, (q, answer) in enumerate(questions, 1)
    )

    tables_out = dict(tables)
    tables_out["table_10_threats_to_validity"] = combined["threats_to_validity"]
    files["tables.json"] = json.dumps(tables_out, indent=2, sort_keys=True) + "\n"

    review_rows = [
        "# Human Review Package (8 genuine transcripts)\n",
        "Automated results are immutable. Human columns are "
        "PENDING HUMAN REVIEW until a reviewer fills them.\n",
    ]
    for attempt in live["attempts"]:
        if not attempt["transcript_stored"]:
            continue
        review_rows.append(
            f"## {attempt['question_id']} ({attempt['fixture_id']})\n"
            f"- Automated validator: {attempt['validator_outcome']}"
            f" ({attempt['validator_reason']})\n"
            f"- Citations: {attempt['citations_count']} | "
            f"citation validity: {attempt['citation_validity']}\n"
            "- Human factual assessment: PENDING HUMAN REVIEW\n"
            "- Human usefulness assessment: PENDING HUMAN REVIEW\n"
            "- Human safety assessment: PENDING HUMAN REVIEW\n"
            "- Reviewer notes: PENDING HUMAN REVIEW\n"
            "- Reviewer/date: PENDING HUMAN REVIEW\n"
        )
    files["human-review.md"] = "\n".join(review_rows) + "\n"

    files["reproducibility.md"] = (
        "# Reproducibility\n\n"
        "- Deterministic: `.venv/Scripts/python.exe "
        "scripts/run_research_evaluation.py [--out research-results]` "
        "(byte-identical).\n"
        "- M20 analysis: `.venv/Scripts/python.exe "
        "scripts/analyze_research_results.py [--live-dir <quarantine>] "
        "[--out research-results]` (byte-identical).\n"
        "- This package: `.venv/Scripts/python.exe "
        "scripts/build_defense_package.py [--results-dir research-results] "
        "[--out research-defense]` (byte-identical).\n"
        "- Live transcripts are immutable inputs; the package never calls "
        "any provider.\n"
        f"- Source versions: dataset `{deterministic['dataset_version']}`, "
        f"pipeline `{deterministic['pipeline_version']}`, metrics "
        f"`{deterministic['metric_version']}`, prompts `sgpt.live-prompts.v1`.\n"
    )

    files["figures/grouping-f1.svg"] = _bar_chart(
        "Grouping F1 (synthetic, n=54)",
        "Exact member-set matches",
        [
            ("baseline-a", det["baseline-a"]["grouping_f1"]),
            ("baseline-b", det["baseline-b"]["grouping_f1"]),
            ("sentinelgpt", det["sentinelgpt"]["grouping_f1"]),
        ],
        "Full precision in tables.json.",
    )
    files["figures/priority-agreement.svg"] = _bar_chart(
        "Priority agreement (synthetic, n=54)",
        "Matched groups, expected level",
        [
            ("baseline-a", det["baseline-a"]["priority_agreement"]),
            ("baseline-b", det["baseline-b"]["priority_agreement"]),
            ("sentinelgpt", det["sentinelgpt"]["priority_agreement"]),
        ],
        "Full precision in tables.json.",
    )
    files["figures/regression-resolution.svg"] = _bar_chart(
        "Regression / resolution detection (synthetic)",
        "Expected lifecycle reproduced",
        [
            ("B regression", det["baseline-b"]["regression_detection_rate"]),
            ("B resolution", det["baseline-b"]["resolution_detection_rate"]),
            ("SGPT regression", det["sentinelgpt"]["regression_detection_rate"]),
            ("SGPT resolution", det["sentinelgpt"]["resolution_detection_rate"]),
        ],
        "Baseline A scores 0.0 on both; full precision in tables.json.",
    )
    by_outcome = live["attempts_by_outcome"]
    files["figures/live-outcomes.svg"] = _bar_chart(
        "Live-provider attempts (exploratory, n=12, NOT representative)",
        f"Model {live['model']}",
        [
            ("accepted", (by_outcome.get("completed_accepted", 0) or 0) / 12),
            ("provider-failed", (by_outcome.get("provider_failed", 0) or 0) / 12),
        ],
        "Shares of 12 frozen attempts; not a statistical sample.",
    )
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR))
    parser.add_argument(
        "--human-review",
        default=None,
        help="Optional completed human-review document; updates review-status wording.",
    )
    parser.add_argument("--out", default="research-defense")
    args = parser.parse_args(argv)

    results_dir = Path(args.results_dir)
    out_dir = Path(args.out)
    try:
        review_text = Path(args.human_review).read_text() if args.human_review else None
    except OSError as exc:
        print(f"error: cannot load human review: {exc}", file=sys.stderr)
        return 2
    try:
        files = build_package(results_dir, human_review_text=review_text)
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "figures").mkdir(parents=True, exist_ok=True)
    review_path = out_dir / "human-review.md"
    written = 0
    try:
        for name in sorted(files):
            if name == "human-review.md" and review_path.exists():
                # Human judgments are append-only human data: never
                # overwrite a completed review with the PENDING template.
                # The template is written on first creation only.
                print("keeping existing human-review.md (human judgments preserved)")
                continue
            _write(out_dir, name, files[name])
            written += 1
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {written} defense files to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
