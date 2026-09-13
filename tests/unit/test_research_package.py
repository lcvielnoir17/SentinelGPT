"""Research reproducibility package (M15): runner, artifacts, docs.

Verifies the clean-checkout story end to end: the committed runner
executes the versioned dataset offline (subprocess, real interpreter),
byte-identical reruns, stable artifact ordering, graceful dataset
errors, schema-valid generated results, and documentation that matches
the code constants it cites. No network, database, or secrets anywhere.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
RUNNER = REPO_ROOT / "scripts" / "run_research_evaluation.py"
DATASET = REPO_ROOT / "backend" / "src" / "research" / "dataset.json"
DOCS = REPO_ROOT / "docs" / "research-evaluation.md"

PYTHON = sys.executable


def _run(out_dir: pathlib.Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [PYTHON, str(RUNNER), "--out", str(out_dir), *extra],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_clean_environment_run(tmp_path: pathlib.Path) -> None:
    """Committed runner + dataset evaluate with zero setup."""
    out = tmp_path / "results"
    completed = _run(out)
    assert completed.returncode == 0, completed.stderr
    payload = json.loads((out / "evaluation.json").read_text())
    assert payload["dataset_version"] == "sgpt.research.v1"
    assert payload["aggregate"]["sentinelgpt"]["fixture_count"] == 54
    for fixture in payload["fixtures"]:
        for result in fixture["pipelines"].values():
            assert isinstance(result["mismatches"], list)
    lines = (out / "evaluation.csv").read_text().splitlines()
    assert lines[0] == "fixture_id,pipeline,metric,value"
    assert len(lines) > 14 * 3  # every fixture x every pipeline x metrics


def test_deterministic_second_run(tmp_path: pathlib.Path) -> None:
    """Byte-identical artifacts across independent runs."""
    first, second = tmp_path / "a", tmp_path / "b"
    assert _run(first).returncode == 0
    assert _run(second).returncode == 0
    for name in ("evaluation.json", "evaluation.csv"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_stable_fixture_ordering(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "results"
    assert _run(out).returncode == 0
    payload = json.loads((out / "evaluation.json").read_text())
    assert [f["fixture_id"] for f in payload["fixtures"]] == sorted(
        f["fixture_id"] for f in payload["fixtures"]
    )
    rows = (out / "evaluation.csv").read_text().splitlines()[1:]
    assert rows == sorted(rows)


def test_missing_dataset_behavior(tmp_path: pathlib.Path) -> None:
    completed = subprocess.run(
        [PYTHON, str(RUNNER), "--dataset", str(tmp_path / "nope.json")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 2
    assert "not found" in completed.stderr


def test_malformed_dataset_behavior(tmp_path: pathlib.Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"dataset_version": "v9", "fixtures": []}')
    completed = subprocess.run(
        [PYTHON, str(RUNNER), "--dataset", str(bad), "--out", str(tmp_path / "o")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 2
    assert "invalid dataset" in completed.stderr


def test_generated_result_schema(tmp_path: pathlib.Path) -> None:
    """Artifacts carry versions, definitions, raw values, and limits."""
    out = tmp_path / "results"
    assert _run(out).returncode == 0
    payload = json.loads((out / "evaluation.json").read_text())
    assert payload["pipeline_version"].startswith("sgpt.research.pipeline.v")
    assert payload["metric_version"] == "sgpt.research.metrics.v1"
    assert len(payload["dataset_sha256"]) == 64
    assert set(payload["baseline_definitions"]) == {"baseline-a", "baseline-b", "sentinelgpt"}
    assert "grouping_precision" in payload["metric_definitions"]
    assert isinstance(payload["limitations"], list) and payload["limitations"]
    assert "micro" in payload["aggregate"] and "error_taxonomy" in payload["aggregate"]
    replays = payload["transcript_results"]
    assert [(r["fixture_id"], r["accepted"]) for r in replays] == [
        ("dup-headers-01", False),  # unknown-citation seed sorts first
        ("dup-headers-01", True),
    ]
    for fixture in payload["fixtures"]:
        assert set(fixture["pipelines"]) == {"baseline-a", "baseline-b", "sentinelgpt"}
        for result in fixture["pipelines"].values():
            assert isinstance(result["metrics"], dict)
            assert isinstance(result["mismatches"], list)


def test_no_secrets_or_services_required() -> None:
    """Static pins: runner + research import nothing sensitive or live."""
    import pathlib as _pathlib

    tokens = (
        "get_settings",
        "os.environ",
        "os.getenv",
        "infrastructure.database",
        "workers.",
        "socket",
        "httpx",
        "requests",
        "Gemini",
        "genai",
        "session.add",
        "session.commit",
    )
    hits = []
    paths = list((_pathlib.Path("backend/src/research")).rglob("*.py")) + [RUNNER]
    for path in sorted(paths):
        for i, line in enumerate(path.read_text().splitlines(), 1):
            for token in tokens:
                if token in line:
                    hits.append(f"{path.name}:{i}:{token}")
    assert hits == []


def test_documentation_matches_code() -> None:
    """Docs cite the same versions and commands the code implements."""
    from src.research.evaluate import PIPELINE_VERSION
    from src.research.schema import DATASET_VERSION

    text = DOCS.read_text()
    assert DATASET_VERSION in text
    assert "run_research_evaluation.py" in text
    assert "sgpt.research.pipeline.v" in text
    assert PIPELINE_VERSION.split(".v")[0] in text
    for heading in (
        "Research question",
        "Baselines",
        "Metrics",
        "How to run",
        "Threats to validity",
        "Limitations",
    ):
        assert heading in text
