"""Research fixtures & ground truth (M13): schema, determinism, boundary.

Proves the dataset is versioned, reproducible, and isolated: schema
validation rejects malformed/duplicate fixtures, loading twice yields
identical results, ground truth is consistent with observations, the
SentinelGPT pipeline runs real domain functions offline, and the
research package cannot reach production scanning, persistence,
network, or AI providers (static boundary guard).
"""

from __future__ import annotations

import json
import pathlib

import pytest

from src.research.pipeline import (
    fingerprint_of,
    run_baseline_a,
    run_baseline_b,
    run_sentinelgpt,
)
from src.research.schema import (
    DATASET_VERSION,
    FixtureValidationError,
    check_ground_truth_consistency,
    validate_dataset,
    validate_fixture,
)

DATASET_PATH = pathlib.Path("backend/src/research/dataset.json")


def _load() -> dict:
    return validate_dataset(json.loads(DATASET_PATH.read_text()))


def _obs(obs_id: str, **overrides: object) -> dict:
    row: dict[str, object] = {
        "obs_id": obs_id,
        "engine": "headers-analyzer",
        "title": "Missing X-Frame-Options security header",
        "severity": "MEDIUM",
        "category": "MISSING_SECURITY_HEADER",
        "evidence": "e",
        "location": "/",
    }
    row.update(overrides)
    return row


def _fixture(**overrides: object) -> dict:
    base: dict[str, object] = {
        "id": "test-01",
        "hostname": "target.example",
        "scan_a": [_obs("o1")],
        "ground_truth": {
            "canonical": [
                {
                    "key": "xfo",
                    "members": ["o1"],
                    "severity": "MEDIUM",
                    "category": "MISSING_SECURITY_HEADER",
                    "lifecycle": "NEW",
                }
            ],
            "compliance": {},
        },
    }
    base.update(overrides)
    return base  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Schema validation                                                           #
# --------------------------------------------------------------------------- #


def test_dataset_loads_with_version() -> None:
    dataset = _load()
    assert dataset["dataset_version"] == DATASET_VERSION == "sgpt.research.v1"
    assert len(dataset["fixtures"]) == 54
    assert [f["id"] for f in dataset["fixtures"]] == sorted(f["id"] for f in dataset["fixtures"])


@pytest.mark.parametrize(
    "mutation",
    [
        {"dataset_version": "v9"},
        {"fixtures": []},
        {"fixtures": "nope"},
        {},
        [],
        "text",
    ],
)
def test_malformed_dataset_rejected(mutation: object) -> None:
    with pytest.raises(FixtureValidationError):
        validate_dataset(mutation)


def test_malformed_fixture_rejected() -> None:
    base = _fixture()
    for bad in (
        {**base, "id": ""},
        {**base, "scan_a": []},
        {**base, "scan_a": [{**base["scan_a"][0], "severity": "CRITICALITY"}]},
        {**base, "scan_a": [_obs("o1"), _obs("o1")]},
        {**base, "history": {"o1": 5}},
        {**base, "remediation": {"o1": "FIXED"}},
        {**base, "ground_truth": {}},
        {**base, "ground_truth": {"canonical": [], "compliance": {}}},
    ):
        with pytest.raises(FixtureValidationError):
            validate_fixture(bad)


def test_duplicate_fixture_rejected() -> None:
    with pytest.raises(FixtureValidationError):
        validate_dataset({"dataset_version": DATASET_VERSION, "fixtures": [_fixture(), _fixture()]})


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #


def test_load_twice_identical() -> None:
    first = _load()
    second = _load()
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_pipeline_deterministic() -> None:
    dataset = _load()
    for fixture in dataset["fixtures"]:
        assert run_sentinelgpt(fixture) == run_sentinelgpt(fixture)
        assert run_baseline_a(fixture) == run_baseline_a(fixture)
        assert run_baseline_b(fixture) == run_baseline_b(fixture)


def test_fingerprints_stable() -> None:
    assert fingerprint_of(
        "target.example", "MISSING_SECURITY_HEADER", "Missing X-Frame-Options security header"
    ) == fingerprint_of(
        "target.example", "MISSING_SECURITY_HEADER", "Missing X-Frame-Options security header"
    )


# --------------------------------------------------------------------------- #
# Ground truth                                                                #
# --------------------------------------------------------------------------- #


def test_ground_truth_consistent() -> None:
    for fixture in _load()["fixtures"]:
        assert check_ground_truth_consistency(fixture) == [], fixture["id"]


def test_ground_truth_inconsistency_detected() -> None:
    fixture = validate_fixture(_fixture())
    fixture["ground_truth"]["canonical"][0]["members"] = ["ghost"]
    assert check_ground_truth_consistency(fixture)
    raw = _fixture(scan_b=[_obs("o9")])
    assert check_ground_truth_consistency(validate_fixture(raw))


def test_sentinelgpt_matches_ground_truth_groups() -> None:
    """Every fixture's real-pipeline grouping equals the pinned expectation."""
    for fixture in _load()["fixtures"]:
        predicted = sorted(tuple(sorted(g["members"])) for g in run_sentinelgpt(fixture)["groups"])
        expected = sorted(tuple(sorted(e["members"])) for e in fixture["ground_truth"]["canonical"])
        assert predicted == expected, fixture["id"]


def test_sentinelgpt_matches_ground_truth_fields() -> None:
    for fixture in _load()["fixtures"]:
        by_members = {tuple(sorted(g["members"])): g for g in run_sentinelgpt(fixture)["groups"]}
        for entry in fixture["ground_truth"]["canonical"]:
            group = by_members[tuple(sorted(entry["members"]))]
            assert group["severity"] == entry["severity"], fixture["id"]
            assert group["lifecycle"] == entry["lifecycle"], fixture["id"]
            assert group["priority_level"] == entry["priority_level"], fixture["id"]
            assert group["category"] == entry["category"], fixture["id"]


def test_baseline_input_equivalence() -> None:
    """All pipelines consume the same observations (nothing added/removed).

    SentinelGPT additionally reports fingerprint-less observations
    separately (mirroring production); those are covered by the
    unidentified assertion, not by group membership.
    """
    for fixture in _load()["fixtures"]:
        obs_ids = sorted(o["obs_id"] for o in fixture["scan_a"] + fixture["scan_b"])
        expected_unidentified = sorted(fixture["ground_truth"].get("unidentified", []))
        for runner in (run_baseline_a, run_baseline_b, run_sentinelgpt):
            output = runner(fixture)
            seen = sorted(m for g in output["groups"] for m in g["members"])
            if runner is run_sentinelgpt:
                seen = sorted(set(seen) | set(output.get("unidentified", [])))
                assert output.get("unidentified", []) == expected_unidentified, (
                    fixture["id"],
                    runner.__name__,
                )
            assert seen == obs_ids, (fixture["id"], runner.__name__)


def test_remediation_never_moves_lifecycle() -> None:
    """DONE + PERSISTENT coexists: workflow state cannot resolve findings."""
    dataset = _load()
    fixture = next(f for f in dataset["fixtures"] if f["id"] == "remediation-persistence")
    group = run_sentinelgpt(fixture)["groups"][0]
    assert group["remediation_status"] == "DONE"
    assert group["lifecycle"] == "PERSISTENT"


# --------------------------------------------------------------------------- #
# Production boundary + security                                              #
# --------------------------------------------------------------------------- #


def test_research_package_boundary_static() -> None:
    """Research modules import stdlib + pure domain functions only.

    No scanner execution, repositories, workers, network clients, or AI
    providers — fixtures stay isolated from production scanning and
    canonical findings stay untouchable by construction.
    """
    import pathlib as _pathlib

    forbidden_tokens = (
        "infrastructure.database",
        "workers.",
        "scanning.sandbox",
        "google.generativeai",
        "google.genai",
        "import httpx",
        "from httpx",
        "import requests",
        "import socket",
        "Gemini",
        "session.add",
        "session.commit",
        ".execute(",
    )
    root = _pathlib.Path("backend/src/research")
    hits = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("from src.") or stripped.startswith("import src."):
                module = stripped.split()[1].rstrip(",")
                allowed = module == "src.research" or module.startswith(
                    (
                        "src.research.",
                        "src.domain.scans.",
                        "src.domain.compliance.",
                        # M16 transcripts reuse the pure M12 response
                        # validator (+ its evidence dataclass): no agent,
                        # no network, no writes.
                        "src.domain.investigation.validator",
                        "src.domain.investigation.evidence",
                    )
                )
                if not allowed:
                    hits.append(f"{path.name}:{i}:{stripped}")
            for token in forbidden_tokens:
                if token in line:
                    hits.append(f"{path.name}:{i}:{token}")
    assert hits == []


def test_no_network_dependency() -> None:
    """The full M13 path runs with sockets disabled."""
    import socket

    real_create = socket.socket.connect

    def refused(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access attempted")

    socket.socket.connect = refused  # type: ignore[method-assign]
    try:
        dataset = _load()
        for fixture in dataset["fixtures"]:
            run_sentinelgpt(fixture)
            run_baseline_a(fixture)
            run_baseline_b(fixture)
    finally:
        socket.socket.connect = real_create  # type: ignore[method-assign]


def test_prompt_injection_stays_inert() -> None:
    """Adversarial text is fingerprinted as data; output claims nothing."""
    dataset = _load()
    fixture = next(f for f in dataset["fixtures"] if f["id"] == "prompt-injection")
    output = run_sentinelgpt(fixture)
    blob = json.dumps(output)
    assert output["groups"][0]["lifecycle"] == "NEW"
    for banned in ("COMPLIANT", "CERTIFIED", "RESOLVED", "FIXED"):
        assert banned not in blob


def test_unsupported_category_raises() -> None:
    """Categories without extractor rules fail loudly, never silently."""
    from src.domain.scans.fingerprinting import UnsupportedFingerprintCategory
    from src.research.pipeline import fingerprint_of

    with pytest.raises(UnsupportedFingerprintCategory):
        fingerprint_of("target.example", "DNS_MISCONFIGURATION", "whatever")


def test_same_fixture_twice_same_result() -> None:
    dataset = _load()
    fixture = next(f for f in dataset["fixtures"] if f["id"] == "dup-headers-01")
    first = run_sentinelgpt(fixture)
    # Reload from disk (not reuse) to prove file-level reproducibility.
    reloaded = next(f for f in _load()["fixtures"] if f["id"] == "dup-headers-01")
    assert run_sentinelgpt(reloaded) == first
