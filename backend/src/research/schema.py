"""Research fixture schema: versioned dataset validation (M13).

The dataset is a committed JSON file — deterministic by construction
(no generator, no randomness, no timestamps). Every fixture carries
its ground truth alongside the raw observations so evaluation never
guesses intent. Validation is hand-rolled (no new dependency) with
errors that name the fixture, field, and reason.
"""

from __future__ import annotations

from typing import Any

DATASET_VERSION = "sgpt.research.v1"

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
LIFECYCLES = ("NEW", "PERSISTENT", "RESOLVED", "REGRESSED")
STATUSES = ("TODO", "IN_PROGRESS", "DONE", "DEFERRED")

_REQUIRED_OBS_FIELDS = ("obs_id", "engine", "title", "severity", "category")
_REQUIRED_CANONICAL_FIELDS = ("key", "members", "severity", "category", "lifecycle")


class FixtureValidationError(ValueError):
    """A dataset fixture failed deterministic schema validation."""


def validate_dataset(raw: object) -> dict[str, Any]:
    """Validate a decoded dataset document (raises FixtureValidationError)."""
    if not isinstance(raw, dict):
        raise FixtureValidationError("dataset must be a JSON object")
    version = raw.get("dataset_version")
    if version != DATASET_VERSION:
        raise FixtureValidationError(
            f"dataset_version must be {DATASET_VERSION!r}, got {version!r}"
        )
    fixtures = raw.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise FixtureValidationError("fixtures must be a non-empty list")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, fixture in enumerate(fixtures):
        clean = validate_fixture(fixture, index=index)
        if clean["id"] in seen:
            raise FixtureValidationError(f"duplicate fixture id: {clean['id']!r}")
        seen.add(clean["id"])
        validated.append(clean)
    validated.sort(key=lambda f: str(f["id"]))
    return {"dataset_version": DATASET_VERSION, "fixtures": validated}


def validate_fixture(raw: object, *, index: int = 0) -> dict[str, Any]:
    """Validate one fixture (raises FixtureValidationError)."""
    where = f"fixtures[{index}]"
    if not isinstance(raw, dict):
        raise FixtureValidationError(f"{where} must be an object")
    fixture_id = raw.get("id")
    if not isinstance(fixture_id, str) or not fixture_id.strip():
        raise FixtureValidationError(f"{where}.id must be non-empty text")
    hostname = raw.get("hostname", "target.example")
    if not isinstance(hostname, str) or not hostname.strip():
        raise FixtureValidationError(f"{fixture_id}.hostname must be non-empty text")
    scan_a = _observation_list(raw.get("scan_a"), f"{fixture_id}.scan_a", required=True)
    scan_b = _observation_list(raw.get("scan_b"), f"{fixture_id}.scan_b", required=False)
    history = raw.get("history", {})
    if not isinstance(history, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in history.items()
    ):
        raise FixtureValidationError(f"{fixture_id}.history must map text to text")
    technologies = raw.get("technologies", [])
    if not isinstance(technologies, list) or any(not isinstance(t, str) for t in technologies):
        raise FixtureValidationError(f"{fixture_id}.technologies must be a list of text")
    remediation = raw.get("remediation", {})
    if not isinstance(remediation, dict) or any(
        not isinstance(k, str) or v not in STATUSES for k, v in remediation.items()
    ):
        raise FixtureValidationError(
            f"{fixture_id}.remediation must map obs id to {sorted(STATUSES)}"
        )
    ground_truth = raw.get("ground_truth")
    if not isinstance(ground_truth, dict):
        raise FixtureValidationError(f"{fixture_id}.ground_truth must be an object")
    canonical = ground_truth.get("canonical")
    if not isinstance(canonical, list) or not canonical:
        raise FixtureValidationError(f"{fixture_id}.ground_truth.canonical must be non-empty")
    for entry in canonical:
        _canonical_entry(entry, fixture_id)
    compliance = ground_truth.get("compliance", {})
    if not isinstance(compliance, dict) or any(
        not isinstance(k, str) or not isinstance(v, list) for k, v in compliance.items()
    ):
        raise FixtureValidationError(
            f"{fixture_id}.ground_truth.compliance must map framework to control list"
        )
    return {
        "id": fixture_id,
        "title": str(raw.get("title", "")),
        "hostname": hostname,
        "scan_a": scan_a,
        "scan_b": scan_b,
        "history": dict(history),
        "technologies": list(technologies),
        "remediation": dict(remediation),
        "ground_truth": {
            "canonical": [dict(e) for e in canonical],
            "compliance": {k: list(v) for k, v in compliance.items()},
        },
    }


def _observation_list(raw: object, where: str, *, required: bool) -> list[dict[str, Any]]:
    if raw is None:
        if required:
            raise FixtureValidationError(f"{where} is required")
        return []
    if not isinstance(raw, list) or (required and not raw):
        raise FixtureValidationError(f"{where} must be a non-empty list")
    seen: set[str] = set()
    cleaned: list[dict[str, Any]] = []
    for obs in raw:
        if not isinstance(obs, dict):
            raise FixtureValidationError(f"{where} entries must be objects")
        for field_name in _REQUIRED_OBS_FIELDS:
            if not isinstance(obs.get(field_name), str) or not str(obs[field_name]).strip():
                raise FixtureValidationError(f"{where} entry missing text field {field_name!r}")
        obs_id = str(obs["obs_id"])
        if obs_id in seen:
            raise FixtureValidationError(f"{where} duplicate obs_id: {obs_id!r}")
        seen.add(obs_id)
        severity = str(obs["severity"]).strip().upper()
        if severity not in SEVERITIES:
            raise FixtureValidationError(f"{where} entry {obs_id!r} bad severity: {severity!r}")
        entry: dict[str, Any] = {k: obs.get(k) for k in _REQUIRED_OBS_FIELDS}
        entry["obs_id"] = obs_id
        entry["severity"] = severity
        entry["evidence"] = str(obs.get("evidence", ""))
        entry["location"] = str(obs.get("location", ""))
        for optional in ("cve_id", "affected_technology"):
            if obs.get(optional) is not None:
                if not isinstance(obs[optional], str):
                    raise FixtureValidationError(f"{where} entry {obs_id!r} bad {optional!r}")
                entry[optional] = obs[optional]
        if obs.get("cvss_score") is not None:
            if not isinstance(obs["cvss_score"], (int, float)) or isinstance(
                obs["cvss_score"], bool
            ):
                raise FixtureValidationError(f"{where} entry {obs_id!r} bad cvss_score")
            entry["cvss_score"] = obs["cvss_score"]
        cleaned.append(entry)
    return cleaned


def _canonical_entry(entry: object, fixture_id: str) -> None:
    where = f"{fixture_id}.ground_truth.canonical entry"
    if not isinstance(entry, dict):
        raise FixtureValidationError(f"{where} must be an object")
    for field_name in _REQUIRED_CANONICAL_FIELDS:
        if entry.get(field_name) is None:
            raise FixtureValidationError(f"{where} missing {field_name!r}")
    if not isinstance(entry["key"], str) or not entry["key"]:
        raise FixtureValidationError(f"{where} key must be non-empty text")
    if (
        not isinstance(entry["members"], list)
        or not entry["members"]
        or any(not isinstance(m, str) for m in entry["members"])
    ):
        raise FixtureValidationError(f"{where} members must be a non-empty text list")
    if str(entry["severity"]).upper() not in SEVERITIES:
        raise FixtureValidationError(f"{where} bad severity")
    if entry["lifecycle"] not in LIFECYCLES:
        raise FixtureValidationError(f"{where} bad lifecycle")
    if "priority_level" in entry and not isinstance(entry["priority_level"], str):
        raise FixtureValidationError(f"{where} bad priority_level")


def check_ground_truth_consistency(fixture: dict[str, Any]) -> list[str]:
    """Cross-check ground truth against fixture observations (pure).

    Returns human-readable inconsistency strings (empty = consistent):
    every member must exist, every observation should belong to exactly
    one canonical group, remediation/history keys must resolve.
    """
    problems: list[str] = []
    obs_ids = {o["obs_id"] for o in fixture["scan_a"]} | {o["obs_id"] for o in fixture["scan_b"]}
    claimed: list[str] = []
    for entry in fixture["ground_truth"]["canonical"]:
        for member in entry["members"]:
            if member not in obs_ids:
                problems.append(f"member {member!r} is not an observation")
            claimed.append(member)
    uncovered = sorted(obs_ids - set(claimed))
    if uncovered:
        problems.append(f"observations without canonical cover: {uncovered}")
    duplicates = sorted({m for m in claimed if claimed.count(m) > 1})
    if duplicates:
        problems.append(f"observations claimed twice: {duplicates}")
    for key in list(fixture["history"]) + list(fixture["remediation"]):
        if key not in obs_ids:
            problems.append(f"history/remediation key without observation: {key!r}")
    return problems


__all__ = [
    "DATASET_VERSION",
    "FixtureValidationError",
    "LIFECYCLES",
    "SEVERITIES",
    "STATUSES",
    "check_ground_truth_consistency",
    "validate_dataset",
    "validate_fixture",
]
