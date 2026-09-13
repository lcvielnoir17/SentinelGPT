"""Deterministic CI policy evaluation (M10, no AI anywhere).

Policy contract (v1, deliberately tiny)::

    {"fail_on_severity": "HIGH", "fail_on_regression": true}

* ``fail_on_severity`` — FAIL when any finding meets or exceeds the
  threshold (INFO < LOW < MEDIUM < HIGH < CRITICAL). Null/absent
  disables the dimension.
* ``fail_on_regression`` — FAIL when any finding lifecycle is
  REGRESSED. Defaults to False.

Outcome states: PASS / FAIL / PENDING / NOT_EVALUATED.

* No policy configured → NOT_EVALUATED (the deterministic result is
  returned without pretending the build passes).
* Scan not terminal → PENDING.
* Scan REJECTED/CANCELLED → FAIL with reason ``scan_failed``
  (fail-closed: a build whose security scan itself failed must not
  pass silently).
* Terminal success → FAIL on threshold/regression breach, else PASS.

A successful HTTP request may legitimately carry ``policy: FAIL`` —
that is a scan success with a policy violation, never a 500.
"""

from __future__ import annotations

from typing import Any

POLICY_VERSION = "sgpt.ci-policy.v1"

PASS = "PASS"
FAIL = "FAIL"
PENDING = "PENDING"
NOT_EVALUATED = "NOT_EVALUATED"

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Scan states whose findings are final enough to judge.
COMPLETED_SCAN_STATUSES = frozenset({"REPORT_READY", "REPORT_READY_DEGRADED"})
# Terminal states where the scan itself failed (fail-closed → FAIL).
FAILED_SCAN_STATUSES = frozenset({"REJECTED", "CANCELLED"})


def parse_policy(raw: object) -> dict[str, Any] | None:
    """Validate a trigger-time policy object (None means 'no policy').

    Unknown keys are rejected — a silently ignored policy dimension
    would be worse than a 400.
    """
    from src.domain.ci.errors import InvalidCiError

    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise InvalidCiError("policy must be an object or null.")
    allowed = {"fail_on_severity", "fail_on_regression"}
    unknown = sorted(k for k in raw if k not in allowed)
    if unknown:
        raise InvalidCiError(f"policy has unknown keys: {unknown}.")
    policy: dict[str, Any] = {}
    threshold = raw.get("fail_on_severity")
    if threshold is not None:
        if not isinstance(threshold, str):
            raise InvalidCiError("policy.fail_on_severity must be text or null.")
        level = threshold.strip().upper()
        if level not in SEVERITY_RANK:
            raise InvalidCiError(f"policy.fail_on_severity must be one of {sorted(SEVERITY_RANK)}.")
        policy["fail_on_severity"] = level
    regress = raw.get("fail_on_regression", False)
    if not isinstance(regress, bool):
        raise InvalidCiError("policy.fail_on_regression must be a boolean.")
    policy["fail_on_regression"] = regress
    return policy


def evaluate_policy(
    *,
    scan_status: str,
    severity_counts: dict[str, int],
    has_regression: bool,
    policy: dict[str, Any] | None,
) -> dict[str, Any]:
    """Deterministic policy outcome for one scan state."""
    if policy is None:
        return {"state": NOT_EVALUATED, "reason": "no policy configured"}
    if scan_status in FAILED_SCAN_STATUSES:
        return {"state": FAIL, "reason": "scan_failed"}
    if scan_status not in COMPLETED_SCAN_STATUSES:
        return {"state": PENDING, "reason": f"scan {scan_status}"}
    threshold = policy.get("fail_on_severity")
    if isinstance(threshold, str) and threshold in SEVERITY_RANK:
        limit = SEVERITY_RANK[threshold]
        worst = max(
            (SEVERITY_RANK.get(str(level).upper(), -1) for level in severity_counts),
            default=-1,
        )
        if worst >= limit:
            return {"state": FAIL, "reason": "severity_threshold"}
    if policy.get("fail_on_regression") is True and has_regression:
        return {"state": FAIL, "reason": "regression_detected"}
    return {"state": PASS, "reason": "within policy"}


__all__ = [
    "COMPLETED_SCAN_STATUSES",
    "FAILED_SCAN_STATUSES",
    "FAIL",
    "NOT_EVALUATED",
    "PASS",
    "PENDING",
    "POLICY_VERSION",
    "SEVERITY_RANK",
    "evaluate_policy",
    "parse_policy",
]
