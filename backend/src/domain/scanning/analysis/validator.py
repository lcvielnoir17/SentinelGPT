"""Response validator: the AI/evidence integrity boundary (ADR-0008).

Fail-closed rules:

* Oversized, non-JSON, or schema-invalid responses are rejected outright.
* Every ``finding_ids`` reference is checked against the evidence set.
  Unknown IDs never become supported evidence: the referencing claim is
  forced to UNSUPPORTED and counted; groups left without any valid ID are
  dropped (recorded as unsupported claims).
* The validator NEVER mutates the EvidenceSet and never invents IDs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.domain.scanning.analysis.models import (
    AnalysisFailureKind,
    Assessment,
    Claim,
    CorrelatedGroup,
    EvidenceStatus,
    ProviderMetadata,
    RemediationItem,
)
from src.domain.scanning.findings import Severity, bound_evidence, dumps_stable

if TYPE_CHECKING:
    from datetime import datetime

    from src.domain.scanning.analysis.evidence import EvidenceSet

MAX_OUTPUT_JSON_BYTES = 262_144
_MAX_SUMMARY_CHARS = 4_000
_MAX_TEXT_CHARS = 1_000
_VALID_PRIORITIES = {s.value for s in Severity}
_STATUS_VALUES = {s.value for s in EvidenceStatus}


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating one raw provider response."""

    accepted: bool
    assessment: Assessment | None
    failure_kind: AnalysisFailureKind | None
    errors: tuple[str, ...] = field(default=())
    unsupported_claims: tuple[Claim, ...] = field(default=())


def validate_analysis_response(
    raw: str | bytes | dict[str, Any],
    evidence_set: EvidenceSet,
    *,
    provider_metadata_base: dict[str, str],
    now: datetime,
) -> ValidationResult:
    """Validate and convert a provider response into an Assessment.

    ``provider_metadata_base`` supplies provider/model/model_version; schema
    versions are filled from the prompt module constants; ``created_at`` is
    injected by the caller's clock.
    """
    if isinstance(raw, bytes):
        if len(raw) > MAX_OUTPUT_JSON_BYTES:
            return _reject(AnalysisFailureKind.LIMIT_EXCEEDED, "response exceeds size cap")
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_OUTPUT_JSON_BYTES:
            return _reject(AnalysisFailureKind.LIMIT_EXCEEDED, "response exceeds size cap")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            return _reject(
                AnalysisFailureKind.MALFORMED_RESPONSE,
                f"invalid JSON: {exc.msg}",
            )
    else:
        parsed = raw

    if not isinstance(parsed, dict):
        return _reject(AnalysisFailureKind.MALFORMED_RESPONSE, "payload is not a JSON object")

    return _validate_structure(parsed, evidence_set, provider_metadata_base, now)


def _reject(kind: AnalysisFailureKind, detail: str) -> ValidationResult:
    return ValidationResult(accepted=False, assessment=None, failure_kind=kind, errors=(detail,))


def _validate_structure(
    payload: dict[str, Any],
    evidence_set: EvidenceSet,
    metadata_base: dict[str, str],
    now: datetime,
) -> ValidationResult:
    errors: list[str] = []
    unsupported: list[Claim] = []

    overall_summary: str | None = None
    summary_value = payload.get("overall_summary")
    if isinstance(summary_value, str) and summary_value.strip():
        if len(summary_value) > _MAX_SUMMARY_CHARS:
            errors.append("overall_summary exceeds length cap")
        else:
            overall_summary = summary_value
    else:
        errors.append("overall_summary must be a non-empty string")

    priority_raw: str | None = None
    priority_value = payload.get("priority")
    if isinstance(priority_value, str) and priority_value in _VALID_PRIORITIES:
        priority_raw = priority_value
    else:
        errors.append(f"priority must be one of {sorted(_VALID_PRIORITIES)}")

    limitations_raw = payload.get("limitations", [])
    limitations = _string_list(limitations_raw, "limitations", errors)

    # ---- correlated groups ------------------------------------------- #
    groups_raw = payload.get("correlated_groups", [])
    if not isinstance(groups_raw, list):
        errors.append("correlated_groups must be a list")
        groups_raw = []
    validated_groups: list[CorrelatedGroup] = []
    for index, group in enumerate(groups_raw):
        if not isinstance(group, dict):
            errors.append(f"correlated_groups[{index}] is not an object")
            continue
        title = group.get("title")
        rationale = group.get("rationale", "")
        ids_raw = group.get("finding_ids", [])
        if not isinstance(title, str) or not title.strip():
            errors.append(f"correlated_groups[{index}].title invalid")
            continue
        if not isinstance(ids_raw, list) or not all(isinstance(i, str) for i in ids_raw):
            errors.append(f"correlated_groups[{index}].finding_ids invalid")
            continue
        group_known_ids = tuple(sorted({i for i in ids_raw if evidence_set.has_finding(i)}))
        unknown_ids = [i for i in ids_raw if not evidence_set.has_finding(i)]
        for unknown in unknown_ids:
            unsupported.append(
                Claim(
                    text=f"Group '{title}' references unknown finding",
                    finding_ids=(unknown,),
                    status=EvidenceStatus.UNSUPPORTED,
                    detail="ID absent from evidence set",
                )
            )
        if not group_known_ids:
            # Per-ID unsupported claims above already document this group;
            # the group itself is dropped so empty clusters never surface.
            continue
        validated_groups.append(
            CorrelatedGroup(
                group_id=CorrelatedGroup.derive_group_id(title, group_known_ids),
                title=title,
                finding_ids=group_known_ids,
                rationale=_safe_str(rationale),
            )
        )

    # ---- remediation --------------------------------------------------- #
    remediation_raw = payload.get("remediation", [])
    if not isinstance(remediation_raw, list):
        errors.append("remediation must be a list")
        remediation_raw = []
    remediation: list[RemediationItem] = []
    for index, item in enumerate(remediation_raw):
        if not isinstance(item, dict):
            errors.append(f"remediation[{index}] is not an object")
            continue
        title = item.get("title")
        detail = item.get("detail", "")
        ids_raw = item.get("finding_ids", [])
        if not isinstance(title, str) or not title.strip():
            errors.append(f"remediation[{index}].title invalid")
            continue
        known_ids: tuple[str, ...] = ()
        if isinstance(ids_raw, list):
            known_ids = tuple(
                sorted({i for i in ids_raw if isinstance(i, str) and evidence_set.has_finding(i)})
            )
        remediation.append(
            RemediationItem(title=title, detail=_safe_str(detail), finding_ids=known_ids)
        )

    # ---- claims ---------------------------------------------------------- #
    claims_raw = payload.get("claims", [])
    if not isinstance(claims_raw, list):
        errors.append("claims must be a list")
        claims_raw = []
    claims: list[Claim] = []
    for index, claim in enumerate(claims_raw):
        if not isinstance(claim, dict):
            errors.append(f"claims[{index}] is not an object")
            continue
        text = claim.get("text")
        ids_raw = claim.get("finding_ids", [])
        if not isinstance(text, str) or not text.strip():
            errors.append(f"claims[{index}].text invalid")
            continue
        id_list = [i for i in ids_raw if isinstance(i, str)] if isinstance(ids_raw, list) else []
        known = [i for i in id_list if evidence_set.has_finding(i)]
        unknown = [i for i in id_list if i not in known]
        for unknown_id in unknown:
            unsupported.append(
                Claim(
                    text=text[:200],
                    finding_ids=(unknown_id,),
                    status=EvidenceStatus.UNSUPPORTED,
                    detail="referenced finding does not exist",
                )
            )
        declared_status = claim.get("status")
        if unknown:
            # Unknown references ALWAYS win: a claim citing evidence that
            # does not exist can never be supported or merely inferred.
            status = EvidenceStatus.UNSUPPORTED
        elif isinstance(declared_status, str) and declared_status in _STATUS_VALUES:
            status = EvidenceStatus(declared_status)
        elif not id_list:
            status = EvidenceStatus.UNSUPPORTED
        elif len(known) == len(id_list):
            status = EvidenceStatus.SUPPORTED
        else:
            status = EvidenceStatus.INFERRED
        claims.append(
            Claim(text=_safe_str(text), finding_ids=tuple(sorted(set(id_list))), status=status)
        )

    if errors:
        return ValidationResult(
            accepted=False,
            assessment=None,
            failure_kind=AnalysisFailureKind.SCHEMA_INVALID,
            errors=tuple(errors),
            unsupported_claims=tuple(unsupported),
        )
    assert overall_summary is not None and priority_raw is not None  # narrowed above

    metadata = ProviderMetadata(
        provider=metadata_base.get("provider", "unknown"),
        model=metadata_base.get("model", "unknown"),
        model_version=metadata_base.get("model_version", "unknown"),
        prompt_schema_version=metadata_base.get("prompt_schema_version", "v1"),
        output_schema_version=metadata_base.get("output_schema_version", "v1"),
        created_at=now,
        nondeterministic=True,
    )

    body_canonical = dumps_stable(
        {
            "summary": overall_summary,
            "priority": priority_raw,
            "groups": [g.to_dict() for g in validated_groups],
            "remediation": [r.to_dict() for r in remediation],
            "limitations": limitations,
            "claims": [c.to_dict() for c in claims],
        }
    )
    assessment_id = Assessment.derive_assessment_id(
        evidence_set.evidence_set_id,
        metadata.provider,
        metadata.model,
        metadata.prompt_schema_version,
        metadata.output_schema_version,
        body_canonical,
    )
    assessment = Assessment(
        assessment_id=assessment_id,
        evidence_set_id=evidence_set.evidence_set_id,
        overall_summary=overall_summary,
        priority=Severity(priority_raw),
        correlated_groups=tuple(validated_groups),
        remediation=tuple(remediation),
        limitations=tuple(_safe_str(x) for x in limitations),
        claims=tuple(claims),
        unsupported_claim_count=len(unsupported),
        provider_metadata=metadata,
    )
    return ValidationResult(
        accepted=True,
        assessment=assessment,
        failure_kind=None,
        errors=(),
        unsupported_claims=tuple(unsupported),
    )


def _safe_str(value: Any) -> str:
    return bound_evidence(value if isinstance(value, str) else str(value))


def _string_list(raw: Any, name: str, errors: list[str]) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        errors.append(f"{name} must be a list of strings")
        return []
    return [_safe_str(x) for x in raw]
