"""Comparison response validator: the AI/evidence integrity boundary.

Fail-closed rules (mirroring the scan-analysis validator):

* Oversized, non-JSON, or schema-invalid responses are rejected outright.
* Every ``finding_ids`` / ``fingerprints`` reference is checked against
  the comparison evidence registries. Unknown references never become
  supported: the referencing entry is forced to UNSUPPORTED and counted;
  entries left without any valid reference are dropped (recorded as
  unsupported claims).
* ``priority_changes`` from/to levels are verified against the
  deterministic record snapshots. A mismatch is dropped and counted —
  the AI can never restate a level the evidence disagrees with.
* The validator NEVER mutates the evidence and never invents IDs. The
  output schema contains no severity/lifecycle/priority write path, so
  canonical truth cannot be altered by construction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.domain.scanning.analysis.comparison_models import (
    AnalysisFailureKind,
    ComparisonAction,
    ComparisonAssessment,
    ComparisonClaim,
    EvidenceStatus,
    PriorityChange,
    RegressionInsight,
    ResolvedItem,
)
from src.domain.scanning.analysis.models import Claim, ProviderMetadata
from src.domain.scanning.findings import bound_evidence, dumps_stable

if TYPE_CHECKING:
    from datetime import datetime

    from src.domain.scanning.analysis.comparison_evidence import ComparisonEvidence

MAX_OUTPUT_JSON_BYTES = 262_144
_MAX_SUMMARY_CHARS = 2_000
_MAX_TECHNICAL_CHARS = 4_000
_MAX_TEXT_CHARS = 1_000
_STATUS_VALUES = {s.value for s in EvidenceStatus}


@dataclass(frozen=True)
class ComparisonValidationResult:
    """Outcome of validating one raw provider comparison response."""

    accepted: bool
    assessment: ComparisonAssessment | None
    failure_kind: AnalysisFailureKind | None
    errors: tuple[str, ...] = field(default=())
    unsupported_claims: tuple[Claim, ...] = field(default=())


def validate_comparison_response(
    raw: str | bytes | dict[str, Any],
    evidence: ComparisonEvidence,
    *,
    provider_metadata_base: dict[str, str],
    now: datetime,
) -> ComparisonValidationResult:
    """Validate and convert a provider response into a ComparisonAssessment."""
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

    return _validate_structure(parsed, evidence, provider_metadata_base, now)


def _reject(kind: AnalysisFailureKind, detail: str) -> ComparisonValidationResult:
    return ComparisonValidationResult(
        accepted=False, assessment=None, failure_kind=kind, errors=(detail,)
    )


def _known_refs(
    ids_raw: Any,
    fps_raw: Any,
    evidence: ComparisonEvidence,
    *,
    context: str,
    unsupported: list[Claim],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split references into known IDs/fingerprints; count unknown ones."""
    id_list = [i for i in ids_raw if isinstance(i, str)] if isinstance(ids_raw, list) else []
    fp_list = [f for f in fps_raw if isinstance(f, str)] if isinstance(fps_raw, list) else []
    known_ids = sorted({i for i in id_list if i in evidence.finding_ids})
    known_fps = sorted({f for f in fp_list if f in evidence.fingerprints})
    for unknown in sorted(set(id_list) - set(known_ids)):
        unsupported.append(
            Claim(
                text=f"{context} references unknown finding",
                finding_ids=(unknown,),
                status=EvidenceStatus.UNSUPPORTED,
                detail="ID absent from comparison evidence",
            )
        )
    for unknown in sorted(set(fp_list) - set(known_fps)):
        unsupported.append(
            Claim(
                text=f"{context} references unknown fingerprint",
                finding_ids=(),
                status=EvidenceStatus.UNSUPPORTED,
                detail=f"fingerprint absent from comparison evidence: {unknown[:32]}",
            )
        )
    return tuple(known_ids), tuple(known_fps)


def _validate_structure(
    payload: dict[str, Any],
    evidence: ComparisonEvidence,
    metadata_base: dict[str, str],
    now: datetime,
) -> ComparisonValidationResult:
    errors: list[str] = []
    unsupported: list[Claim] = []

    executive_summary = _required_text(
        payload.get("executive_summary"), "executive_summary", _MAX_SUMMARY_CHARS, errors
    )
    technical_summary = _required_text(
        payload.get("technical_summary"), "technical_summary", _MAX_TECHNICAL_CHARS, errors
    )
    limitations = _string_list(payload.get("limitations", []), "limitations", errors)

    records = {str(r.get("fingerprint")): r for r in evidence.records}

    key_changes = _validate_claims(
        payload.get("key_changes", []), "key_changes", evidence, unsupported, errors
    )
    citations = _validate_claims(
        payload.get("citations", []), "citations", evidence, unsupported, errors
    )
    priority_changes = _validate_priority_changes(
        payload.get("priority_changes", []), records, unsupported, errors
    )
    regressions = _validate_anchored(
        payload.get("regressions", []),
        "regressions",
        ("finding_id", "fingerprint", "previous_state", "current_state", "why_matters"),
        records,
        unsupported,
        errors,
        RegressionInsight,
    )
    resolved_items = _validate_anchored(
        payload.get("resolved_items", []),
        "resolved_items",
        ("finding_id", "fingerprint", "note"),
        records,
        unsupported,
        errors,
        ResolvedItem,
    )
    recommended_actions = _validate_actions(
        payload.get("recommended_actions", []), evidence, unsupported, errors
    )

    if errors:
        return ComparisonValidationResult(
            accepted=False,
            assessment=None,
            failure_kind=AnalysisFailureKind.SCHEMA_INVALID,
            errors=tuple(errors),
            unsupported_claims=tuple(unsupported),
        )
    assert executive_summary is not None and technical_summary is not None  # narrowed above

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
            "executive_summary": executive_summary,
            "technical_summary": technical_summary,
            "key_changes": [c.to_dict() for c in key_changes],
            "priority_changes": [p.to_dict() for p in priority_changes],
            "regressions": [r.to_dict() for r in regressions],
            "resolved_items": [r.to_dict() for r in resolved_items],
            "recommended_actions": [a.to_dict() for a in recommended_actions],
            "limitations": limitations,
            "citations": [c.to_dict() for c in citations],
        }
    )
    assessment = ComparisonAssessment(
        assessment_id=ComparisonAssessment.derive_assessment_id(
            evidence.comparison_evidence_id,
            metadata.provider,
            metadata.model,
            metadata.prompt_schema_version,
            metadata.output_schema_version,
            body_canonical,
        ),
        comparison_evidence_id=evidence.comparison_evidence_id,
        executive_summary=executive_summary,
        technical_summary=technical_summary,
        key_changes=tuple(key_changes),
        priority_changes=tuple(priority_changes),
        regressions=tuple(regressions),
        resolved_items=tuple(resolved_items),
        recommended_actions=tuple(recommended_actions),
        limitations=tuple(limitations),
        citations=tuple(citations),
        unsupported_claim_count=len(unsupported),
        provider_metadata=metadata,
    )
    return ComparisonValidationResult(
        accepted=True,
        assessment=assessment,
        failure_kind=None,
        errors=(),
        unsupported_claims=tuple(unsupported),
    )


def _required_text(value: Any, name: str, cap: int, errors: list[str]) -> str | None:
    if isinstance(value, str) and value.strip():
        if len(value) > cap:
            errors.append(f"{name} exceeds length cap")
            return None
        return value
    errors.append(f"{name} must be a non-empty string")
    return None


def _string_list(raw: Any, name: str, errors: list[str]) -> list[str]:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        errors.append(f"{name} must be a list of strings")
        return []
    return [_safe_str(x) for x in raw]


def _validate_claims(
    raw: Any,
    name: str,
    evidence: ComparisonEvidence,
    unsupported: list[Claim],
    errors: list[str],
) -> list[ComparisonClaim]:
    if not isinstance(raw, list):
        errors.append(f"{name} must be a list")
        return []
    validated: list[ComparisonClaim] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            errors.append(f"{name}[{index}] is not an object")
            continue
        text = item.get("text")
        if not isinstance(text, str) or not text.strip():
            errors.append(f"{name}[{index}].text invalid")
            continue
        known_ids, known_fps = _known_refs(
            item.get("finding_ids", []),
            item.get("fingerprints", []),
            evidence,
            context=f"{name}[{index}]",
            unsupported=unsupported,
        )
        if not known_ids and not known_fps:
            continue
        declared = item.get("status")
        if isinstance(declared, str) and declared in _STATUS_VALUES:
            status = EvidenceStatus(declared)
        else:
            status = EvidenceStatus.SUPPORTED
        validated.append(
            ComparisonClaim(
                text=_safe_str(text),
                finding_ids=known_ids,
                fingerprints=known_fps,
                status=status,
            )
        )
    return validated


def _validate_priority_changes(
    raw: Any,
    records: dict[str, Any],
    unsupported: list[Claim],
    errors: list[str],
) -> list[PriorityChange]:
    if not isinstance(raw, list):
        errors.append("priority_changes must be a list")
        return []
    validated: list[PriorityChange] = []
    for index, item in enumerate(raw):
        ctx = f"priority_changes[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{ctx} is not an object")
            continue
        finding_id = item.get("finding_id")
        fingerprint = item.get("fingerprint")
        from_level = item.get("from_level")
        to_level = item.get("to_level")
        reason = item.get("reason", "")
        if not isinstance(finding_id, str) or not finding_id:
            errors.append(f"{ctx}.finding_id invalid")
            continue
        if not isinstance(fingerprint, str) or not fingerprint:
            errors.append(f"{ctx}.fingerprint invalid")
            continue
        record = records.get(fingerprint)
        record_ids = set()
        if isinstance(record, dict):
            for key in ("id", "previous_finding_id"):
                value = record.get(key)
                if isinstance(value, str) and value:
                    record_ids.add(value)
        previous = record.get("previous_priority") if isinstance(record, dict) else None
        current = record.get("priority") if isinstance(record, dict) else None
        expected_from = previous.get("level") if isinstance(previous, dict) else None
        expected_to = current.get("level") if isinstance(current, dict) else None
        if (
            record is None
            or finding_id not in record_ids
            or from_level != expected_from
            or to_level != expected_to
        ):
            # Restated levels must equal the deterministic snapshots:
            # anything else is dropped and counted, never laundered.
            unsupported.append(
                Claim(
                    text=f"{ctx} disagrees with deterministic priority",
                    finding_ids=(finding_id,),
                    status=EvidenceStatus.UNSUPPORTED,
                    detail="from/to levels do not match record snapshots",
                )
            )
            continue
        validated.append(
            PriorityChange(
                finding_id=finding_id,
                fingerprint=fingerprint,
                from_level=str(from_level),
                to_level=str(to_level),
                reason=_safe_str(reason),
            )
        )
    return validated


def _validate_anchored(
    raw: Any,
    name: str,
    fields: tuple[str, ...],
    records: dict[str, Any],
    unsupported: list[Claim],
    errors: list[str],
    factory: Any,
) -> list[Any]:
    """Entries anchored to one co-occurring (finding, fingerprint) pair."""
    if not isinstance(raw, list):
        errors.append(f"{name} must be a list")
        return []
    validated: list[Any] = []
    for index, item in enumerate(raw):
        ctx = f"{name}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{ctx} is not an object")
            continue
        finding_id = item.get("finding_id")
        fingerprint = item.get("fingerprint")
        if not isinstance(finding_id, str) or not finding_id:
            errors.append(f"{ctx}.finding_id invalid")
            continue
        if not isinstance(fingerprint, str) or not fingerprint:
            errors.append(f"{ctx}.fingerprint invalid")
            continue
        record = records.get(fingerprint)
        record_ids = set()
        if isinstance(record, dict):
            for key in ("id", "previous_finding_id"):
                value = record.get(key)
                if isinstance(value, str) and value:
                    record_ids.add(value)
        if record is None or finding_id not in record_ids:
            unsupported.append(
                Claim(
                    text=f"{ctx} references unknown comparison record",
                    finding_ids=(finding_id,),
                    status=EvidenceStatus.UNSUPPORTED,
                    detail="finding/fingerprint pair absent from evidence",
                )
            )
            continue
        kwargs = {
            "finding_id": finding_id,
            "fingerprint": fingerprint,
        }
        for slot in fields[2:]:
            value = item.get(slot, "")
            kwargs[slot] = _safe_str(value)
        validated.append(factory(**kwargs))
    return validated


def _validate_actions(
    raw: Any,
    evidence: ComparisonEvidence,
    unsupported: list[Claim],
    errors: list[str],
) -> list[ComparisonAction]:
    if not isinstance(raw, list):
        errors.append("recommended_actions must be a list")
        return []
    validated: list[ComparisonAction] = []
    for index, item in enumerate(raw):
        ctx = f"recommended_actions[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{ctx} is not an object")
            continue
        title = item.get("title")
        if not isinstance(title, str) or not title.strip():
            errors.append(f"{ctx}.title invalid")
            continue
        ids_raw = item.get("finding_ids", [])
        id_list = [i for i in ids_raw if isinstance(i, str)] if isinstance(ids_raw, list) else []
        known_ids = sorted({i for i in id_list if i in evidence.finding_ids})
        for unknown in sorted(set(id_list) - set(known_ids)):
            unsupported.append(
                Claim(
                    text=f"{ctx} references unknown finding",
                    finding_ids=(unknown,),
                    status=EvidenceStatus.UNSUPPORTED,
                    detail="ID absent from comparison evidence",
                )
            )
        validated.append(
            ComparisonAction(
                title=_safe_str(title),
                detail=_safe_str(item.get("detail", "")),
                finding_ids=tuple(known_ids),
                verification=_safe_str(item.get("verification", ""))[:_MAX_TEXT_CHARS],
            )
        )
    return validated


def _safe_str(value: Any) -> str:
    return bound_evidence(value if isinstance(value, str) else str(value))
