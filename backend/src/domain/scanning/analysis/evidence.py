"""Immutable, canonical evidence set built from Phase 5 results (ADR-0008).

Guarantees:

* Constructed once from an :class:`~src.scanning.engines.http_analysis.
  HttpAnalysisResult` (or equivalent parts); no mutation path exists.
* Deterministic subset only: wall-clock timing (``elapsed_ms``) is
  deliberately EXCLUDED so identical scan outputs always yield identical
  evidence, IDs, and prompt payloads.
* Canonical serialization uses the shared stable JSON writer; the
  ``evidence_set_id`` is SHA-256 over that canonical form (first 16 hex).
* O(1) lookup by finding ID for the validator.

AI output can never alter this object: nothing in the API accepts or
returns mutable references into it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from src.domain.scanning.findings import dumps_stable

if TYPE_CHECKING:
    from collections.abc import Mapping

    from src.domain.scanning.findings import Finding, Observation
    from src.scanning.engines.http_analysis import HttpAnalysisResult

EVIDENCE_SCHEMA_VERSION = "sgpt.evidence.v1"


@dataclass(frozen=True)
class EvidenceSet:
    """Frozen evidence derived from one deterministic analysis result."""

    schema_version: str
    evidence_set_id: str
    engine_name: str
    engine_version: str
    target_hostname: str
    request_scheme: str
    request_port: int
    request_path: str
    status: int | None
    redirect_count: int
    truncated: bool
    content_type: str
    response_bytes: int | None
    error_kind: str | None
    error_detail: str
    observations: tuple[Observation, ...]
    findings: tuple[Finding, ...]
    _finding_index: Mapping[str, Finding]

    @staticmethod
    def _derive_id(canonical_without_id: dict[str, Any]) -> str:
        return hashlib.sha256(dumps_stable(canonical_without_id).encode("utf-8")).hexdigest()[:16]

    @classmethod
    def from_result(cls, result: HttpAnalysisResult) -> EvidenceSet:
        """Build the immutable set from a deterministic engine result."""
        findings = tuple(sorted(result.findings, key=lambda f: f.id))
        observations = tuple(sorted(result.observations, key=lambda o: o.id))
        canonical = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "engine": {
                "name": result.engine_name,
                "version": result.engine_version,
            },
            "target_hostname": result.target_hostname,
            "request": {
                "scheme": result.request_scheme,
                "port": result.request_port,
                "path": result.request_path,
                "status": result.status,
                "redirect_count": result.redirect_count,
                "truncated": result.truncated,
                "content_type": result.content_type,
                "response_bytes": result.response_bytes,
                "error_kind": result.error_kind,
                "error_detail": result.error_detail,
            },
            "observations": [o.to_dict() for o in observations],
            "findings": [f.to_dict() for f in findings],
        }
        evidence_id = cls._derive_id(canonical)
        index = {finding.id: finding for finding in findings}
        instance = cls(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            evidence_set_id=evidence_id,
            engine_name=result.engine_name,
            engine_version=result.engine_version,
            target_hostname=result.target_hostname,
            request_scheme=result.request_scheme,
            request_port=result.request_port,
            request_path=result.request_path,
            status=result.status,
            redirect_count=result.redirect_count,
            truncated=result.truncated,
            content_type=result.content_type,
            response_bytes=result.response_bytes,
            error_kind=result.error_kind,
            error_detail=result.error_detail,
            observations=observations,
            findings=findings,
            _finding_index=MappingProxyType(index),
        )
        return instance

    # ------------------------------------------------------------------ #
    # Accessors                                                          #
    # ------------------------------------------------------------------ #

    def get_finding(self, finding_id: str) -> Finding | None:
        """O(1) lookup used by the response validator."""
        return self._finding_index.get(finding_id)

    def has_finding(self, finding_id: str) -> bool:
        return finding_id in self._finding_index

    @property
    def finding_ids(self) -> tuple[str, ...]:
        return tuple(self._finding_index)

    # ------------------------------------------------------------------ #
    # Canonical serialization                                            #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "evidence_set_id": self.evidence_set_id,
            "engine": {"name": self.engine_name, "version": self.engine_version},
            "target_hostname": self.target_hostname,
            "request": {
                "scheme": self.request_scheme,
                "port": self.request_port,
                "path": self.request_path,
                "status": self.status,
                "redirect_count": self.redirect_count,
                "truncated": self.truncated,
                "content_type": self.content_type,
                "response_bytes": self.response_bytes,
                "error_kind": self.error_kind,
                "error_detail": self.error_detail,
            },
            "observations": [o.to_dict() for o in self.observations],
            "findings": [f.to_dict() for f in self.findings],
        }

    def serialize(self) -> str:
        """Stable JSON representation — byte-identical for equal sets."""
        return dumps_stable(self.to_dict())
