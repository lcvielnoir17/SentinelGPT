"""Deterministic candidate correlation over an evidence set (ADR-0008).

Rule-seeded clusters give the AI a traceable starting point AND give the
pipeline an offline, fully deterministic grouping baseline. Every group's
finding IDs come verbatim from the evidence set — nothing is invented.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.domain.scanning.analysis.evidence import EvidenceSet

_CATEGORIES = (
    ("http.security-headers", "Missing security-header family"),
    ("http.cookies", "Cookie hygiene cluster"),
    ("http.transport", "Transport / TLS posture"),
    ("http.server-info", "Server-information disclosure"),
)


@dataclass(frozen=True)
class CandidateGroup:
    """Deterministic pre-AI cluster of finding IDs."""

    group_id: str
    category: str
    title: str
    finding_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "group_id": self.group_id,
            "category": self.category,
            "title": self.title,
            "finding_ids": list(self.finding_ids),
        }


def build_candidate_groups(evidence_set: EvidenceSet) -> tuple[CandidateGroup, ...]:
    """Cluster findings by Phase 5 category. Deterministic and offline."""
    by_category: dict[str, list[str]] = {}
    for finding in evidence_set.findings:
        by_category.setdefault(finding.category, []).append(finding.id)

    groups: list[CandidateGroup] = []
    for category, title in _CATEGORIES:
        ids = sorted(by_category.get(category, ()))
        if not ids:
            continue
        identity = f"candidate|{category}|{'|'.join(ids)}"
        group_id = hashlib_sha16(identity)
        groups.append(
            CandidateGroup(
                group_id=group_id, category=category, title=title, finding_ids=tuple(ids)
            )
        )
    # Deterministic ordering independent of rule-table order.
    groups.sort(key=lambda g: g.group_id)

    # Any Phase 5 category outside the known table still gets a catch-all
    # cluster so no finding is invisible to the AI layer.
    known = {category for category, _title in _CATEGORIES}
    extras = sorted(set(by_category) - known)
    for category in extras:
        ids = sorted(by_category[category])
        group_id = hashlib_sha16(f"candidate|{category}|{'|'.join(ids)}")
        groups.append(
            CandidateGroup(
                group_id=group_id,
                category=category,
                title=f"{category} cluster",
                finding_ids=tuple(ids),
            )
        )
    groups.sort(key=lambda g: g.group_id)
    return tuple(groups)


def hashlib_sha16(identity: str) -> str:
    import hashlib

    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
