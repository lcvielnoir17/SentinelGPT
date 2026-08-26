"""Structured observation/finding model for scan engines (ADR-0007).

Layering contract for SentinelGPT's future AI analysis:

    HTTP observation  (raw, bounded fact)
        ↓ security assessment (deterministic rule)
    Finding           (severity + confidence + recommendation)

Rules:

* Observations never claim risk; findings always carry an explicit
  severity AND confidence so downstream correlation can weigh them.
* Evidence is BOUNDED and REDACTED: cookie values, authorization/token
  headers, and oversized payloads are never stored.
* Finding IDs are deterministic hashes of their identity fields, stable
  across runs and processes (no UUIDs).
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

MAX_EVIDENCE_CHARS = 512
MAX_COOKIE_NAMES_IN_EVIDENCE = 10


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def bound_evidence(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    """Clamp evidence text and strip control characters."""
    cleaned = "".join(ch if ch.isprintable() or ch in "\t" else " " for ch in text)
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 1] + "…"


def redact_cookie_value(set_cookie_header: str) -> str:
    """Reduce a Set-Cookie header to name + attribute flags.

    The cookie VALUE is dropped unconditionally — session tokens must never
    land in findings or logs.
    """
    parts = set_cookie_header.split(";", 1)
    name_part = parts[0].strip()
    name = name_part.split("=", 1)[0].strip() if "=" in name_part else name_part
    attributes = parts[1] if len(parts) > 1 else ""
    lowered = attributes.lower()
    flags = []
    if "secure" in lowered:
        flags.append("Secure")
    if "httponly" in lowered:
        flags.append("HttpOnly")
    samesite = "unspecified"
    for token in lowered.split(";"):
        token = token.strip()
        if token.startswith("samesite="):
            raw = token.split("=", 1)[1].strip()
            samesite = raw if raw in {"strict", "lax", "none"} else "invalid"
    flags.append(f"SameSite={samesite}")
    return f"{name} [<value-redacted>] ({', '.join(flags)})"


@dataclass(frozen=True)
class Observation:
    """A bounded raw fact gathered from a validated response."""

    id: str
    category: str
    title: str
    detail: str
    evidence: str = ""
    location: str = ""

    @staticmethod
    def make_id(category: str, title: str, location: str = "") -> str:
        identity = f"{category}|{title}|{location}"
        return hashlib.sha256(identity.encode()).hexdigest()[:16]

    @classmethod
    def create(
        cls,
        *,
        category: str,
        title: str,
        detail: str,
        evidence: str = "",
        location: str = "",
    ) -> Observation:
        return cls(
            id=cls.make_id(category, title, location),
            category=category,
            title=title,
            detail=detail,
            evidence=bound_evidence(evidence),
            location=location,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "location": self.location,
        }


@dataclass(frozen=True)
class Finding:
    """An assessed issue derived from one or more observations."""

    id: str
    category: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    evidence: str
    location: str
    recommendation: str
    observation_ids: tuple[str, ...] = field(default=())

    @staticmethod
    def make_id(category: str, title: str, location: str = "") -> str:
        identity = f"finding|{category}|{title}|{location}"
        return hashlib.sha256(identity.encode()).hexdigest()[:16]

    @classmethod
    def create(
        cls,
        *,
        category: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: Confidence,
        evidence: str = "",
        location: str = "",
        recommendation: str = "",
        observation_ids: tuple[str, ...] = (),
    ) -> Finding:
        return cls(
            id=cls.make_id(category, title, location),
            category=category,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            evidence=bound_evidence(evidence),
            location=location,
            recommendation=recommendation,
            observation_ids=tuple(observation_ids),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "location": self.location,
            "recommendation": self.recommendation,
            "observation_ids": list(self.observation_ids),
        }


def dumps_stable(obj: Any) -> str:
    """Deterministic JSON serialization for results (stable key order)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))
