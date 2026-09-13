"""Target technology persistence and v2 wiring.

Covers the repository upsert/list contract, the worker persist step
(invalid rows skipped, never failing the scan), the assembler v2 bridge
with technology relevance, and time-gated technology signals for
comparison.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from src.domain.scans.priority import PRIORITY_VERSION_V2
from src.reporting.assembler import _priority_for


class _Row:
    """Minimal ORM-row stand-in (attributes assigned post-construction)."""

    def __init__(self, **kwargs: object) -> None:
        self.__dict__.update(kwargs)


class _FakeResult:
    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows

    def scalars(self) -> _FakeResult:
        return self

    def all(self) -> list[_Row]:
        return list(self._rows)

    def first(self) -> _Row | None:
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, rows: list[_Row] | None = None) -> None:
        self.rows: list[_Row] = rows or []
        self.added: list[_Row] = []
        self.flushes = 0

    def add(self, row: _Row) -> None:
        self.added.append(row)
        self.rows.append(row)

    async def execute(self, _stmt: object) -> _FakeResult:
        return _FakeResult(self.rows)

    async def flush(self) -> None:
        self.flushes += 1


def _tech_row(**overrides: object) -> _Row:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "slug": "nginx",
        "display": "nginx",
        "family": "server",
        "version": "1.25",
        "confidence": "HIGH",
        "sources": "header:server",
        "first_observed_at": datetime(2026, 1, 1, tzinfo=UTC),
        "last_observed_at": datetime(2026, 1, 1, tzinfo=UTC),
        "observed_in_scan_id": None,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    base.update(overrides)
    return _Row(**base)


# --------------------------------------------------------------------------- #
# Repository                                                                  #
# --------------------------------------------------------------------------- #


async def test_upsert_inserts_then_updates() -> None:
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )

    session = _FakeSession()
    repo = TargetRepository(session)  # type: ignore[arg-type]
    target_id = uuid.uuid4()

    first = await repo.upsert_technology(
        target_id=target_id,
        slug="nginx",
        display="nginx",
        family="server",
        version="1.25",
        confidence="HIGH",
        source="header:server",
        observed_in_scan_id=None,
    )
    assert first["slug"] == "nginx"
    assert session.flushes == 1

    second = await repo.upsert_technology(
        target_id=target_id,
        slug="nginx",
        display="nginx",
        family="server",
        version="1.26",
        confidence="MEDIUM",
        source="html:marker",
        observed_in_scan_id=None,
    )
    # Same identity row: version latest wins, first observation preserved,
    # sources merged, confidence keeps the max.
    assert second["id"] == first["id"]
    assert second["version"] == "1.26"
    assert second["sources"] == "header:server,html:marker"
    assert second["confidence"] == "HIGH"
    assert len(session.rows) == 1


async def test_list_technologies_returns_dtos() -> None:
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )

    target_id = uuid.uuid4()
    session = _FakeSession([_tech_row(target_id=target_id, slug="nginx")])
    repo = TargetRepository(session)  # type: ignore[arg-type]
    rows = await repo.list_technologies(target_id)
    assert [r["slug"] for r in rows] == ["nginx"]
    assert rows[0]["first_observed_at"] == datetime(2026, 1, 1, tzinfo=UTC).isoformat()


# --------------------------------------------------------------------------- #
# Worker persist step                                                         #
# --------------------------------------------------------------------------- #


def _technology(slug: str = "nginx", family: str = "server") -> object:
    from src.domain.scanning.findings import Confidence

    return type(
        "T",
        (),
        {
            "slug": slug,
            "display": slug,
            "family": family,
            "version": "1.25",
            "confidence": Confidence.HIGH,
            "sources": ("header:server",),
        },
    )()


async def test_persist_technologies_upserts_valid_rows() -> None:
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )
    from tests.unit.conftest import _principal

    calls: list[dict] = []

    async def fake_upsert(_self: object, **kwargs: object) -> dict:
        calls.append(dict(kwargs))
        return {"id": str(uuid.uuid4()), **{k: str(v) for k, v in kwargs.items()}}

    async def fake_flush(_self: object) -> None:
        return None

    # Patch at class level without a fixture: save and restore manually.
    original_upsert = TargetRepository.upsert_technology
    original_flush = TargetRepository.flush
    TargetRepository.upsert_technology = fake_upsert  # type: ignore[method-assign]
    TargetRepository.flush = fake_flush  # type: ignore[method-assign]
    try:
        service = ScanService(object(), _principal())  # type: ignore[arg-type]
        scan = type("S", (), {"id": uuid.uuid4(), "target_id": uuid.uuid4()})()
        result = type("R", (), {"technologies": (_technology(),)})()
        await service._persist_technologies(scan, result)
    finally:
        TargetRepository.upsert_technology = original_upsert
        TargetRepository.flush = original_flush
    assert len(calls) == 1
    assert calls[0]["slug"] == "nginx"
    assert calls[0]["target_id"] == scan.target_id


async def test_persist_technologies_skips_invalid_rows() -> None:
    from src.domain.scans.scan_service import ScanService
    from src.infrastructure.database.repositories.target_repository import (
        TargetRepository,
    )
    from tests.unit.conftest import _principal

    calls: list[dict] = []

    async def fake_upsert(_self: object, **kwargs: object) -> dict:
        calls.append(dict(kwargs))
        return dict(kwargs)

    async def fake_flush(_self: object) -> None:
        return None

    original_upsert = TargetRepository.upsert_technology
    original_flush = TargetRepository.flush
    TargetRepository.upsert_technology = fake_upsert  # type: ignore[method-assign]
    TargetRepository.flush = fake_flush  # type: ignore[method-assign]
    try:
        service = ScanService(object(), _principal())  # type: ignore[arg-type]
        scan = type("S", (), {"id": uuid.uuid4(), "target_id": uuid.uuid4()})()
        bad_family = _technology(slug="x", family="botnet")
        bad_conf = _technology(slug="y")
        object.__setattr__(bad_conf, "confidence", "CERTAIN")
        empty_slug = _technology(slug="  ")
        result = type("R", (), {"technologies": (bad_family, bad_conf, empty_slug)})()
        await service._persist_technologies(scan, result)
        # Nothing persisted — and crucially, nothing raised.
        none_result = type("R", (), {})()
        await service._persist_technologies(scan, none_result)
    finally:
        TargetRepository.upsert_technology = original_upsert
        TargetRepository.flush = original_flush
    assert calls == []


# --------------------------------------------------------------------------- #
# Assembler bridge + comparison time-gating                                   #
# --------------------------------------------------------------------------- #


def test_assembler_technology_relevance() -> None:
    rows = [
        {
            "cve_id": "CVE-2021-44228",
            "cvss_score": None,
            "affected_technology": "nginx HTTP server",
        }
    ]
    without_tech = _priority_for("MEDIUM", None, rows, ())
    assert without_tech.score == 40 + 5  # CVE only
    with_tech = _priority_for("MEDIUM", None, rows, ("nginx",))
    assert with_tech.score == 40 + 5 + 5  # CVE + tech relevance
    assert with_tech.version == PRIORITY_VERSION_V2
    assert any(f.startswith("tech-relevance:") for f in with_tech.factors)
    # Technology without paired evidence scores nothing extra.
    assert _priority_for("MEDIUM", None, None, ("nginx",)).score == 40


def test_technology_signal_time_gating() -> None:
    from src.domain.scans.scan_service import _technology_signal_slugs

    rows = [
        {"slug": "nginx", "first_observed_at": datetime(2026, 1, 1, tzinfo=UTC)},
        {"slug": "php", "first_observed_at": datetime(2026, 5, 1, tzinfo=UTC)},
        {"slug": "ghost", "first_observed_at": None},
    ]
    assert _technology_signal_slugs(rows, None) == ("ghost", "nginx", "php")
    assert _technology_signal_slugs(rows, datetime(2026, 2, 1, tzinfo=UTC)) == ("nginx",)
    # Unparseable timestamps never backdate.
    rows.append({"slug": "bad", "first_observed_at": "not-a-date"})
    assert _technology_signal_slugs(rows, datetime(2026, 2, 1, tzinfo=UTC)) == ("nginx",)
