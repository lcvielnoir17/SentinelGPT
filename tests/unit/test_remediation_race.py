"""Remediation/enrichment insert races resolve onto the winner (no 500).

Concurrent writers for the same identity must converge: the loser of
the unique-constraint race re-reads and returns/updates the winning
row instead of bubbling ``IntegrityError``.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy.exc import IntegrityError

from src.infrastructure.database.models import FindingEnrichment, FindingRemediation
from src.infrastructure.database.repositories.scan_repository import (
    ScanEngineExecutionRepository,
)

TARGET_ID = uuid.uuid4()
USER_ID = uuid.uuid4()


class _FakeResult:
    def __init__(self, rows: list) -> None:  # type: ignore[no-untyped-def]
        self._rows = rows

    def scalars(self):  # type: ignore[no-untyped-def]
        return self

    def first(self):  # type: ignore[no-untyped-def]
        return self._rows[0] if self._rows else None


class _RacingSession:
    """Select script + one-shot flush failure, savepoint-aware adds."""

    def __init__(self, selects: list, *, fail_flush_once: bool = False) -> None:  # type: ignore[no-untyped-def]
        self._selects = list(selects)
        self._fail_flush_once = fail_flush_once
        self._staged: list = []
        self.persisted: list = []

    async def execute(self, _stmt: object):  # type: ignore[no-untyped-def]
        if not self._selects:
            raise AssertionError("unexpected select")
        return _FakeResult(self._selects.pop(0))

    def add(self, row: object) -> None:
        self._staged.append(row)

    async def flush(self) -> None:
        if self._fail_flush_once:
            self._fail_flush_once = False
            raise IntegrityError("INSERT", {}, Exception("duplicate key"))
        self.persisted.extend(self._staged)
        self._staged.clear()

    def begin_nested(self):  # type: ignore[no-untyped-def]
        session = self

        @asynccontextmanager
        async def _nested():  # type: ignore[no-untyped-def]
            base = len(session._staged)
            try:
                yield session
            except Exception:
                del session._staged[base:]
                raise

        return _nested()


def _remediation_kwargs(**overrides: object) -> dict:  # type: ignore[no-untyped-def]
    params: dict = {
        "fingerprint": "fp-1",
        "target_id": TARGET_ID,
        "status": "IN_PROGRESS",
        "notes": "patching",
        "updated_by_user_id": USER_ID,
    }
    params.update(overrides)
    return params


def _enrichment_kwargs() -> dict:  # type: ignore[no-untyped-def]
    return {
        "fingerprint": "fp-1",
        "target_id": TARGET_ID,
        "source": "nvd",
        "external_ref": "CVE-2024-1234",
        "cve_id": "CVE-2024-1234",
        "cwe_id": None,
        "cvss_score": 7.5,
        "cvss_vector": None,
        "references": [],
        "affected_technology": None,
        "remediation": None,
    }


@pytest.mark.asyncio
async def test_set_remediation_race_updates_winner() -> None:
    winner = FindingRemediation(
        fingerprint="fp-1",
        target_id=TARGET_ID,
        status="TODO",
        notes="old",
        updated_by_user_id=USER_ID,
    )
    session = _RacingSession([[], [winner]], fail_flush_once=True)
    dto = await ScanEngineExecutionRepository(session).set_remediation(**_remediation_kwargs())  # type: ignore[arg-type]
    assert dto["status"] == "IN_PROGRESS"
    assert dto["notes"] == "patching"
    assert winner.status == "IN_PROGRESS"


@pytest.mark.asyncio
async def test_set_remediation_happy_path_unchanged() -> None:
    session = _RacingSession([[]])
    dto = await ScanEngineExecutionRepository(session).set_remediation(**_remediation_kwargs())  # type: ignore[arg-type]
    assert dto["status"] == "IN_PROGRESS"
    assert len(session.persisted) == 1


@pytest.mark.asyncio
async def test_add_enrichment_race_returns_winner() -> None:
    winner = FindingEnrichment(
        fingerprint="fp-1",
        target_id=TARGET_ID,
        source="nvd",
        external_ref="CVE-2024-1234",
        cve_id="CVE-2024-1234",
        cwe_id=None,
        cvss_score=7.5,
        cvss_vector=None,
        references=[],
        affected_technology=None,
        remediation=None,
    )
    session = _RacingSession([[], [winner]], fail_flush_once=True)
    dto = await ScanEngineExecutionRepository(session).add_enrichment(**_enrichment_kwargs())  # type: ignore[arg-type]
    assert dto["cve_id"] == "CVE-2024-1234"
    assert dto["fingerprint"] == "fp-1"
