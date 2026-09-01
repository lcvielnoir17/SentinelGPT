"""Regression test for the Celery prefork DB engine reset.

When a Celery worker is started with prefork concurrency (the default),
each child process inherits the module-level ``_engine`` and
``_sessionmaker`` singletons from the parent. Any asyncpg connection
that was opened in the parent's context is bound to the parent's event
loop — which does not exist in the child. When the first task in a
child calls ``asyncio.run(...)`` and reuses those connections,
asyncpg raises ``RuntimeError: ... attached to a different loop`` /
``InterfaceError: another operation is in progress`` and the scan
strands in QUEUED.

The fix connects a ``worker_process_init`` signal that clears the
singletons so each child re-initialises its engine against its own
event loop. This test pins that contract.
"""

from __future__ import annotations

from unittest.mock import patch


def test_worker_process_init_resets_inherited_db_engine() -> None:
    """The ``worker_process_init`` signal clears stale engine state."""
    # Simulate a parent process that already initialised the engine.
    from src.infrastructure.database import connection as db_connection

    fake_engine = object()
    fake_sessionmaker = object()
    db_connection._engine = fake_engine  # type: ignore[assignment]
    db_connection._sessionmaker = fake_sessionmaker  # type: ignore[assignment]

    # Importing the celery_app module registers the signal handler.
    import src.workers.celery_app  # noqa: F401

    # Invoke the registered signal handler directly.
    from src.workers.celery_app import _reset_db_engine_in_child

    _reset_db_engine_in_child()

    assert db_connection._engine is None
    assert db_connection._sessionmaker is None


def test_get_async_sessionmaker_reinitialises_after_reset() -> None:
    """After a reset, the next ``get_async_sessionmaker`` returns a new instance."""
    from src.infrastructure.database import connection as db_connection

    fake_engine = object()
    fake_sessionmaker = object()
    db_connection._engine = fake_engine  # type: ignore[assignment]
    db_connection._sessionmaker = fake_sessionmaker  # type: ignore[assignment]

    import src.workers.celery_app  # noqa: F401
    from src.workers.celery_app import _reset_db_engine_in_child

    _reset_db_engine_in_child()

    # We don't actually open a connection here (no live DB in unit tests);
    # we just verify the lazy-init branch sees a clean state.
    with patch.object(db_connection, "create_async_engine", autospec=True) as mock_create:
        db_connection.get_async_engine()
        assert mock_create.called
        # And the previous fake engine is gone.
        assert db_connection._engine is not fake_engine  # type: ignore[attr-defined]


def test_task_postrun_resets_engine_between_asyncio_runs() -> None:
    """Simulates the bug: task A's asyncio.run closes its loop, then task B
    starts a new asyncio.run. Without a reset between them, the cached
    asyncpg connections are bound to the dead loop. The ``task_postrun``
    signal handler must reset the engine so the next task binds fresh
    connections to its own loop.
    """
    from src.infrastructure.database import connection as db_connection

    fake_engine = object()
    fake_sessionmaker = object()
    db_connection._engine = fake_engine  # type: ignore[assignment]
    db_connection._sessionmaker = fake_sessionmaker  # type: ignore[assignment]

    import src.workers.celery_app  # noqa: F401
    from src.workers.celery_app import _reset_db_engine_after_task

    # Simulate task A finishing (asyncio.run returned, its loop is closed).
    _reset_db_engine_after_task(task_id="scan-1", task=None)

    assert db_connection._engine is None
    assert db_connection._sessionmaker is None

    # Simulate task B starting on a fresh asyncio.run / loop. The engine
    # must be re-initialised lazily; we just assert the prior state was
    # discarded so the new task sees a clean slate.
    assert db_connection._engine is not fake_engine  # type: ignore[attr-defined]
