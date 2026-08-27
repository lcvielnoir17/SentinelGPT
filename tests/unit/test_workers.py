"""Unit tests for the Celery worker wiring (Phase 7 execution tier).

These tests verify the worker module is correctly configured without
requiring a live broker. They cover:

* The Celery app loads with the expected queue/serializer config
  (SRS Ch6 §6: JSON, prefetch=1, task time-limit, no late-ack).
* The ``enqueue_scan`` helper is a no-op when
  ``scanner_execution_enabled`` is false (mirrors the route layer gate).
* The task module exposes the same task name the route layer dispatches
  to, so the API never accidentally invokes a stale name.
"""

from __future__ import annotations

import uuid

from src.config.settings import get_settings
from src.workers.celery_app import celery_app
from src.workers.scan_tasks import enqueue_scan, execute_scan_job_task


def test_celery_app_loads_with_expected_config() -> None:
    """Worker app is wired with SRS-mandated defaults."""
    assert celery_app.main == "sentinelgpt"
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"
    assert celery_app.conf.timezone == "UTC"
    assert celery_app.conf.enable_utc is True
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert celery_app.conf.task_acks_late is False
    assert celery_app.conf.task_time_limit >= 60
    assert "json" in celery_app.conf.accept_content


def test_celery_app_routes_scan_task_to_scan_queue() -> None:
    """The scan task is bound to the ``scan`` queue (SRS Ch6 §6)."""
    routes = celery_app.conf.task_routes or {}
    assert "src.workers.scan_tasks.execute_scan_job_task" in routes
    assert routes["src.workers.scan_tasks.execute_scan_job_task"]["queue"] == "scan"


def test_scan_task_registered_with_expected_name() -> None:
    """The task name on the route side and the worker side MUST agree."""
    assert execute_scan_job_task.name == "src.workers.scan_tasks.execute_scan_job_task"


def test_enqueue_scan_no_op_when_execution_disabled(monkeypatch: object) -> None:
    """When the operator has not flipped the switch, no task is dispatched.

    Mirrors ``scan_routes.create_scan``'s gate so the API and worker
    tiers cannot drift in their safety behavior.
    """
    settings = get_settings()
    original = settings.scanner_execution_enabled

    class _FakeApp:
        def send_task(self, *args: object, **kwargs: object) -> object:  # noqa: ARG002
            raise AssertionError("send_task should NOT be called when execution is disabled")

    import src.workers.scan_tasks as scan_tasks

    original_celery = scan_tasks.celery_app
    scan_tasks.celery_app = _FakeApp()  # type: ignore[assignment]
    try:
        # Force the gate to off
        object.__setattr__(settings, "scanner_execution_enabled", False)
        try:
            result = enqueue_scan(uuid.uuid4())
            assert result == ""
        finally:
            object.__setattr__(settings, "scanner_execution_enabled", original)
    finally:
        scan_tasks.celery_app = original_celery  # type: ignore[assignment]


def test_enqueue_scan_returns_task_id_when_enabled() -> None:
    """With the gate on, a task id is returned without touching the broker.

    The fake ``send_task`` returns an object with an ``id`` so the helper
    is exercised end-to-end without needing Redis.
    """

    class _FakeAsyncResult:
        id = "task-id-1234"

    class _FakeApp:
        def send_task(self, *args: object, **kwargs: object) -> _FakeAsyncResult:  # noqa: ARG002
            return _FakeAsyncResult()

    import src.workers.scan_tasks as scan_tasks

    original_celery = scan_tasks.celery_app
    scan_tasks.celery_app = _FakeApp()  # type: ignore[assignment]
    try:
        settings = get_settings()
        original = settings.scanner_execution_enabled
        object.__setattr__(settings, "scanner_execution_enabled", True)
        try:
            result = enqueue_scan(uuid.uuid4())
            assert result == "task-id-1234"
        finally:
            object.__setattr__(settings, "scanner_execution_enabled", original)
    finally:
        scan_tasks.celery_app = original_celery  # type: ignore[assignment]
