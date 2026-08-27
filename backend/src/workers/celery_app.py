"""Celery application factory for the SentinelGPT worker tier.

This module defines the single Celery application instance shared by all
worker tasks. Three logical queues are wired (SRS Ch6 §6):

* ``scan``   — long-running, CPU/IO-bound, sandbox-provisioning work
* ``ai``     — network-bound, rate-limited by Gemini quota
* ``report`` — memory-bound, PDF rendering (placeholder until reports land)

Routing from the API process uses ``send_task`` rather than a direct
import so the API does not have to import the worker tasks (and therefore
the entire scanning stack) at startup — Celery's broker is the seam.

Security notes:

* The application object is a singleton bound to the process; tests inject
  a fresh ``app.conf`` via ``app.conf.update(...)`` rather than re-importing
  the module.
* The default broker and result backend are read from the existing
  ``Settings`` (no env knobs added), keeping secrets management centralized.
* ``task_acks_late=True`` is OFF by default: tasks acknowledge after the
  successful database commit. A crash mid-execution therefore leaves the
  scan in ``RUNNING`` and the next worker re-claims it only if the scan
  state machine allows the transition back to ``RUNNING`` from ``REJECTED``
  (it does not, by design). This is the honest outcome: the scan surfaces
  its failure and an operator re-queues it explicitly.
"""

from __future__ import annotations

from celery import Celery

from src.config.constants import CELERY_QUEUE_SCAN
from src.config.settings import get_settings
from src.infrastructure.logging.logger import configure_logging, get_logger

logger = get_logger(__name__)


def _build_celery() -> Celery:
    settings = get_settings()
    configure_logging(log_level=settings.log_level, log_json=settings.log_json)
    app = Celery(
        "sentinelgpt",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
        include=[
            "src.workers.scan_tasks",
        ],
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=False,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=200,
        broker_connection_retry_on_startup=True,
        task_default_queue=CELERY_QUEUE_SCAN,
        task_routes={
            "src.workers.scan_tasks.execute_scan_job_task": {
                "queue": CELERY_QUEUE_SCAN,
            },
        },
        task_time_limit=900,
        task_soft_time_limit=840,
    )
    return app


celery_app: Celery = _build_celery()


__all__ = ["celery_app"]
