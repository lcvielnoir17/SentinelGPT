"""Background task workers package (SRS Ch6 §6).

This package houses the Celery worker tier that drains the asynchronous
job queues. The ``scan`` queue is the only one wired in this phase; the
``ai`` and ``report`` queues are reserved for the upcoming AI-analysis
and PDF-report workers and will be added without API changes (the API
process dispatches by task name, never by import).

Public surface:

* :func:`src.workers.celery_app.celery_app` — the configured Celery app
* :func:`src.workers.scan_tasks.enqueue_scan` — API-side dispatch helper
* :func:`src.workers.scan_tasks.execute_scan_job_task` — the scan task
"""

from src.workers.celery_app import celery_app
from src.workers.scan_tasks import enqueue_scan, execute_scan_job_task

__all__ = ["celery_app", "enqueue_scan", "execute_scan_job_task"]
