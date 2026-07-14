from __future__ import annotations

import os
import socket
import time
from uuid import uuid4

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.forensics.models import WorkerHeartbeat
from common.async_pipeline import process_claimed_job
from common.postgres_jobs import claim_next_job, mark_job_failure


class Command(BaseCommand):
    help = "Run the durable PostgreSQL-backed evidence analysis worker."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Claim at most one job and exit.")
        parser.add_argument("--worker-id", default="", help="Stable worker instance identifier.")

    def handle(self, *args, **options):
        worker_id = options["worker_id"] or os.getenv("RAILWAY_REPLICA_ID") or f"{socket.gethostname()}-{uuid4().hex[:8]}"
        self.stdout.write(f"Starting durable NETRA worker {worker_id}")
        while True:
            job = claim_next_job(worker_id)
            self._heartbeat(worker_id, job.id if job else "")
            if job is None:
                if options["once"]:
                    return
                time.sleep(settings.NETRA_JOB_POLL_SECONDS)
                continue
            try:
                process_claimed_job(job)
                self.stdout.write(self.style.SUCCESS(f"Completed {job.id}"))
            except Exception as exc:
                failed = mark_job_failure(job.id, worker_id, exc)
                self.stderr.write(f"Job {job.id} ended as {failed.status}: {failed.error_code}")
            finally:
                self._heartbeat(worker_id, "")
            if options["once"]:
                return

    @staticmethod
    def _heartbeat(worker_id: str, current_job_id: str) -> None:
        WorkerHeartbeat.objects.update_or_create(
            worker_name="postgres-analysis",
            instance_id=worker_id,
            defaults={
                "status": "healthy",
                "last_seen_at": timezone.now(),
                "current_job_id": current_job_id,
                "details_json": {
                    "queueProvider": "postgres-row-lock",
                    "processingMode": "postgres-worker",
                },
            },
        )
