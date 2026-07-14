from __future__ import annotations

import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections
from django.utils import timezone

from apps.forensics.models import WorkerHeartbeat
from common.async_pipeline import process_claimed_job
from common.postgres_jobs import claim_next_job, mark_job_failure, renew_job_lease
from common.quarantine_cleanup import cleanup_worker_artifacts


class Command(BaseCommand):
    help = "Run the durable PostgreSQL-backed evidence analysis worker."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Claim at most one job and exit.")
        parser.add_argument("--worker-id", default="", help="Stable worker instance identifier.")

    def handle(self, *args, **options):
        worker_id = options["worker_id"] or os.getenv("RAILWAY_REPLICA_ID") or f"{socket.gethostname()}-{uuid4().hex[:8]}"
        self._start_health_server()
        cleanup_worker_artifacts()
        last_cleanup = time.monotonic()
        self.stdout.write(f"Starting durable NETRA worker {worker_id}")
        while True:
            if time.monotonic() - last_cleanup >= settings.NETRA_CLEANUP_INTERVAL_SECONDS:
                cleanup_worker_artifacts()
                last_cleanup = time.monotonic()
            job = claim_next_job(worker_id)
            self._heartbeat(worker_id, job.id if job else "")
            if job is None:
                if options["once"]:
                    return
                time.sleep(settings.NETRA_JOB_POLL_SECONDS)
                continue
            heartbeat_stop = threading.Event()
            heartbeat_thread = threading.Thread(
                target=self._job_heartbeat_loop,
                args=(heartbeat_stop, worker_id, job.id),
                name=f"lease-heartbeat-{job.id}",
                daemon=True,
            )
            heartbeat_thread.start()
            try:
                process_claimed_job(job)
                self.stdout.write(self.style.SUCCESS(f"Completed {job.id}"))
            except Exception as exc:
                failed = mark_job_failure(job.id, worker_id, exc)
                self.stderr.write(f"Job {job.id} ended as {failed.status}: {failed.error_code}")
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=settings.NETRA_JOB_HEARTBEAT_SECONDS + 1)
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

    @classmethod
    def _job_heartbeat_loop(cls, stop: threading.Event, worker_id: str, job_id: str) -> None:
        while not stop.wait(settings.NETRA_JOB_HEARTBEAT_SECONDS):
            close_old_connections()
            try:
                if not renew_job_lease(job_id, worker_id):
                    return
                cls._heartbeat(worker_id, job_id)
            except Exception:
                # A transient database error is retried on the next bounded
                # heartbeat interval; the main worker still owns the job lease.
                continue
            finally:
                close_old_connections()

    @staticmethod
    def _start_health_server() -> None:
        port = int(os.getenv("PORT", "0"))
        if not port:
            return

        class HealthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.rstrip("/") != "/api/health":
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = b'{"status":"ok","service":"netra-worker"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format, *_args):
                return

        server = ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)
        threading.Thread(target=server.serve_forever, name="worker-health", daemon=True).start()
