from __future__ import annotations

import json
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
from apps.forensics.services.webhook_delivery import claim_next_delivery, process_delivery
from common.access_log_retention import maintain_access_log_partitions
from common.async_pipeline import process_claimed_job
from common.postgres_jobs import claim_next_job, mark_job_failure, renew_job_lease
from common.quarantine_cleanup import cleanup_worker_artifacts
from common.storage_cache import StorageCacheUnavailable, storage_cache
from common.worker_capacity import invalidate_worker_capacity_cache
from common.tool_capabilities import require_worker_capabilities


class Command(BaseCommand):
    help = "Run the durable PostgreSQL-backed evidence analysis worker."
    cache_state: dict = {}

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Claim at most one job and exit.")
        parser.add_argument("--worker-id", default="", help="Stable worker instance identifier.")

    def handle(self, *args, **options):
        if settings.NETRA_RUNTIME_ROLE != "worker":
            raise RuntimeError("run_postgres_worker requires NETRA_RUNTIME_ROLE=worker")
        if settings.NETRA_PROCESSING_MODE != "postgres-worker" or settings.NETRA_QUEUE_PROVIDER != "postgres-row-lock":
            raise RuntimeError("The production worker requires postgres-worker and postgres-row-lock")
        self.capabilities = require_worker_capabilities()
        worker_id = options["worker_id"] or os.getenv("RAILWAY_REPLICA_ID") or f"{socket.gethostname()}-{uuid4().hex[:8]}"
        self.cache_state = storage_cache.preflight()
        self._start_health_server()
        cleanup_worker_artifacts()
        last_cleanup = time.monotonic()
        last_access_log_maintenance = 0.0
        self.access_log_maintenance = {"status": "pending"}
        self.stdout.write(f"Starting durable NETRA worker {worker_id}")
        if not self.cache_state.get("ok"):
            self.stderr.write(f"Encrypted Storage cache is not usable [{self.cache_state.get('code')}]")
        while True:
            if time.monotonic() - last_access_log_maintenance >= settings.NETRA_ACCESS_LOG_MAINTENANCE_SECONDS:
                try:
                    result = maintain_access_log_partitions()
                    self.access_log_maintenance = {
                        "status": result.status,
                        "createdPartitions": result.created_partitions,
                        "droppedPartitions": result.dropped_partitions,
                        "deletedRows": result.deleted_rows,
                    }
                except Exception as exc:  # nosec B110
                    self.access_log_maintenance = {"status": "failed", "error": type(exc).__name__}
                    self.stderr.write(f"AccessLog maintenance failed [{type(exc).__name__}]")
                last_access_log_maintenance = time.monotonic()
            if time.monotonic() - last_cleanup >= settings.NETRA_CLEANUP_INTERVAL_SECONDS:
                cleanup_worker_artifacts()
                self.cache_state = storage_cache.preflight()
                last_cleanup = time.monotonic()
            job = claim_next_job(worker_id)
            self._heartbeat(worker_id, job.id if job else "")
            if job is None:
                delivery = claim_next_delivery(worker_id) if settings.NETRA_ENABLE_INTEGRATIONS else None
                if delivery is not None:
                    completed = process_delivery(delivery)
                    self.stdout.write(f"Integration delivery {completed.pk} ended as {completed.result}")
                    if options["once"]:
                        return
                    continue
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
                if isinstance(exc, StorageCacheUnavailable):
                    # Re-probe immediately so the heartbeat and health endpoint
                    # name the cache fault instead of reporting a healthy worker.
                    self.cache_state = storage_cache.preflight()
                    self.stderr.write(f"Encrypted Storage cache fault [{exc.code}]")
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=settings.NETRA_JOB_HEARTBEAT_SECONDS + 1)
                self._heartbeat(worker_id, "")
            if options["once"]:
                return

    def _heartbeat(self, worker_id: str, current_job_id: str) -> None:
        WorkerHeartbeat.objects.update_or_create(
            worker_name="postgres-analysis",
            instance_id=worker_id,
            defaults={
                "status": "healthy",
                "last_seen_at": timezone.now(),
                "current_job_id": current_job_id,
                "details_json": {
                    "runtimeRole": "worker",
                    "releaseId": settings.NETRA_RELEASE_ID,
                    "queueProvider": "postgres-row-lock",
                    "processingMode": "postgres-worker",
                    "capabilities": self.capabilities,
                    "storageCacheOk": bool(self.cache_state.get("ok")),
                    "storageCacheCode": self.cache_state.get("code", ""),
                    "accessLogMaintenance": self.access_log_maintenance,
                },
            },
        )
        invalidate_worker_capacity_cache()

    def _job_heartbeat_loop(self, stop: threading.Event, worker_id: str, job_id: str) -> None:
        while not stop.wait(settings.NETRA_JOB_HEARTBEAT_SECONDS):
            close_old_connections()
            try:
                if not renew_job_lease(job_id, worker_id):
                    return
                self._heartbeat(worker_id, job_id)
            except Exception:  # nosec B112
                # A transient database error is retried on the next bounded
                # heartbeat interval; the main worker still owns the job lease.
                continue
            finally:
                close_old_connections()

    def _start_health_server(self) -> None:
        port = int(os.getenv("PORT", "0"))
        if not port:
            return
        command = self

        class HealthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.rstrip("/") != "/api/health":
                    self.send_response(404)
                    self.end_headers()
                    return
                state = command.cache_state or {}
                document = {
                    "status": "ok" if state.get("ok") else "degraded",
                    "service": "netra-worker",
                    "releaseId": settings.NETRA_RELEASE_ID,
                    "storageCache": state.get("code", ""),
                }
                payload = json.dumps(document, sort_keys=True).encode("utf-8")
                # Deliberately still 200 when degraded: a failing health check
                # makes Railway restart the worker in a loop, which destroys the
                # log line naming the cache fault.
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, _format, *_args):
                return

        # Railway must reach the container health port; the handler exposes only
        # a fixed, non-sensitive status document.
        server = ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)  # nosec B104
        threading.Thread(target=server.serve_forever, name="worker-health", daemon=True).start()
