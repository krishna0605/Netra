import time
import socket

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.forensics.models import WorkerHeartbeat
from common.fleet import execute_safe_retention


class Command(BaseCommand):
    help = "Run safe retention cleanup for finalized capture chunks."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--interval", type=int, default=3600)

    def handle(self, *args, **options):
        instance_id = f"{socket.gethostname()}-retention"
        while True:
            WorkerHeartbeat.objects.update_or_create(worker_name="retention", instance_id=instance_id, defaults={"status": "healthy", "last_seen_at": timezone.now(), "details_json": {"intervalSeconds": options["interval"]}})
            run = execute_safe_retention()
            self.stdout.write(f"Retention run {run.id}: reclaimed {run.bytes_reclaimed} bytes")
            if options["once"]:
                return
            remaining = max(60, options["interval"])
            while remaining > 0:
                time.sleep(min(10, remaining))
                remaining -= 10
                WorkerHeartbeat.objects.update_or_create(worker_name="retention", instance_id=instance_id, defaults={"status": "healthy", "last_seen_at": timezone.now(), "details_json": {"intervalSeconds": options["interval"]}})
