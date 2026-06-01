import time
import socket

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.forensics.models import CaptureSchedule, WorkerHeartbeat
from common.fleet import queue_schedule_run


class Command(BaseCommand):
    help = "Run the bounded fleet capture scheduler."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--interval", type=int, default=15)

    def handle(self, *args, **options):
        instance_id = f"{socket.gethostname()}-scheduler"
        while True:
            WorkerHeartbeat.objects.update_or_create(worker_name="scheduler", instance_id=instance_id, defaults={"status": "healthy", "last_seen_at": timezone.now(), "details_json": {"intervalSeconds": options["interval"]}})
            now = timezone.now()
            for schedule in CaptureSchedule.objects.filter(enabled=True, next_run_at__lte=now).order_by("next_run_at"):
                queue_schedule_run(schedule)
            if options["once"]:
                return
            time.sleep(max(5, options["interval"]))
