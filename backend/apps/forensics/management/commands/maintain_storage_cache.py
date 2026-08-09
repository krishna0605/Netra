import json
import logging

from django.core.management.base import BaseCommand

from common.storage_cache import storage_cache


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Inspect or perform bounded maintenance on the encrypted persistent Storage cache."
    requires_system_checks = []

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument("--startup", action="store_true")
        mode.add_argument("--prune", action="store_true")
        mode.add_argument("--status", action="store_true")
        parser.add_argument("--json", action="store_true")
        parser.add_argument(
            "--best-effort",
            action="store_true",
            help="Report startup degradation without preventing the API process from starting.",
        )

    def handle(self, *args, **options):
        try:
            status = storage_cache.status() if options["status"] else storage_cache.prune(startup=options["startup"])
            payload = {**status.as_dict(), "available": True}
        except Exception as exc:
            if not options["best_effort"]:
                raise
            logger.warning("Encrypted cache startup maintenance is degraded: %s", exc.__class__.__name__)
            payload = {
                "available": False,
                "enabled": storage_cache.enabled,
                "root": str(storage_cache.root),
                "detail": "Encrypted cache startup maintenance did not complete.",
            }
        self.stdout.write(json.dumps(payload, sort_keys=True) if options["json"] else str(payload))
