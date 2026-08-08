import json

from django.core.management.base import BaseCommand

from common.storage_cache import storage_cache


class Command(BaseCommand):
    help = "Inspect or perform bounded maintenance on the encrypted persistent Storage cache."
    requires_system_checks = []

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument("--startup", action="store_true")
        mode.add_argument("--prune", action="store_true")
        mode.add_argument("--status", action="store_true")
        parser.add_argument("--json", action="store_true")

    def handle(self, *args, **options):
        status = storage_cache.status() if options["status"] else storage_cache.prune(startup=options["startup"])
        payload = status.as_dict()
        self.stdout.write(json.dumps(payload, sort_keys=True) if options["json"] else str(payload))
