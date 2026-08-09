from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.forensics.route_policies import route_policy_inventory
from apps.forensics.urls import urlpatterns


class Command(BaseCommand):
    help = "Generate or verify the committed API route-policy inventory."

    def add_arguments(self, parser):
        parser.add_argument("--check", action="store_true", help="Fail if the committed inventory differs.")

    def handle(self, *args, **options):
        target = Path(settings.BASE_DIR).parent / "docs" / "api" / "ROUTE_POLICY_INVENTORY.json"
        rendered = json.dumps(route_policy_inventory(urlpatterns), indent=2, sort_keys=True) + "\n"
        if options["check"]:
            if not target.exists() or target.read_text(encoding="utf-8") != rendered:
                raise CommandError("Route-policy inventory is missing or stale.")
            self.stdout.write(self.style.SUCCESS(f"Verified {len(urlpatterns)} route policies."))
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Wrote {len(urlpatterns)} route policies to {target}."))
