import json

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.forensics.models import IntegrationCredential
from apps.forensics.services.integration_credentials import store_integration_secret


class Command(BaseCommand):
    help = "Plan or execute migration of legacy plaintext integration credentials."

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")
        parser.add_argument("--json", action="store_true", dest="json_output")

    def handle(self, *args, **options):
        rows = IntegrationCredential.objects.exclude(secret_value="").select_related("integration", "integration__organization")
        count = rows.count()
        if not options["execute"]:
            if options["json_output"]:
                self.stdout.write(json.dumps({"mode": "plan", "legacyCredentialCount": count, "migratedCount": 0}))
            else:
                self.stdout.write(f"PLAN ONLY: {count} legacy integration credential(s). No credential was changed.")
            return
        if count == 0:
            if options["json_output"]:
                self.stdout.write(json.dumps({"mode": "execute", "legacyCredentialCount": 0, "migratedCount": 0}))
            else:
                self.stdout.write("No legacy integration credentials require migration.")
            return
        try:
            with transaction.atomic():
                for credential in rows.select_for_update():
                    store_integration_secret(
                        credential.integration,
                        credential.secret_value,
                        label=credential.secret_label or "webhook-hmac",
                    )
        except Exception as exc:
            raise CommandError("Integration credential migration failed; no partial migration was committed.") from exc
        if options["json_output"]:
            self.stdout.write(json.dumps({"mode": "execute", "legacyCredentialCount": count, "migratedCount": count}))
        else:
            self.stdout.write(self.style.SUCCESS(f"Migrated {count} integration credential(s) to encrypted envelopes."))
