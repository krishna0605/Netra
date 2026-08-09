from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.forensics.models import IntegrationCredential
from apps.forensics.services.integration_credentials import store_integration_secret


class Command(BaseCommand):
    help = "Plan or execute migration of legacy plaintext integration credentials."

    def add_arguments(self, parser):
        parser.add_argument("--execute", action="store_true")

    def handle(self, *args, **options):
        rows = IntegrationCredential.objects.exclude(secret_value="").select_related("integration", "integration__organization")
        count = rows.count()
        if not options["execute"]:
            self.stdout.write(f"PLAN ONLY: {count} legacy integration credential(s). No credential was changed.")
            return
        if count == 0:
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
        self.stdout.write(self.style.SUCCESS(f"Migrated {count} integration credential(s) to encrypted envelopes."))

