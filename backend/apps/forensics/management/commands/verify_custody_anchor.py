from django.core.management.base import BaseCommand, CommandError

from common.custody_anchors import load_anchor, verify_anchor


class Command(BaseCommand):
    help = "Verify an exported Ed25519 custody anchor independently of the ledger database."

    def add_arguments(self, parser):
        parser.add_argument("source")

    def handle(self, *args, **options):
        try:
            anchor = verify_anchor(load_anchor(options["source"]))
        except Exception as exc:
            raise CommandError("Custody anchor verification failed.") from exc
        self.stdout.write(self.style.SUCCESS(
            f"Verified anchor for case {anchor['caseId']} with {anchor['eventCount']} event(s)."
        ))
