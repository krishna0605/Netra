from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.forensics.models import Case
from common.custody import record_custody_event
from common.custody_anchors import write_anchor


class Command(BaseCommand):
    help = "Export privacy-minimal, Ed25519-signed custody anchors."

    def add_arguments(self, parser):
        parser.add_argument("--case-id")
        parser.add_argument("--output-directory", required=True)
        parser.add_argument("--upload", action="store_true", help="Upload immutable anchors after local creation.")

    def handle(self, *args, **options):
        cases = Case.objects.order_by("id")
        if options["case_id"]:
            cases = cases.filter(pk=options["case_id"])
        if not cases.exists():
            raise CommandError("No matching case exists.")
        root = Path(options["output_directory"]).expanduser().resolve()
        for case in cases.iterator():
            latest = case.custody_ledger.order_by("-created_at", "-id").first()
            suffix = latest.id if latest else "empty"
            target = root / f"{case.id}-{suffix}.json"
            uri = write_anchor(case, target, upload=options["upload"])
            record_custody_event(
                case, "custody-anchor", "custody-anchor-created",
                {"anchorLocation": uri if options["upload"] else target.name},
                resource_type="custody-anchor", resource_id=suffix,
            )
            self.stdout.write(uri)
