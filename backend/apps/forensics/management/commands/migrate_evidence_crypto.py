from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from common.crypto_migration import (
    enumerate_legacy_artifacts,
    execute_migration,
    validate_state_path,
)


class Command(BaseCommand):
    help = "Plan or execute a resumable, egress-capped legacy artifact crypto migration."
    requires_system_checks = []

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--plan", action="store_true", help="Inventory database pointers only (default).")
        mode.add_argument("--execute", action="store_true", help="Perform the explicitly gated migration.")
        parser.add_argument("--resume", action="store_true")
        parser.add_argument("--state", required=True)
        parser.add_argument("--max-source-bytes", type=int)
        parser.add_argument("--retain-until")
        parser.add_argument("--confirm-project-ref")

    def handle(self, *args, **options):
        try:
            state_path = validate_state_path(Path(options["state"]))
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        artifacts = enumerate_legacy_artifacts()
        estimated = sum(item.expected_bytes for item in artifacts)
        if not options["execute"]:
            self.stdout.write(self.style.SUCCESS(
                f"PLAN ONLY: {len(artifacts)} legacy pointer(s), {estimated} trusted source byte(s). "
                "No Storage object was read or written."
            ))
            return
        if not options["resume"]:
            raise CommandError("Execution requires --resume so interruption state is always enabled.")
        if not settings.SUPABASE_PROJECT_REF or options["confirm_project_ref"] != settings.SUPABASE_PROJECT_REF:
            raise CommandError("--confirm-project-ref must exactly match the configured target project reference.")
        if not options["max_source_bytes"] or options["max_source_bytes"] <= 0:
            raise CommandError("Execution requires a positive --max-source-bytes ceiling.")
        try:
            retain_until = datetime.fromisoformat(options["retain_until"] or "")
            if retain_until.tzinfo is None:
                raise ValueError
        except ValueError as exc:
            raise CommandError("--retain-until must be an ISO-8601 timestamp with a timezone.") from exc
        if retain_until <= datetime.now(timezone.utc):
            raise CommandError("--retain-until must be in the future.")
        state = execute_migration(
            artifacts, state_path=state_path, max_source_bytes=options["max_source_bytes"],
            retain_until=retain_until.isoformat(),
        )
        committed = sum(1 for item in state["artifacts"].values() if item.get("status") == "committed")
        self.stdout.write(self.style.SUCCESS(
            f"Committed {committed}/{len(artifacts)} artifact(s); source bytes read: {state['bytesRead']}."
        ))
