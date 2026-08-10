import json
import logging

from django.core.management.base import BaseCommand, CommandError

from common.storage_cache import (
    CACHE_CAPACITY_EXHAUSTED,
    CACHE_DISABLED,
    CACHE_LOCK_TIMEOUT,
    CACHE_ROOT_NOT_WRITABLE,
    OBJECT_SOURCE_UNAVAILABLE,
    storage_cache,
)


logger = logging.getLogger(__name__)

REMEDIATION = {
    CACHE_ROOT_NOT_WRITABLE: (
        "The persistent volume is not writable by the runtime user. Confirm a volume is mounted at "
        "NETRA_STORAGE_ROOT and that the entrypoint chown ran before privileges were dropped."
    ),
    CACHE_CAPACITY_EXHAUSTED: (
        "The volume cannot hold the cache and preserve its free-space reserve. Expand the Railway "
        "volume or lower NETRA_STORAGE_CACHE_MAX_BYTES."
    ),
    CACHE_LOCK_TIMEOUT: (
        "A cache lease could not be acquired. Check for a stalled worker still holding the volume lock."
    ),
    OBJECT_SOURCE_UNAVAILABLE: (
        "Supabase Storage rejected or could not serve the object. Verify SUPABASE_SECRET_KEY is current "
        "and that the evidence object still exists in its bucket."
    ),
    CACHE_DISABLED: "NETRA_STORAGE_CACHE_ENABLED is off; hosted deployments require the persistent cache.",
}


class Command(BaseCommand):
    help = "Inspect or perform bounded maintenance on the encrypted persistent Storage cache."
    requires_system_checks = []

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument("--startup", action="store_true")
        mode.add_argument("--prune", action="store_true")
        mode.add_argument("--status", action="store_true")
        mode.add_argument(
            "--preflight",
            action="store_true",
            help="Probe volume writability and capacity only, then report the classified result.",
        )
        parser.add_argument("--json", action="store_true")
        parser.add_argument(
            "--best-effort",
            action="store_true",
            help="Report startup degradation without preventing the API process from starting.",
        )

    def handle(self, *args, **options):
        probing = options["startup"] or options["preflight"]
        try:
            preflight = storage_cache.preflight() if probing else None
            if preflight is not None and not preflight["ok"]:
                code = preflight["code"]
                raise CommandError(
                    f"Encrypted Storage cache preflight failed [{code}]. "
                    f"{REMEDIATION.get(code, 'Inspect the worker log for the underlying exception.')}"
                )
            if options["preflight"]:
                payload = {**preflight, "available": True}
            else:
                status = storage_cache.status() if options["status"] else storage_cache.prune(startup=options["startup"])
                payload = {**status.as_dict(), "available": True}
                if preflight is not None:
                    payload["preflight"] = preflight
        except Exception as exc:
            if not options["best_effort"]:
                raise
            # The API process starts degraded so its logs stay reachable; the
            # worker runs without --best-effort and fails the deploy instead.
            logger.warning("Encrypted cache startup maintenance is degraded: %s", exc)
            payload = {
                "available": False,
                "enabled": storage_cache.enabled,
                "root": str(storage_cache.root),
                "detail": "Encrypted cache startup maintenance did not complete.",
            }
        self.stdout.write(json.dumps(payload, sort_keys=True) if options["json"] else str(payload))
