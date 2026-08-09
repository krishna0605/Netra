import json
import uuid
import urllib.error
import urllib.request

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection

from common.kafka import TOPIC_QUEUE_MAP
from common.http_transport import bounded_read, normalized_https_origin, open_same_origin
from common.supabase_keys import elevated_api_headers


BUCKETS = [
    "netra-evidence",
    "netra-capture-chunks",
    "netra-analysis-chunks",
    "netra-zeek-logs",
    "netra-reports",
    "netra-exports",
]

REALTIME_TABLES = [
    "forensics_operationalevent",
    "forensics_processingjob",
    "forensics_alert",
    "forensics_anomalyrecord",
    "forensics_capturejob",
    "forensics_workerheartbeat",
]


class Command(BaseCommand):
    help = "Bootstrap egress-safe Supabase extensions, queues, private buckets, and optional realtime for Netra."

    def add_arguments(self, parser):
        parser.add_argument(
            "--deep-storage-check",
            action="store_true",
            help="Upload, download, and delete one tiny probe per bucket. Never use this for routine startup checks.",
        )

    def handle(self, *args, **options):
        if getattr(settings, "NETRA_DATABASE_PROVIDER", "") != "supabase":
            self.stdout.write(self.style.WARNING("NETRA_DATABASE_PROVIDER is not 'supabase'; running bootstrap anyway."))
        created = {
            "extensions": self._extensions(),
            "queues": self._queues(),
            "buckets": self._buckets(deep_storage_check=options["deep_storage_check"]),
            "realtimeTables": self._realtime_tables(),
        }
        self.stdout.write(json.dumps(created, indent=2))
        self.stdout.write(self.style.SUCCESS("Supabase bootstrap completed."))

    def _extensions(self) -> list[str]:
        # Supabase provisions pgcrypto. Netra's schedules and retention are
        # Django workers, and the repository has no pg_trgm queries or indexes.
        statements = ["create extension if not exists pgmq"]
        completed = []
        with connection.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)
                completed.append(statement)
        return completed

    def _queues(self) -> list[str]:
        queue_names = sorted(set(TOPIC_QUEUE_MAP.values()))
        completed = []
        with connection.cursor() as cursor:
            for queue_name in queue_names:
                cursor.execute("select exists(select 1 from information_schema.tables where table_schema = 'pgmq' and table_name = %s)", [f"q_{queue_name}"])
                if cursor.fetchone()[0]:
                    completed.append(f"reused:{queue_name}")
                    continue
                cursor.execute("select pgmq.create(%s)", [queue_name])
                completed.append(f"created:{queue_name}")
        return completed

    def _buckets(self, *, deep_storage_check: bool = False) -> list[str]:
        if not settings.SUPABASE_URL or not settings.SUPABASE_SECRET_KEY:
            return ["skipped: SUPABASE_URL and SUPABASE_SECRET_KEY are required"]
        existing = self._storage_request("/storage/v1/bucket", method="GET")
        existing_names = {row.get("name") or row.get("id") for row in json.loads(existing or "[]")}
        completed = []
        for bucket in BUCKETS:
            if bucket in existing_names:
                completed.append(f"reused:{bucket}")
            else:
                body = json.dumps({"id": bucket, "name": bucket, "public": False}).encode("utf-8")
                self._storage_request("/storage/v1/bucket", method="POST", body=body)
                completed.append(f"created:{bucket}")
            if deep_storage_check:
                self._probe_bucket(bucket)
                completed.append(f"deep-verified:{bucket}")
            else:
                completed.append(f"metadata-verified:{bucket}")
        return completed

    def _realtime_tables(self) -> list[str]:
        existing_tables = set(connection.introspection.table_names())
        tables = [table for table in REALTIME_TABLES if table in existing_tables]
        completed = []
        with connection.cursor() as cursor:
            cursor.execute("select exists(select 1 from pg_publication where pubname = 'supabase_realtime')")
            if not cursor.fetchone()[0]:
                return ["skipped: supabase_realtime publication is not available"]
            realtime_enabled = (
                getattr(settings, "NETRA_REALTIME_PROVIDER", "") == "supabase"
                and not getattr(settings, "NETRA_FREE_PLAN_GUARD", False)
            )
            for table in tables:
                cursor.execute("select exists(select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = %s)", [table])
                published = cursor.fetchone()[0]
                if not realtime_enabled:
                    if published:
                        cursor.execute(f'alter publication supabase_realtime drop table public."{table}"')
                        completed.append(f"removed:{table}")
                    else:
                        completed.append(f"disabled:{table}")
                    continue
                if published:
                    completed.append(f"reused:{table}")
                else:
                    cursor.execute(f'alter publication supabase_realtime add table public."{table}"')
                    completed.append(f"added:{table}")
        return completed

    def _storage_request(self, path: str, method: str, body: bytes | None = None) -> str:
        key = settings.SUPABASE_SECRET_KEY
        origin = normalized_https_origin(settings.SUPABASE_URL)
        request = urllib.request.Request(
            f"{origin}{path}",
            method=method,
            data=body,
            headers=elevated_api_headers(key, content_type="application/json"),
        )
        try:
            with open_same_origin(request, origin=origin, timeout=30) as response:
                return bounded_read(response, 131072).decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = bounded_read(exc, 131072).decode("utf-8", errors="replace")
            if exc.code == 409:
                return "[]"
            raise RuntimeError(f"Supabase Storage bootstrap HTTP {exc.code}: {detail}") from exc

    def _probe_bucket(self, bucket: str) -> None:
        key = settings.SUPABASE_SECRET_KEY
        object_name = f"bootstrap/netra-bootstrap-probe-{uuid.uuid4().hex}.txt"
        origin = normalized_https_origin(settings.SUPABASE_URL)
        url = f"{origin}/storage/v1/object/{bucket}/{object_name}"
        headers = {**elevated_api_headers(key, content_type="text/plain"), "x-upsert": "true"}
        upload = urllib.request.Request(url, method="POST", data=b"netra-bootstrap-probe", headers=headers)
        download = urllib.request.Request(url, method="GET", headers=elevated_api_headers(key))
        delete = urllib.request.Request(url, method="DELETE", headers=elevated_api_headers(key, content_type="application/json"))
        try:
            with open_same_origin(upload, origin=origin, timeout=30) as response:
                bounded_read(response, 131072)
            with open_same_origin(download, origin=origin, timeout=30) as response:
                content = bounded_read(response, 1024)
                if content != b"netra-bootstrap-probe":
                    raise RuntimeError(f"Supabase Storage bootstrap probe failed for {bucket}: content mismatch")
        finally:
            try:
                with open_same_origin(delete, origin=origin, timeout=30) as response:
                    bounded_read(response, 131072)
            except Exception:  # nosec B110
                pass
