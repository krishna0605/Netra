import json
import uuid
import urllib.error
import urllib.request

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection

from common.kafka import TOPIC_QUEUE_MAP


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
    help = "Bootstrap Supabase extensions, queues, private buckets, and realtime publication for Netra."

    def handle(self, *args, **options):
        if getattr(settings, "NETRA_DATABASE_PROVIDER", "") != "supabase":
            self.stdout.write(self.style.WARNING("NETRA_DATABASE_PROVIDER is not 'supabase'; running bootstrap anyway."))
        created = {
            "extensions": self._extensions(),
            "queues": self._queues(),
            "buckets": self._buckets(),
            "realtimeTables": self._realtime_tables(),
        }
        self.stdout.write(json.dumps(created, indent=2))
        self.stdout.write(self.style.SUCCESS("Supabase bootstrap completed."))

    def _extensions(self) -> list[str]:
        statements = [
            "create extension if not exists pgcrypto with schema extensions",
            "create extension if not exists pg_trgm with schema extensions",
            "create extension if not exists pgmq",
            "create extension if not exists pg_cron",
        ]
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

    def _buckets(self) -> list[str]:
        if not settings.SUPABASE_URL or not settings.SUPABASE_SERVICE_ROLE_KEY:
            return ["skipped: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required"]
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
            self._probe_bucket(bucket)
            completed.append(f"verified:{bucket}")
        return completed

    def _realtime_tables(self) -> list[str]:
        existing_tables = set(connection.introspection.table_names())
        tables = [table for table in REALTIME_TABLES if table in existing_tables]
        completed = []
        with connection.cursor() as cursor:
            cursor.execute("select exists(select 1 from pg_publication where pubname = 'supabase_realtime')")
            if not cursor.fetchone()[0]:
                return ["skipped: supabase_realtime publication is not available"]
            for table in tables:
                cursor.execute("select exists(select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = %s)", [table])
                if cursor.fetchone()[0]:
                    completed.append(f"reused:{table}")
                    continue
                cursor.execute(f'alter publication supabase_realtime add table public."{table}"')
                completed.append(f"added:{table}")
        return completed

    def _storage_request(self, path: str, method: str, body: bytes | None = None) -> str:
        key = settings.SUPABASE_SERVICE_ROLE_KEY
        request = urllib.request.Request(
            f"{settings.SUPABASE_URL.rstrip('/')}{path}",
            method=method,
            data=body,
            headers={"Authorization": f"Bearer {key}", "apikey": key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if exc.code == 409:
                return "[]"
            raise RuntimeError(f"Supabase Storage bootstrap HTTP {exc.code}: {detail}") from exc

    def _probe_bucket(self, bucket: str) -> None:
        key = settings.SUPABASE_SERVICE_ROLE_KEY
        object_name = f"bootstrap/netra-bootstrap-probe-{uuid.uuid4().hex}.txt"
        url = f"{settings.SUPABASE_URL.rstrip('/')}/storage/v1/object/{bucket}/{object_name}"
        headers = {"Authorization": f"Bearer {key}", "apikey": key, "Content-Type": "text/plain", "x-upsert": "true"}
        upload = urllib.request.Request(url, method="POST", data=b"netra-bootstrap-probe", headers=headers)
        download = urllib.request.Request(url, method="GET", headers={"Authorization": f"Bearer {key}", "apikey": key})
        delete = urllib.request.Request(url, method="DELETE", headers={"Authorization": f"Bearer {key}", "apikey": key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(upload, timeout=30) as response:
                response.read()
            with urllib.request.urlopen(download, timeout=30) as response:
                content = response.read()
                if content != b"netra-bootstrap-probe":
                    raise RuntimeError(f"Supabase Storage bootstrap probe failed for {bucket}: content mismatch")
        finally:
            try:
                with urllib.request.urlopen(delete, timeout=30) as response:
                    response.read()
            except Exception:
                pass
