import json
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.management import call_command
from django.test import RequestFactory, SimpleTestCase, override_settings

from common.readiness import storage_cache_status_payload
from common.storage_cache import StorageCacheUnavailable
from common.storage_cache_middleware import StorageCacheFailureMiddleware
from common.vault import build_manifest_payload
from apps.forensics.management.commands.export_supabase_data_manifest import Command as DataManifestCommand
from apps.forensics.management.commands.export_supabase_schema_manifest import Command as SchemaManifestCommand


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


class PhaseFourOperationalGapTests(SimpleTestCase):
    @override_settings(NETRA_EVIDENCE_ENCRYPTION="on")
    def test_encrypted_manifest_requires_explicit_versioned_algorithm(self):
        saved = {
            "filename": "synthetic.pcap",
            "stored_path": "local://synthetic",
            "size_bytes": 1,
            "plaintext_sha256": "a" * 64,
            "encrypted_sha256": "b" * 64,
        }
        with self.assertRaisesRegex(ValueError, "versioned encryption algorithm"):
            build_manifest_payload(saved, "evidence-1", "CASE-1")

    def test_cache_failure_middleware_returns_stable_503(self):
        request = RequestFactory().get("/api/reports/report-1/download", HTTP_X_REQUEST_ID="phase4-cache")
        middleware = StorageCacheFailureMiddleware(lambda _request: None)
        response = middleware.process_exception(request, StorageCacheUnavailable("private detail"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(json.loads(response.content)["error"]["code"], "storage_cache_unavailable")
        self.assertNotContains(response, "private detail", status_code=503)

    def test_cache_readiness_fails_closed_without_exposing_exception(self):
        with patch("common.readiness.storage_cache.status", side_effect=OSError("sensitive filesystem detail")):
            payload = storage_cache_status_payload()
        self.assertFalse(payload["available"])
        self.assertNotIn("sensitive filesystem detail", str(payload))

    def test_best_effort_startup_reports_degradation_and_exits_successfully(self):
        output = StringIO()
        with TemporaryDirectory(), patch(
            "apps.forensics.management.commands.maintain_storage_cache.storage_cache.prune",
            side_effect=OSError("cache unavailable"),
        ):
            call_command("maintain_storage_cache", startup=True, best_effort=True, json=True, stdout=output)
        self.assertIn('"available": false', output.getvalue())


class HostedActivationContractTests(SimpleTestCase):
    def test_schema_manifests_default_to_current_table_count(self):
        schema_options = SchemaManifestCommand().create_parser("manage.py", "export_supabase_schema_manifest").parse_args([])
        data_options = DataManifestCommand().create_parser("manage.py", "export_supabase_data_manifest").parse_args([])

        self.assertEqual(schema_options.require_count, 53)
        self.assertEqual(data_options.require_count, 53)

    def test_production_compose_uses_bearer_auth_and_supervised_bootstrap(self):
        compose = (REPOSITORY_ROOT / "infra" / "docker" / "compose.netra-production.yml").read_text(encoding="utf-8")

        self.assertIn("NETRA_ACCESS_MODE: bearer", compose)
        self.assertNotIn("NETRA_ACCESS_MODE: supabase-auth", compose)
        self.assertNotIn("bootstrap_supabase", compose)
        self.assertIn("python manage.py check --deploy", compose)
        self.assertIn("python manage.py migrate --noinput", compose)
