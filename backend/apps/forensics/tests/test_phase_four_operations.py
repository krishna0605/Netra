import json
from io import StringIO
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.management import call_command
from django.test import RequestFactory, SimpleTestCase, override_settings

from common.readiness import storage_cache_status_payload
from common.storage_cache import StorageCacheUnavailable
from common.storage_cache_middleware import StorageCacheFailureMiddleware
from common.vault import build_manifest_payload


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
