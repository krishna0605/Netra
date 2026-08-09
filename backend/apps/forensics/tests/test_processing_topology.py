from datetime import timedelta
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.forensics.models import WorkerHeartbeat
from common.worker_capacity import CAPACITY_CACHE_KEY, compatible_analysis_worker_available


@override_settings(
    NETRA_DEPLOYMENT_PROFILE="production",
    NETRA_PROCESSING_MODE="postgres-worker",
    NETRA_QUEUE_PROVIDER="postgres-row-lock",
    NETRA_RUNTIME_ROLE="api",
    NETRA_WORKER_CAPACITY_CACHE_SECONDS=0,
    NETRA_RATE_LIMITS_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=True,
)
class ProcessingTopologyTests(TestCase):
    @staticmethod
    def _details():
        return {
            "runtimeRole": "worker",
            "releaseId": "local-dev",
            "processingMode": "postgres-worker",
            "queueProvider": "postgres-row-lock",
            "capabilities": {
                "pcap": True,
                "pcapng": True,
                "structuredEvidence": True,
                "tshark": {"available": True, "version": "4.6.7"},
                "zeek": {"available": True, "version": "8.2.1"},
            },
        }

    def _upload(self):
        return self.client.post(
            "/api/evidence/upload",
            data={
                "caseId": "CASE-WORKER-ONLY",
                "evidenceType": "Auto-detect",
                "file": SimpleUploadedFile("synthetic.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20),
            },
            HTTP_X_NETRA_USER="worker-topology@example.test",
            HTTP_X_NETRA_ROLE="Investigator",
        )

    def test_missing_worker_capacity_rejects_before_storage_write(self):
        with patch("apps.forensics.views.save_uploaded_file") as save_uploaded:
            response = self._upload()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "analysis_capacity_unavailable")
        save_uploaded.assert_not_called()

    def test_only_recent_matching_worker_satisfies_capacity(self):
        WorkerHeartbeat.objects.create(
            worker_name="postgres-analysis",
            instance_id="stale",
            status="healthy",
            last_seen_at=timezone.now() - timedelta(minutes=10),
            details_json=self._details(),
        )
        self.assertFalse(compatible_analysis_worker_available())
        WorkerHeartbeat.objects.create(
            worker_name="postgres-analysis",
            instance_id="ready",
            status="healthy",
            last_seen_at=timezone.now(),
            details_json=self._details(),
        )
        self.assertTrue(compatible_analysis_worker_available())

    def test_api_module_has_no_direct_packet_analyzer_symbol(self):
        from apps.forensics import views

        self.assertFalse(hasattr(views, "analyze_pcap"))
