from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.forensics.models import WorkerHeartbeat
from common.parser_runner import ParserResult
from common.tool_capabilities import capability_failures, worker_capabilities
from common.worker_capacity import compatible_analysis_worker_available


class ToolCapabilityDiscoveryTests(SimpleTestCase):
    def tearDown(self):
        worker_capabilities.cache_clear()

    @patch("common.tool_capabilities.run_parser")
    def test_exact_versions_are_parsed(self, run_parser_mock):
        run_parser_mock.side_effect = [
            ParserResult(0, "TShark (Wireshark) 4.6.7", ""),
            ParserResult(0, "zeek version 8.2.1", ""),
        ]
        worker_capabilities.cache_clear()
        capabilities = worker_capabilities()
        self.assertEqual(capabilities["tshark"]["version"], "4.6.7")
        self.assertEqual(capabilities["zeek"]["version"], "8.2.1")
        self.assertEqual(capability_failures(capabilities), [])

    def test_mismatched_tool_fails_capability_contract(self):
        capabilities = {
            "tshark": {"available": True, "version": "4.6.6"},
            "zeek": {"available": True, "version": "8.2.1"},
        }
        self.assertEqual(capability_failures(capabilities), ["tshark"])


@override_settings(
    NETRA_WORKER_CAPACITY_CACHE_SECONDS=0,
    NETRA_REQUIRED_TSHARK_VERSION="4.6.7",
    NETRA_REQUIRED_ZEEK_VERSION="8.2.1",
    NETRA_REQUIRE_WORKER_RELEASE_MATCH=True,
    NETRA_RELEASE_ID="phase4-release",
)
class WorkerAdmissionCapabilityTests(TestCase):
    def test_wrong_release_or_version_does_not_satisfy_admission(self):
        WorkerHeartbeat.objects.create(
            worker_name="postgres-analysis",
            instance_id="wrong-version",
            status="healthy",
            last_seen_at=timezone.now(),
            details_json={
                "runtimeRole": "worker",
                "releaseId": "phase4-release",
                "processingMode": "postgres-worker",
                "queueProvider": "postgres-row-lock",
                "capabilities": {
                    "pcap": True,
                    "pcapng": True,
                    "tshark": {"available": True, "version": "4.6.6"},
                    "zeek": {"available": True, "version": "8.2.1"},
                },
            },
        )
        self.assertFalse(compatible_analysis_worker_available())
