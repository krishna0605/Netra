from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken
from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, PcapNgWriter, PcapWriter

from apps.forensics.models import Case, ProcessingJob, UserProfile
from common.postgres_jobs import JobCancellationRequested, claim_next_job, mark_job_failure, request_job_cancellation


SECURE_GOLDEN_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_DEPLOYMENT_PROFILE="hackathon-core",
    NETRA_ENABLE_LAB_TOOLS=False,
    NETRA_PROCESSING_MODE="sync",
    NETRA_STORAGE_PROVIDER="local",
    NETRA_SEARCH_PROVIDER="postgres",
    NETRA_EVIDENCE_KEY="golden-path-test-evidence-key",
    NETRA_EVIDENCE_KEY_ID="golden-test-key-001",
)


@SECURE_GOLDEN_SETTINGS
class HackathonGoldenPathTests(TestCase):
    def setUp(self):
        self.client = Client()
        user = get_user_model().objects.create_user(
            username="golden-investigator@example.test",
            email="golden-investigator@example.test",
            password="unused-test-password",
        )
        UserProfile.objects.create(user=user, role="Investigator", display_name="Golden Investigator")
        token = str(RefreshToken.for_user(user).access_token)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    @staticmethod
    def _packets():
        packets = [
            Ether() / IP(src="10.10.1.5", dst="192.0.2.10") / TCP(sport=41000, dport=22, flags="S"),
            Ether() / IP(src="10.10.1.5", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="netra.example")),
            Ether() / IP(src="10.10.1.6", dst="198.51.100.20") / TCP(sport=42000, dport=443, flags="S"),
        ]
        for index, packet in enumerate(packets):
            packet.time = 1_720_000_000 + index
        return packets

    def _capture_bytes(self, capture_format: str) -> bytes:
        with tempfile.TemporaryDirectory(prefix="netra-fixture-") as folder:
            path = Path(folder) / f"golden.{capture_format}"
            if capture_format == "pcapng":
                writer = PcapNgWriter(str(path))
            else:
                writer = PcapWriter(str(path), sync=True)
            try:
                for packet in self._packets():
                    writer.write(packet)
            finally:
                writer.close()
            return path.read_bytes()

    @patch("apps.forensics.views.publish_event", return_value=True)
    def test_real_pcap_upload_filters_ml_persistence_and_pdf_report(self, _publish):
        with tempfile.TemporaryDirectory(prefix="netra-golden-storage-") as storage:
            with self.settings(NETRA_STORAGE_ROOT=Path(storage)):
                upload = self.client.post(
                    "/api/evidence/upload",
                    data={
                        "caseId": "CASE-GOLDEN-PCAP",
                        "evidenceType": "Auto-detect",
                        "investigator": "Golden Investigator",
                        "department": "Hackathon QA",
                        "sourceLocation": "Synthetic authorized fixture",
                        "priority": "High",
                        "remarks": "Golden-path release verification",
                        "flags": '["synthetic", "release-gate"]',
                        "sourceIp": "10.10.1.5",
                        "protocol": "TCP",
                        "port": "22",
                        "packetLimit": "2",
                        "file": SimpleUploadedFile(
                            "golden.pcap",
                            self._capture_bytes("pcap"),
                            content_type="application/vnd.tcpdump.pcap",
                        ),
                    },
                    **self.headers,
                )

                self.assertEqual(upload.status_code, 201, upload.content)
                payload = upload.json()
                self.assertEqual(payload["status"], "verified")
                self.assertEqual(payload["normalization"]["detectedType"], "PCAP")
                self.assertEqual(payload["normalization"]["parser"], "pcap")
                self.assertEqual(payload["analysis"]["packets"], 1)
                self.assertIn("anomalies", payload["analysis"])
                self.assertNotIn("analysis_path", payload)
                self.assertNotIn("stored_path", payload)

                case = Case.objects.get(pk="CASE-GOLDEN-PCAP")
                self.assertEqual(case.department, "Hackathon QA")
                self.assertEqual(case.flags_json, ["synthetic", "release-gate"])
                job = ProcessingJob.objects.get(pk=payload["jobId"])
                analysis = job.stats["analysis"]
                self.assertEqual(analysis["indexedPackets"], 1)
                self.assertEqual(analysis["packets"][0]["sourceIp"], "10.10.1.5")
                self.assertEqual(analysis["packets"][0]["destinationPort"], 22)
                self.assertEqual(analysis["packets"][0]["transportProtocol"], "TCP")
                self.assertEqual(analysis["packets"][0]["protocol"], "SSH")
                self.assertIn("features", analysis)
                self.assertIn("anomalies", analysis)

                report = self.client.post(
                    "/api/reports/CASE-GOLDEN-PCAP/generate-pdf",
                    data={"language": "English", "format": "pdf"},
                    content_type="application/json",
                    **self.headers,
                )
                self.assertEqual(report.status_code, 201, report.content)
                report_payload = report.json()
                self.assertEqual(report_payload["status"], "ready")
                download = self.client.get(report_payload["downloadUrl"], **self.headers)
                self.assertEqual(download.status_code, 200)
                self.assertTrue(download.content.startswith(b"%PDF"))

    @patch("apps.forensics.views.publish_event", return_value=True)
    def test_real_pcapng_is_auto_detected_and_analyzed(self, _publish):
        with tempfile.TemporaryDirectory(prefix="netra-golden-storage-") as storage:
            with self.settings(NETRA_STORAGE_ROOT=Path(storage)):
                response = self.client.post(
                    "/api/evidence/upload",
                    data={
                        "caseId": "CASE-GOLDEN-PCAPNG",
                        "evidenceType": "Auto-detect",
                        "file": SimpleUploadedFile(
                            "golden.pcapng",
                            self._capture_bytes("pcapng"),
                            content_type="application/x-pcapng",
                        ),
                    },
                    **self.headers,
                )

                self.assertEqual(response.status_code, 201, response.content)
                payload = response.json()
                self.assertEqual(payload["normalization"]["detectedType"], "PCAP")
                self.assertIn("magic:pcapng", payload["normalization"]["signals"])
                self.assertEqual(payload["analysis"]["packets"], 3)

    def test_bpf_is_rejected_when_offline_filtering_is_disabled(self):
        with self.settings(NETRA_BPF_FILTER_ENABLED=False):
            response = self.client.post(
                "/api/evidence/upload",
                data={
                    "caseId": "CASE-BPF-DISABLED",
                    "evidenceType": "Auto-detect",
                    "bpfFilter": "tcp port 22",
                    "file": SimpleUploadedFile(
                        "golden.pcap",
                        self._capture_bytes("pcap"),
                        content_type="application/vnd.tcpdump.pcap",
                    ),
                },
                **self.headers,
            )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["code"], "bpf_filter_unavailable")
        self.assertFalse(Case.objects.filter(pk="CASE-BPF-DISABLED").exists())

    def test_durable_upload_is_idempotent_leased_and_cancelable(self):
        with tempfile.TemporaryDirectory(prefix="netra-durable-storage-") as storage:
            with self.settings(
                NETRA_PROCESSING_MODE="postgres-worker",
                NETRA_STORAGE_ROOT=Path(storage),
                NETRA_WORKER_MAX_RETRIES=3,
            ):
                request_data = {
                    "caseId": "CASE-DURABLE-PCAP",
                    "evidenceType": "Auto-detect",
                    "idempotencyKey": "durable-upload-1",
                }
                first = self.client.post(
                    "/api/evidence/upload",
                    data=request_data
                    | {
                        "file": SimpleUploadedFile(
                            "durable.pcap",
                            self._capture_bytes("pcap"),
                            content_type="application/vnd.tcpdump.pcap",
                        )
                    },
                    **self.headers,
                )
                replay = self.client.post(
                    "/api/evidence/upload",
                    data=request_data
                    | {
                        "file": SimpleUploadedFile(
                            "durable.pcap",
                            self._capture_bytes("pcap"),
                            content_type="application/vnd.tcpdump.pcap",
                        )
                    },
                    **self.headers,
                )

                self.assertEqual(first.status_code, 202, first.content)
                self.assertEqual(replay.status_code, 202, replay.content)
                self.assertEqual(replay.json()["jobId"], first.json()["jobId"])
                self.assertTrue(replay.json()["idempotentReplay"])
                self.assertEqual(ProcessingJob.objects.count(), 1)

                claimed = claim_next_job("test-worker")
                self.assertIsNotNone(claimed)
                self.assertEqual(claimed.status, ProcessingJob.Status.RUNNING)
                self.assertEqual(claimed.attempt_count, 1)

                request_job_cancellation(claimed.id)
                canceled = mark_job_failure(claimed.id, "test-worker", JobCancellationRequested("cancel"))
                self.assertEqual(canceled.status, ProcessingJob.Status.CANCELED)

    def test_supabase_multipart_upload_uses_v2_chunks_without_persisting_internal_manifest(self):
        with tempfile.TemporaryDirectory(prefix="netra-v2-upload-") as temporary_root:
            encrypted = {
                "stored_path": "supabase://netra-evidence/v2/ev-test/manifest.v2.json",
                "size_bytes": len(self._capture_bytes("pcap")),
                "sha256": "a" * 64,
                "plaintext_sha256": "a" * 64,
                "encrypted_sha256": "b" * 64,
                "encryption_algorithm": "AES-256-GCM-chunked-v2",
                "key_id": "golden-test-key-001",
                "v2_manifest": {"wrappedDataKey": "internal-only"},
            }
            with self.settings(
                NETRA_STORAGE_PROVIDER="supabase",
                NETRA_PROCESSING_MODE="postgres-worker",
                NETRA_TEMP_ROOT=Path(temporary_root),
            ), patch("common.storage.encrypt_evidence_v2", return_value=encrypted) as encrypt_v2:
                response = self.client.post(
                    "/api/evidence/upload",
                    data={
                        "caseId": "CASE-V2-MULTIPART",
                        "evidenceType": "Auto-detect",
                        "file": SimpleUploadedFile(
                            "v2.pcap",
                            self._capture_bytes("pcap"),
                            content_type="application/vnd.tcpdump.pcap",
                        ),
                    },
                    **self.headers,
                )

        self.assertEqual(response.status_code, 202, response.content)
        payload = response.json()
        job = ProcessingJob.objects.get(pk=payload["jobId"])
        encrypt_v2.assert_called_once()
        self.assertTrue(job.evidence_file.stored_path.endswith("/manifest.v2.json"))
        self.assertNotIn("v2_manifest", job.stats["saved"])
        self.assertNotIn("v2_manifest", payload)

    def test_mixed_structured_evidence_runs_the_analysis_flow(self):
        records = [
            {
                "timestamp": "2026-07-14T10:00:00Z", "src_ip": "10.0.0.5", "dst_ip": "203.0.113.10", "action": "allow",
                "qname": "login.example.test", "query": "login.example.test", "dns": True, "rrtype": "A", "rcode": "NOERROR",
                "sni": "login.example.test", "ja3": "demo", "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "handshake": "client_hello",
                "dst_port": 443, "protocol": "TCP", "bytes": 900,
            },
            {"timestamp": "2026-07-14T10:00:01Z", "client_ip": "10.0.0.5", "resolver_ip": "10.0.0.53", "qname": "dns.example.test", "dst_port": 53, "protocol": "UDP"},
            {"timestamp": "2026-07-14T10:00:02Z", "source_ip": "10.0.0.9", "destination_ip": "198.51.100.20", "action": "deny", "destination_port": 22, "protocol": "TCP"},
        ]
        with tempfile.TemporaryDirectory(prefix="netra-structured-storage-") as storage:
            with self.settings(NETRA_STORAGE_ROOT=Path(storage)):
                response = self.client.post(
                    "/api/evidence/upload",
                    data={
                        "caseId": "CASE-MIXED-EVIDENCE",
                        "evidenceType": "Auto-detect",
                        "file": SimpleUploadedFile("mixed.json", json.dumps(records).encode("utf-8"), content_type="application/json"),
                    },
                    **self.headers,
                )

        self.assertEqual(response.status_code, 201, response.content)
        payload = response.json()
        self.assertEqual(payload["normalization"]["normalizedType"], "Mixed Evidence")
        job = ProcessingJob.objects.get(pk=payload["jobId"])
        structured = job.stats["analysis"]["structuredEvidence"]
        self.assertEqual(structured["acceptedCount"], 3)
        self.assertEqual(set(structured["recordTypes"]), {"Firewall Logs", "DNS Logs", "TLS Metadata"})
