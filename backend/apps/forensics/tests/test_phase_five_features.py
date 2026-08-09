from pathlib import Path
from tempfile import TemporaryDirectory

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AnalysisReference, Case, CaseMembership, ProcessingJob, UserProfile
from apps.forensics.tests.factories import netra_organization


@override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_ENABLE_STRUCTURED_IMPORTS=True,
    NETRA_EVIDENCE_ENCRYPTION="on",
    NETRA_EVIDENCE_KEY="phase-five-feature-test-evidence-key",
    NETRA_EVIDENCE_KEY_ID="phase-five-test-key",
    NETRA_STORAGE_PROVIDER="local",
)
class PhaseFiveDurableFeatureTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        self.user = get_user_model().objects.create_user(username="phase5-features@example.test")
        UserProfile.objects.create(user=self.user, organization=self.organization, role="Investigator")
        token = str(RefreshToken.for_user(self.user).access_token)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        self.client = Client()
        self.case = Case.objects.create(
            id="CASE-PHASE5-FEATURES",
            organization=self.organization,
            display_reference="CASE-PHASE5-FEATURES",
            title="Original case title",
            investigator="Synthetic Investigator",
        )
        CaseMembership.objects.create(case=self.case, user=self.user, role="Investigator")
        self.job = ProcessingJob.objects.create(
            id="job-phase5-features",
            case=self.case,
            status=ProcessingJob.Status.COMPLETED,
            stats={
                "analysis": {
                    "packets": [{"id": "packet-1", "sourceIp": "192.0.2.1", "destinationIp": "198.51.100.2", "payload": "not copied"}],
                    "sessions": [],
                    "payloadFindings": [],
                }
            },
        )

    def test_analysis_reference_is_scoped_server_derived_and_idempotent(self):
        path = f"/api/workspaces/{self.case.route_ref}/analysis/jobs/{self.job.id}/references/packet"
        first = self.client.post(path, {"sourceReference": "packet-1"}, content_type="application/json", **self.headers)
        second = self.client.post(path, {"sourceReference": "packet-1"}, content_type="application/json", **self.headers)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(AnalysisReference.objects.count(), 1)
        self.assertNotIn("payload", first.json()["metadata"])

    def test_capture_log_import_creates_durable_encrypted_job_before_202(self):
        with TemporaryDirectory() as storage, self.settings(NETRA_STORAGE_ROOT=Path(storage)):
            path = f"/api/workspaces/{self.case.route_ref}/imports/capture-log"
            upload = SimpleUploadedFile(
                "firewall.log",
                b"2026-08-09 src=192.0.2.10 dst=198.51.100.20 action=deny protocol=tcp\n",
                content_type="text/plain",
            )
            response = self.client.post(path, {"file": upload}, HTTP_IDEMPOTENCY_KEY="capture-log-1", **self.headers)
            replay = self.client.post(path, {}, HTTP_IDEMPOTENCY_KEY="capture-log-1", **self.headers)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(replay.status_code, 202)
        self.assertEqual(response.json()["jobId"], replay.json()["jobId"])
        job = ProcessingJob.objects.get(pk=response.json()["jobId"])
        self.assertEqual(job.operation_kind, ProcessingJob.OperationKind.CAPTURE_LOG_IMPORT)
        self.assertTrue(job.evidence_file.stored_path)
        self.case.refresh_from_db()
        self.assertEqual(self.case.title, "Original case title")

    def test_invalid_import_has_no_durable_side_effect(self):
        with TemporaryDirectory() as storage, self.settings(NETRA_STORAGE_ROOT=Path(storage)):
            response = self.client.post(
                f"/api/workspaces/{self.case.route_ref}/imports/zeek-log",
                {"file": SimpleUploadedFile("unsafe.zip", b"PK", content_type="application/zip")},
                HTTP_IDEMPOTENCY_KEY="zeek-invalid-1",
                **self.headers,
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(ProcessingJob.objects.count(), 1)

