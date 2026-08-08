from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import Case, UserProfile
from common.identifiers import InvalidCaseId, validate_case_id
from common.safe_paths import UnsafeArtifactPath
from common.storage import write_binary_artifact, write_text_artifact


SECURE_TEST_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
)


class IdentifierValidationTests(SimpleTestCase):
    def test_accepts_existing_case_identifier_shape(self):
        self.assertEqual(validate_case_id("CYB-GJ-2026-ABC12345"), "CYB-GJ-2026-ABC12345")
        self.assertEqual(validate_case_id("CASE_under-score"), "CASE_under-score")

    def test_rejects_path_and_platform_edge_cases(self):
        invalid_values = [
            "../CASE",
            "..\\CASE",
            "/var/tmp/CASE",
            "C:\\tmp\\CASE",
            "\\\\server\\share\\CASE",
            "%2e%2e%2fCASE",
            "CASE/../OTHER",
            "CASE\\..\\OTHER",
            ".",
            "CASE.NULL\x00",
            "CASE\nOTHER",
            "CASE.",
            "CASE ",
            "AB",
            "A" * 65,
        ]
        for value in invalid_values:
            with self.subTest(value=repr(value)), self.assertRaises(InvalidCaseId):
                validate_case_id(value)


@SECURE_TEST_SETTINGS
class CaseIdentifierRequestTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = get_user_model().objects.create_user(
            username="artifact-security@example.test",
            email="artifact-security@example.test",
            password="unused-test-password",
        )
        UserProfile.objects.create(user=self.user, role="Investigator", display_name="Artifact Security")
        token = str(RefreshToken.for_user(self.user).access_token)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def test_case_creation_rejects_invalid_identifier_without_truncation(self):
        response = self.client.post(
            "/api/cases",
            data={"caseNumber": "../CASE-ESCAPE", "title": "Must not exist"},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_case_id")
        self.assertFalse(Case.objects.exists())

    def test_evidence_upload_rejects_invalid_case_before_storage_write(self):
        with TemporaryDirectory() as temporary_directory, override_settings(
            NETRA_STORAGE_ROOT=Path(temporary_directory) / "storage",
            NETRA_TEMP_ROOT=Path(temporary_directory) / "temp",
        ), patch("apps.forensics.views.save_uploaded_file") as save_uploaded:
            response = self.client.post(
                "/api/evidence/upload",
                data={
                    "caseId": "C:\\outside\\CASE",
                    "file": SimpleUploadedFile("evidence.pcap", b"not-written"),
                },
                **self.headers,
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["code"], "invalid_case_id")
            save_uploaded.assert_not_called()
            self.assertFalse(Case.objects.exists())
            self.assertEqual(list(Path(temporary_directory).rglob("*")), [])


class ArtifactPathContainmentTests(SimpleTestCase):
    def test_rejects_cross_platform_and_encoded_artifact_paths(self):
        invalid_names = [
            "../report.html",
            "..\\report.html",
            "/tmp/report.html",
            "C:\\tmp\\report.html",
            "\\\\server\\share\\report.html",
            "%2e%2e%2freport.html",
            "nested/report.html",
            "nested\\report.html",
            "report..html",
            "report.html.",
            "report.html ",
            "report\x00.html",
            "r" * 252 + ".html",
            "report.exe",
        ]
        with TemporaryDirectory() as temporary_directory, override_settings(
            NETRA_STORAGE_ROOT=Path(temporary_directory) / "storage"
        ):
            for filename in invalid_names:
                with self.subTest(filename=repr(filename)), self.assertRaises((UnsafeArtifactPath, ValueError)):
                    write_text_artifact("sensitive", "report", filename)
            files = [path for path in Path(temporary_directory).rglob("*") if path.is_file()]
            self.assertEqual(files, [])

    def test_valid_artifacts_leave_only_encrypted_contained_files(self):
        with TemporaryDirectory() as temporary_directory, override_settings(
            NETRA_STORAGE_ROOT=Path(temporary_directory) / "storage"
        ):
            text_result = write_text_artifact("report text", "report", "rpt-abc123.html")
            binary_result = write_binary_artifact(b"%PDF-test", "report", "rpt-def456.pdf")
            report_folder = (Path(temporary_directory) / "storage" / "reports").resolve()
            files = [path.resolve() for path in report_folder.iterdir() if path.is_file()]

            self.assertEqual(text_result["filename"], "rpt-abc123.html")
            self.assertEqual(binary_result["filename"], "rpt-def456.pdf")
            self.assertEqual({path.name for path in files}, {"rpt-abc123.html.enc", "rpt-def456.pdf.enc"})
            self.assertTrue(all(path.parent == report_folder for path in files))
            self.assertFalse(any(path.suffix == ".tmp" for path in files))
