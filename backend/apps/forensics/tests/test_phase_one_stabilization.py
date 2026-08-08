import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import RequestFactory, TestCase, override_settings

from apps.forensics.api.errors import api_error
from apps.forensics.management.commands.run_netra_worker import Command
from apps.forensics.models import Case, Report
from common.artifacts import generate_pdf_report_artifact, generate_report_artifact
from common.audit import Actor


class RequestIdSafetyTests(TestCase):
    def test_invalid_request_ids_are_replaced_before_response_header_assignment(self):
        request = RequestFactory().get("/api/test", HTTP_X_REQUEST_ID="unsafe\r\nInjected: true")

        response = api_error(request, "test_error", "Test error", status=400)

        request_id = response["X-Request-ID"]
        self.assertRegex(request_id, r"^[0-9a-f]{32}$")
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(payload["error"]["requestId"], request_id)

    def test_valid_request_id_is_preserved(self):
        request = RequestFactory().get("/api/test", HTTP_X_REQUEST_ID="req-2026.valid:01")

        response = api_error(request, "test_error", "Test error", status=400)

        self.assertEqual(response["X-Request-ID"], "req-2026.valid:01")


class QueuedReportIdentityTests(TestCase):
    def setUp(self):
        self.case = Case.objects.create(id="CASE-QUEUED-REPORT", title="Queued report", investigator="Worker")
        self.actor = Actor("Netra report worker", "System", authenticated=True)
        self.analysis = {
            "caseId": self.case.id,
            "summary": {"packets": 0, "sessions": 0, "alerts": 0, "anomalies": 0},
            "alerts": [],
            "anomalies": [],
            "evidence": {},
        }

    def test_html_and_pdf_preserve_the_server_issued_report_id(self):
        with TemporaryDirectory() as temporary_directory, override_settings(
            NETRA_STORAGE_ROOT=Path(temporary_directory) / "storage"
        ):
            html_id = "rpt-11111111111111111111111111111111.html"
            pdf_id = "rpt-22222222222222222222222222222222.pdf"
            Report.objects.create(id=html_id, case=self.case, status="queued")
            Report.objects.create(id=pdf_id, case=self.case, status="queued")

            html = generate_report_artifact(self.case.id, "en", self.analysis, self.actor, report_id=html_id)
            pdf = generate_pdf_report_artifact(self.case.id, "en", self.analysis, self.actor, report_id=pdf_id)

        self.assertEqual(html["id"], html_id)
        self.assertEqual(pdf["id"], pdf_id)
        self.assertEqual(Report.objects.get(pk=html_id).status, "ready")
        self.assertEqual(Report.objects.get(pk=pdf_id).status, "ready")
        self.assertEqual(Report.objects.filter(case=self.case).count(), 2)

    def test_report_id_format_and_extension_are_enforced(self):
        with TemporaryDirectory() as temporary_directory, override_settings(
            NETRA_STORAGE_ROOT=Path(temporary_directory) / "storage"
        ):
            with self.assertRaises(ValueError):
                generate_report_artifact(
                    self.case.id,
                    "en",
                    self.analysis,
                    self.actor,
                    report_id="../../caller-report.html",
                )
            with self.assertRaises(ValueError):
                generate_report_artifact(
                    self.case.id,
                    "en",
                    self.analysis,
                    self.actor,
                    report_id="rpt-33333333333333333333333333333333.pdf",
                )


class QueuedReportWorkerDispatchTests(TestCase):
    @patch("apps.forensics.management.commands.run_netra_worker.emit_operational_event")
    @patch("apps.forensics.management.commands.run_netra_worker.publish_event")
    @patch("apps.forensics.management.commands.run_netra_worker.analysis_for_case", return_value={"summary": {}})
    @patch("apps.forensics.management.commands.run_netra_worker.generate_pdf_report_artifact")
    @patch("apps.forensics.management.commands.run_netra_worker.generate_report_artifact")
    def test_worker_dispatches_html_and_pdf_with_the_server_report_id(
        self,
        generate_html,
        generate_pdf,
        _analysis,
        _publish,
        _emit,
    ):
        html_id = "rpt-11111111111111111111111111111111.html"
        pdf_id = "rpt-22222222222222222222222222222222.pdf"
        generate_html.return_value = {"filename": html_id}
        generate_pdf.return_value = {"filename": pdf_id}
        command = Command()

        command._report_export(
            {"type": "report.generate", "caseId": "CASE-HTML", "format": "html", "reportId": html_id}
        )
        command._report_export(
            {"type": "report.generate", "caseId": "CASE-PDF", "format": "pdf", "reportId": pdf_id}
        )

        generate_html.assert_called_once()
        self.assertEqual(generate_html.call_args.kwargs["report_id"], html_id)
        generate_pdf.assert_called_once()
        self.assertEqual(generate_pdf.call_args.kwargs["report_id"], pdf_id)

    @patch("apps.forensics.management.commands.run_netra_worker.analysis_for_case", return_value={"summary": {}})
    def test_worker_rejects_an_unknown_report_format(self, _analysis):
        with self.assertRaisesMessage(ValueError, "Unsupported queued report format"):
            Command()._report_export(
                {"type": "report.generate", "caseId": "CASE-BAD", "format": "docx"}
            )
