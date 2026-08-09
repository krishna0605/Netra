from __future__ import annotations

from pathlib import Path

from django.contrib.auth import get_user_model
from django.db import connection
from django.http import Http404
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.api import analysis as analysis_module
from apps.forensics.api import legacy_views
from apps.forensics.models import Alert, Case, CaseHistoryEvent, CaseMembership, CustodyLedgerEvent, DetectionMatch, ProcessingJob, UserProfile
from apps.forensics.urls import urlpatterns as api_urlpatterns
from apps.forensics.tests.factories import netra_organization


SECURE_TEST_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
)


def analysis_document(case_id: str, marker: str) -> dict:
    return {
        "caseId": case_id,
        "summary": {"packets": 1, "sessions": 1, "alerts": 1},
        "case": {"id": case_id},
        "evidence": {"id": f"evidence-{marker}"},
        "trafficTimeline": [{"time": "2026-08-08T00:00:00Z", "alerts": 1}],
        "protocolChartData": [{"name": "TCP", "value": 1}],
        "packets": [{"id": "shared-packet", "sourceIp": marker, "destinationIp": "10.0.0.2", "protocol": "TCP", "sourcePort": 1, "destinationPort": 2}],
        "sessions": [{"id": "shared-session", "source": marker, "destination": "10.0.0.2", "protocol": "TCP", "packetCount": 1, "startTime": "start", "endTime": "end"}],
        "decodedProtocols": [{"id": "shared-decoder", "protocol": "HTTP", "marker": marker}],
        "payloadFindings": [{"id": "shared-payload", "protocol": "HTTP", "risk": "high", "marker": marker}],
        "alerts": [{"id": "shared-alert", "ruleId": "shared-rule", "status": "new", "marker": marker}],
        "detectionMatches": [{"id": "shared-detection", "ruleId": "shared-rule", "ruleName": "Shared rule", "category": "Test", "status": "new", "marker": marker}],
        "anomalies": [{"id": "shared-anomaly", "behaviour": "test", "baseline": "normal", "observed": marker, "confidence": 50}],
        "graph": {
            "nodes": [{"id": "shared-node", "risk": 50, "alertIds": ["shared-alert"], "marker": marker}],
            "edges": [{"source": marker, "target": "10.0.0.2"}],
        },
    }


@SECURE_TEST_SETTINGS
class AnalysisCaseBoundaryTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.alice, self.alice_headers = self._user("alice-analysis@example.test", "Investigator")
        self.bob, _ = self._user("bob-analysis@example.test", "Investigator")
        self.alice_case = self._case("CASE-ALICE-SCOPE", self.alice)
        self.bob_case = self._case("CASE-BOB-SCOPE", self.bob)
        self.alice_job = self._job("job-alice-scope", self.alice_case, "alice")
        self.bob_job = self._job("job-bob-scope", self.bob_case, "bob")
        self._findings(self.alice_case, self.alice_job)
        self._findings(self.bob_case, self.bob_job)

    def _user(self, email: str, role: str):
        user = get_user_model().objects.create_user(username=email, email=email, password="unused-test-password")
        UserProfile.objects.create(user=user, organization=netra_organization(), role=role, display_name=email)
        token = str(RefreshToken.for_user(user).access_token)
        return user, {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _case(self, case_id: str, user):
        case = Case.objects.create(
            id=case_id,
            organization=netra_organization(),
            display_reference=case_id,
            title=case_id,
            investigator=user.email,
        )
        CaseMembership.objects.create(case=case, user=user, role="Investigator")
        return case

    def _job(self, job_id: str, case: Case, marker: str, status=ProcessingJob.Status.COMPLETED):
        return ProcessingJob.objects.create(
            id=job_id,
            case=case,
            status=status,
            stats={"analysis": analysis_document(case.id, marker)},
        )

    def _findings(self, case: Case, job: ProcessingJob):
        Alert.objects.create(
            id=f"{job.id}-shared-alert",
            case=case,
            severity="high",
            attack_class="Test",
            alert_type="Test alert",
            source_ip="10.0.0.1",
            destination="10.0.0.2",
            protocol="TCP",
            status="new",
        )
        DetectionMatch.objects.create(
            id=f"{job.id}-shared-detection",
            case=case,
            rule_id="shared-rule",
            rule_name="Shared rule",
            category="Test",
            matched_entity="10.0.0.1",
            status="new",
        )

    def _prefix(self, case: Case, job: ProcessingJob) -> str:
        return f"/api/workspaces/{case.route_ref}/analysis/jobs/{job.id}"

    def test_canonical_routes_hide_another_cases_analysis(self):
        prefix = self._prefix(self.bob_case, self.bob_job)
        paths = (
            f"{prefix}/summary",
            f"{prefix}/packets/shared-packet",
            f"{prefix}/sessions/shared-session",
            f"{prefix}/sessions/shared-session/timeline",
            f"{prefix}/decoder/HTTP",
            f"{prefix}/payloads/shared-payload",
            f"{prefix}/graph/nodes/shared-node",
            f"{prefix}/graph/attack-path",
        )
        for path in paths:
            response = self.client.get(path, **self.alice_headers)
            self.assertEqual(response.status_code, 404, path)
            self.assertEqual(response.json()["error"]["code"], "analysis_resource_not_found")

    def test_analysis_route_inventory_is_explicit_and_scoped(self):
        expected_canonical = {
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/summary",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/traffic-timeline",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/protocol-distribution",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/alerts",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/alerts/<str:alert_id>/status",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/packets",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/packets/<str:packet_id>",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/sessions",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/sessions/<str:session_id>",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/sessions/<str:session_id>/timeline",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/decoder",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/decoder/<str:protocol>",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/payloads",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/payloads/<str:finding_id>",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/detections",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/detections/<str:match_id>/status",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/anomalies",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/anomalies/baseline-comparison",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/anomalies/risk-timeline",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/graph",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/graph/nodes/<str:node_id>",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/graph/attack-path",
        }
        expected_feature_routes = {
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/references/<str:kind>",
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/search",
        }
        expected_integration_routes = {
            "workspaces/<uuid:route_ref>/analysis/jobs/<str:job_id>/integrations/<str:integration_id>/alerts",
        }
        canonical_patterns = {
            str(pattern.pattern)
            for pattern in api_urlpatterns
            if "/analysis/jobs/" in str(pattern.pattern)
        }
        self.assertEqual(canonical_patterns, expected_canonical | expected_feature_routes | expected_integration_routes)
        for pattern in api_urlpatterns:
            if str(pattern.pattern) in expected_canonical:
                self.assertEqual(pattern.callback.__module__, "apps.forensics.api.analysis")
            elif str(pattern.pattern) in expected_feature_routes:
                self.assertEqual(pattern.callback.__module__, "apps.forensics.api.features")
            elif str(pattern.pattern) in expected_integration_routes:
                self.assertEqual(pattern.callback.__module__, "apps.forensics.api.integrations")

    def test_canonical_read_routes_reject_non_get_methods(self):
        path = f"{self._prefix(self.alice_case, self.alice_job)}/packets"
        self.assertEqual(self.client.get(path, **self.alice_headers).status_code, 200)
        self.assertEqual(self.client.post(path, data={}, content_type="application/json", **self.alice_headers).status_code, 405)

    def test_scope_query_uses_case_and_job_without_cross_case_job_lookup(self):
        allowed_path = f"{self._prefix(self.alice_case, self.alice_job)}/packets/shared-packet"
        with CaptureQueriesContext(connection) as allowed_queries:
            response = self.client.get(allowed_path, **self.alice_headers)
        self.assertEqual(response.status_code, 200)
        job_queries = [query["sql"] for query in allowed_queries.captured_queries if "forensics_processingjob" in query["sql"].lower()]
        self.assertEqual(len(job_queries), 1)
        self.assertIn("case_id", job_queries[0].lower())
        self.assertIn(self.alice_job.id, job_queries[0])

        denied_path = f"{self._prefix(self.bob_case, self.bob_job)}/packets/shared-packet"
        with CaptureQueriesContext(connection) as denied_queries:
            denied = self.client.get(denied_path, **self.alice_headers)
        self.assertEqual(denied.status_code, 404)
        denied_job_queries = [query["sql"] for query in denied_queries.captured_queries if "forensics_processingjob" in query["sql"].lower()]
        self.assertEqual(denied_job_queries, [])

    def test_workspace_and_job_must_belong_to_each_other(self):
        prefix = self._prefix(self.alice_case, self.bob_job)
        response = self.client.get(f"{prefix}/packets/shared-packet", **self.alice_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "analysis_resource_not_found")

    def test_duplicate_resource_ids_resolve_only_inside_selected_job(self):
        prefix = self._prefix(self.alice_case, self.alice_job)
        response = self.client.get(f"{prefix}/packets/shared-packet", **self.alice_headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["sourceIp"], "alice")

    def test_non_completed_job_returns_analysis_not_ready(self):
        queued = self._job("job-alice-queued", self.alice_case, "queued", status=ProcessingJob.Status.QUEUED)
        response = self.client.get(f"{self._prefix(self.alice_case, queued)}/summary", **self.alice_headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "analysis_not_ready")

    def test_legacy_route_requires_workspace_and_job_scope(self):
        missing = self.client.get("/api/packets/shared-packet", **self.alice_headers)
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.json()["error"]["code"], "analysis_scope_required")

        allowed = self.client.get(
            f"/api/packets/shared-packet?caseRef={self.alice_case.route_ref}&jobId={self.alice_job.id}",
            **self.alice_headers,
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed["Deprecation"], "true")
        self.assertEqual(allowed.json()["sourceIp"], "alice")

    def test_legacy_route_cannot_use_another_cases_scope(self):
        response = self.client.get(
            f"/api/graph/nodes/shared-node?caseRef={self.bob_case.route_ref}&jobId={self.bob_job.id}",
            **self.alice_headers,
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["error"]["code"], "analysis_resource_not_found")

    def test_admin_legacy_route_does_not_select_global_latest_job(self):
        _admin, admin_headers = self._user("admin-analysis@example.test", "Admin")
        response = self.client.get("/api/dashboard/summary", **admin_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "analysis_scope_required")

    def test_investigator_legacy_route_does_not_fall_back_to_most_recent_case(self):
        """An unscoped compatibility read must never resolve an implicit case.

        The retired helper selected the most recently updated visible case, so an
        investigator with more than one case silently received whichever case had
        been touched last.
        """
        second_case = self._case("CASE-ALICE-SECOND", self.alice)
        second_job = self._job("job-alice-second", second_case, "alice-second")
        self._findings(second_case, second_job)

        for path in ("/api/dashboard/summary", "/api/packets", "/api/graph", "/api/anomalies"):
            with self.subTest(path=path):
                response = self.client.get(path, **self.alice_headers)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "analysis_scope_required")
                self.assertNotIn("alice-second", response.content.decode())

    def test_cross_case_alert_mutation_has_no_side_effects(self):
        before_bob = self.bob_job.stats
        before_history = CaseHistoryEvent.objects.count()
        before_custody = CustodyLedgerEvent.objects.count()
        path = f"{self._prefix(self.bob_case, self.bob_job)}/alerts/shared-alert/status"
        response = self.client.patch(path, data={"status": "dismissed"}, content_type="application/json", **self.alice_headers)
        self.assertEqual(response.status_code, 404)
        self.bob_job.refresh_from_db()
        self.assertEqual(self.bob_job.stats, before_bob)
        self.assertEqual(Alert.objects.get(pk=f"{self.bob_job.id}-shared-alert").status, "new")
        self.assertEqual(CaseHistoryEvent.objects.count(), before_history)
        self.assertEqual(CustodyLedgerEvent.objects.count(), before_custody)

    def test_scoped_alert_mutation_updates_only_selected_alert(self):
        path = f"{self._prefix(self.alice_case, self.alice_job)}/alerts/shared-alert/status"
        response = self.client.patch(path, data={"status": "confirmed"}, content_type="application/json", **self.alice_headers)
        self.assertEqual(response.status_code, 200)
        self.alice_job.refresh_from_db()
        alert = next(row for row in self.alice_job.stats["analysis"]["alerts"] if row["id"] == "shared-alert")
        detection = next(row for row in self.alice_job.stats["analysis"]["detectionMatches"] if row["id"] == "shared-detection")
        self.assertEqual(alert["status"], "confirmed")
        self.assertEqual(detection["status"], "new")
        self.assertEqual(Alert.objects.get(pk=f"{self.alice_job.id}-shared-alert").status, "confirmed")
        self.assertEqual(DetectionMatch.objects.get(pk=f"{self.alice_job.id}-shared-detection").status, "new")
        self.assertEqual(CaseHistoryEvent.objects.filter(case=self.alice_case).count(), 1)
        self.assertEqual(CustodyLedgerEvent.objects.filter(case=self.alice_case).count(), 1)

    def test_rule_id_cannot_select_detection_mutation(self):
        path = f"{self._prefix(self.alice_case, self.alice_job)}/detections/shared-rule/status"
        response = self.client.patch(path, data={"status": "dismissed"}, content_type="application/json", **self.alice_headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(DetectionMatch.objects.get(pk=f"{self.alice_job.id}-shared-detection").status, "new")

    def test_legacy_mutation_ignores_body_case_id_and_requires_query_scope(self):
        response = self.client.patch(
            "/api/alerts/shared-alert/status",
            data={"status": "dismissed", "caseId": self.bob_case.id},
            content_type="application/json",
            **self.alice_headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "analysis_scope_required")
        self.assertEqual(Alert.objects.get(pk=f"{self.bob_job.id}-shared-alert").status, "new")

    def test_invalid_status_is_rejected_without_mutation(self):
        path = f"{self._prefix(self.alice_case, self.alice_job)}/alerts/shared-alert/status"
        response = self.client.patch(path, data={"status": "deleted"}, content_type="application/json", **self.alice_headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "invalid_finding_status")
        self.assertEqual(Alert.objects.get(pk=f"{self.alice_job.id}-shared-alert").status, "new")


class UnscopedAnalysisHelperTests(SimpleTestCase):
    """Phase 1 required that no unscoped analysis helper survive anywhere."""

    def _api_sources(self) -> dict[str, str]:
        package = Path(analysis_module.__file__).parent
        return {path.name: path.read_text(encoding="utf-8") for path in package.glob("*.py")}

    def test_retired_implicit_selection_helpers_are_absent(self):
        for name, source in self._api_sources().items():
            with self.subTest(module=name):
                self.assertNotIn("_selected_case_id", source)
                self.assertNotIn("def _analysis(", source)
                self.assertNotIn("def _results(", source)

    def test_scoped_analysis_helper_requires_a_case(self):
        with self.assertRaises(Http404):
            legacy_views._case_scoped_analysis(case_id="")
        with self.assertRaises(Http404):
            legacy_views._case_scoped_analysis(case_id="   ")

    def test_scoped_analysis_helper_cannot_be_called_positionally(self):
        with self.assertRaises(TypeError):
            legacy_views._case_scoped_analysis("CASE-ALICE-SCOPE")
