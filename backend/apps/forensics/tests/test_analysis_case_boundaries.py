from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import Case, CaseMembership, ProcessingJob, UserProfile


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

    def _user(self, email: str, role: str):
        user = get_user_model().objects.create_user(username=email, email=email, password="unused-test-password")
        UserProfile.objects.create(user=user, role=role, display_name=email)
        token = str(RefreshToken.for_user(user).access_token)
        return user, {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _case(self, case_id: str, user):
        case = Case.objects.create(id=case_id, title=case_id, investigator=user.email)
        CaseMembership.objects.create(case=case, user=user, role="Investigator")
        return case

    def _job(self, job_id: str, case: Case, marker: str, status=ProcessingJob.Status.COMPLETED):
        return ProcessingJob.objects.create(
            id=job_id,
            case=case,
            status=status,
            stats={"analysis": analysis_document(case.id, marker)},
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
