from types import SimpleNamespace
import re

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import Case, CaseMembership, Export, Report, UserProfile
from apps.forensics.urls import urlpatterns as api_urlpatterns
from common.audit import sync_supabase_actor
from common.vault import fernet


SECURE_TEST_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
)


@SECURE_TEST_SETTINGS
class ApiAccessControlTests(TestCase):
    def setUp(self):
        self.client = Client()

    def _user(self, email: str, role: str):
        user = get_user_model().objects.create_user(username=email, email=email, password="unused-test-password")
        UserProfile.objects.create(user=user, role=role, display_name=email)
        token = str(RefreshToken.for_user(user).access_token)
        return user, {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _case(self, case_id: str):
        return Case.objects.create(id=case_id, title=case_id, investigator="Test Investigator")

    def test_health_is_the_only_minimal_public_operational_response(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "service": "netra-backend"})
        self.assertEqual(self.client.get("/api/cases").status_code, 401)
        self.assertEqual(self.client.get("/api/setup/status").status_code, 401)

    def test_every_declared_api_route_is_default_deny_for_anonymous_callers(self):
        self.assertGreaterEqual(len(api_urlpatterns), 147)
        for pattern in api_urlpatterns:
            route = str(pattern.pattern)
            sample_route = re.sub(r"<(?:(?:str|int|uuid|slug):)?[^>]+>", "test-id", route)
            path = f"/api/{sample_route}"
            for method in ("post", "patch", "delete"):
                response = getattr(self.client, method)(path, data={}, content_type="application/json")
                self.assertEqual(response.status_code, 401, msg=f"{method.upper()} {path}")
            get_response = self.client.get(path)
            expected_get = 200 if path.rstrip("/") == "/api/health" else 401
            self.assertEqual(get_response.status_code, expected_get, msg=f"GET {path}")
            self.assertEqual(self.client.options(path).status_code, 200, msg=f"OPTIONS {path}")

    def test_case_list_is_membership_scoped_and_cache_is_actor_scoped(self):
        alice, alice_headers = self._user("alice@example.test", "Investigator")
        bob, bob_headers = self._user("bob@example.test", "Investigator")
        alice_case = self._case("CASE-ALICE")
        bob_case = self._case("CASE-BOB")
        CaseMembership.objects.create(case=alice_case, user=alice, role="Investigator")
        CaseMembership.objects.create(case=bob_case, user=bob, role="Investigator")

        alice_payload = self.client.get("/api/cases", **alice_headers).json()
        bob_payload = self.client.get("/api/cases", **bob_headers).json()

        self.assertEqual([row["id"] for row in alice_payload["results"]], ["CASE-ALICE"])
        self.assertEqual([row["id"] for row in bob_payload["results"]], ["CASE-BOB"])

    def test_cross_case_direct_and_resource_access_is_hidden(self):
        alice, alice_headers = self._user("alice@example.test", "Investigator")
        bob, _ = self._user("bob@example.test", "Investigator")
        alice_case = self._case("CASE-ALICE")
        bob_case = self._case("CASE-BOB")
        CaseMembership.objects.create(case=alice_case, user=alice, role="Investigator")
        CaseMembership.objects.create(case=bob_case, user=bob, role="Investigator")

        self.assertEqual(self.client.get("/api/cases/CASE-BOB", **alice_headers).status_code, 404)
        self.assertEqual(self.client.get("/api/cases/CASE-ALICE", **alice_headers).status_code, 200)

        Report.objects.create(id="alice.html", case=alice_case, generated_by="alice")
        Report.objects.create(id="bob.html", case=bob_case, generated_by="bob")
        Export.objects.create(id="export-alice", case=alice_case, export_type="json", requested_by="alice")
        Export.objects.create(id="export-bob", case=bob_case, export_type="json", requested_by="bob")
        report_ids = [row["id"] for row in self.client.get("/api/reports", **alice_headers).json()["results"]]
        export_ids = [row["id"] for row in self.client.get("/api/exports", **alice_headers).json()["results"]]
        self.assertEqual(report_ids, ["alice.html"])
        self.assertEqual(export_ids, ["export-alice"])
        self.assertEqual(self.client.get("/api/reports/bob.html/download", **alice_headers).status_code, 404)
        self.assertEqual(self.client.get("/api/exports/export-bob", **alice_headers).status_code, 404)

    def test_new_case_gets_creator_membership_and_duplicate_id_is_rejected(self):
        user, headers = self._user("creator@example.test", "Investigator")
        response = self.client.post(
            "/api/cases",
            data={"caseNumber": "CASE-NEW", "title": "New case"},
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(CaseMembership.objects.filter(case_id="CASE-NEW", user=user).exists())
        duplicate = self.client.post(
            "/api/cases",
            data={"caseNumber": "CASE-NEW", "title": "Overwrite attempt"},
            content_type="application/json",
            **headers,
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(Case.objects.get(pk="CASE-NEW").title, "New case")

    def test_upload_may_create_a_new_case_but_cannot_target_another_users_case(self):
        alice, headers = self._user("upload-alice@example.test", "Investigator")
        bob, _ = self._user("upload-bob@example.test", "Investigator")
        bob_case = self._case("CASE-BOB-UPLOAD")
        CaseMembership.objects.create(case=bob_case, user=bob, role="Investigator")

        new_case_response = self.client.post(
            "/api/evidence/upload",
            data={
                "caseId": "CASE-NEW-UPLOAD",
                "evidenceType": "PCAP",
                "file": SimpleUploadedFile("invalid.pcap", b"not-a-pcap", content_type="application/vnd.tcpdump.pcap"),
            },
            **headers,
        )
        self.assertNotEqual(new_case_response.status_code, 404)

        wrong_case_response = self.client.post(
            "/api/evidence/upload",
            data={
                "caseId": "CASE-BOB-UPLOAD",
                "evidenceType": "PCAP",
                "file": SimpleUploadedFile("invalid.pcap", b"not-a-pcap", content_type="application/vnd.tcpdump.pcap"),
            },
            **headers,
        )
        self.assertEqual(wrong_case_response.status_code, 404)
        self.assertFalse(CaseMembership.objects.filter(case=bob_case, user=alice).exists())

    def test_viewer_cannot_reach_operational_or_mutating_routes(self):
        _user, headers = self._user("viewer@example.test", "Viewer")
        self.assertEqual(self.client.get("/api/system/metrics", **headers).status_code, 403)
        self.assertEqual(
            self.client.post("/api/cases", data={}, content_type="application/json", **headers).status_code,
            403,
        )

    @override_settings(
        NETRA_DEPLOYMENT_PROFILE="hackathon-core",
        NETRA_ENABLE_LAB_TOOLS=False,
        NETRA_ENABLE_INTEGRATIONS=False,
        NETRA_ENABLE_CAPTURE_SCHEDULES=False,
        NETRA_ENABLE_RETENTION_OPERATIONS=False,
    )
    def test_hackathon_profile_gates_operations_but_keeps_admin_diagnostics(self):
        _admin, headers = self._user("profile-admin@example.test", "Admin")
        identity = self.client.get("/api/auth/me", **headers)
        self.assertEqual(identity.status_code, 200)
        self.assertFalse(identity.json()["deployment"]["modules"]["lab"]["enabled"])
        for path in ("/api/sensors", "/api/capture-schedules", "/api/integrations", "/api/retention/policy"):
            response = self.client.get(path, **headers)
            self.assertEqual(response.status_code, 404, path)
            self.assertEqual(response.json()["code"], "feature_disabled")
        self.assertEqual(self.client.get("/api/system/metrics", **headers).status_code, 200)

    def test_hosted_setup_endpoint_is_disabled(self):
        _admin, headers = self._user("admin@example.test", "Admin")
        self.assertEqual(self.client.get("/api/setup/status", **headers).status_code, 404)
        self.assertEqual(
            self.client.post("/api/setup/admin", data={}, content_type="application/json", **headers).status_code,
            404,
        )

    @override_settings(NETRA_SENSOR_SHARED_KEY="test-sensor-key")
    def test_sensor_agent_routes_require_their_separate_key(self):
        self.assertEqual(self.client.post("/api/sensors/register", data={}, content_type="application/json").status_code, 401)
        response = self.client.post(
            "/api/sensors/register",
            data={"id": "sensor-test", "name": "Test sensor"},
            content_type="application/json",
            HTTP_X_NETRA_SENSOR_KEY="test-sensor-key",
        )
        self.assertEqual(response.status_code, 201)


@SECURE_TEST_SETTINGS
class IdentityProvisioningTests(TestCase):
    def test_verified_supabase_identity_starts_as_viewer_even_with_admin_claim(self):
        actor = sync_supabase_actor(
            SimpleNamespace(
                id="supabase-user-1",
                email="new@example.test",
                display_name="New User",
                role="Admin",
            )
        )
        self.assertEqual(actor.role, "Viewer")
        self.assertEqual(UserProfile.objects.get(user__username="new@example.test").role, "Viewer")

    def test_evidence_key_rotation_retains_decrypt_only_previous_key(self):
        with override_settings(NETRA_EVIDENCE_KEY="old-evidence-key", NETRA_EVIDENCE_PREVIOUS_KEYS=[]):
            ciphertext = fernet().encrypt(b"evidence")
        with override_settings(NETRA_EVIDENCE_KEY="new-evidence-key", NETRA_EVIDENCE_PREVIOUS_KEYS=["old-evidence-key"]):
            self.assertEqual(fernet().decrypt(ciphertext), b"evidence")


@SECURE_TEST_SETTINGS
@override_settings(NETRA_FRONTEND_ORIGINS=["https://console.example.test"])
class CorsTests(TestCase):
    def test_cors_is_exact_origin_and_does_not_expose_dev_identity_headers(self):
        allowed = self.client.options("/api/cases", HTTP_ORIGIN="https://console.example.test")
        denied = self.client.options("/api/cases", HTTP_ORIGIN="https://evil.example.test")
        self.assertEqual(allowed["Access-Control-Allow-Origin"], "https://console.example.test")
        self.assertNotIn("Access-Control-Allow-Origin", denied)
        self.assertNotIn("X-Netra-Role", allowed["Access-Control-Allow-Headers"])
        self.assertIn("DELETE", allowed["Access-Control-Allow-Methods"])
