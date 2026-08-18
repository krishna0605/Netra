from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AccessLog, Case, CaseMembership, OperationalEvent, Organization, UserProfile
from common.audit import Actor, visible_cases_for_actor
from common.tenancy import netra_organization


SECURE_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_ENABLE_SENSOR_CAPTURE=True,
)


@SECURE_SETTINGS
class OrganizationBoundaryTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.netra = netra_organization()
        self.other = Organization.objects.create(id=uuid4(), name="Other", slug="other")

    def tearDown(self):
        cache.clear()
        super().tearDown()

    def _identity(self, email, role, organization):
        user = get_user_model().objects.create_user(username=email, email=email)
        profile = UserProfile.objects.create(user=user, organization=organization, role=role, department="Shared Department")
        token = RefreshToken.for_user(user).access_token
        token["aal"] = "aal2"
        token = str(token)
        return user, profile, {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _case(self, case_id, organization):
        return Case.objects.create(
            id=case_id,
            display_reference=case_id,
            organization=organization,
            title=case_id,
            investigator="Investigator",
            department="Shared Department",
        )

    def test_admin_visibility_is_limited_to_its_organization(self):
        admin, profile, headers = self._identity("admin@netra.test", "Admin", self.netra)
        own_case = self._case("CASE-ORG-NETRA", self.netra)
        other_case = self._case("CASE-ORG-OTHER", self.other)
        actor = Actor(
            user=admin.username,
            role=profile.role,
            authenticated=True,
            django_user_id=admin.id,
            organization_id=self.netra.id,
            organization_slug=self.netra.slug,
        )

        self.assertEqual(list(visible_cases_for_actor(actor).values_list("id", flat=True)), [own_case.id])
        response = self.client.get("/api/cases", **headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([row["id"] for row in response.json()["results"]], [own_case.id])
        self.assertEqual(self.client.get(f"/api/cases/{other_case.id}", **headers).status_code, 404)

    def test_matching_department_does_not_grant_cross_organization_access(self):
        investigator, _, headers = self._identity("investigator@netra.test", "Investigator", self.netra)
        own_case = self._case("CASE-MEMBER-NETRA", self.netra)
        other_case = self._case("CASE-MEMBER-OTHER", self.other)
        CaseMembership.objects.create(case=own_case, user=investigator, role="Investigator")

        response = self.client.get("/api/cases", **headers)
        self.assertEqual([row["id"] for row in response.json()["results"]], [own_case.id])
        self.assertEqual(self.client.get(f"/api/cases/{other_case.id}", **headers).status_code, 404)

    def test_user_and_operational_event_lists_are_organization_scoped(self):
        admin, _, headers = self._identity("org-admin@netra.test", "Admin", self.netra)
        self._identity("other-viewer@other.test", "Viewer", self.other)
        AccessLog.objects.create(
            organization=self.netra,
            user=admin,
            user_label=admin.username,
            role="Admin",
            action="netra.action",
        )
        AccessLog.objects.create(
            organization=self.other,
            user_label="other",
            role="Admin",
            action="other.action",
        )
        OperationalEvent.objects.create(organization=self.netra, event_type="netra.event")
        OperationalEvent.objects.create(organization=self.other, event_type="other.event")

        users = self.client.get("/api/users", **headers).json()["results"]
        self.assertEqual({row["email"] for row in users}, {admin.username})
        logs = self.client.get("/api/audit/access-logs", **headers).json()["results"]
        self.assertIn("netra.action", [row["action"] for row in logs])
        self.assertNotIn("other.action", [row["action"] for row in logs])
        events = self.client.get("/api/events", **headers).json()["results"]
        self.assertEqual([row["eventType"] for row in events], ["netra.event"])

    def test_cross_organization_membership_target_is_hidden(self):
        _admin, _, headers = self._identity("membership-admin@netra.test", "Admin", self.netra)
        self._identity("foreign-user@other.test", "Viewer", self.other)
        case = self._case("CASE-MEMBERSHIP-NETRA", self.netra)
        response = self.client.post(
            f"/api/cases/{case.id}/members",
            data={"email": "foreign-user@other.test", "role": "Investigator"},
            content_type="application/json",
            **headers,
        )
        self.assertEqual(response.status_code, 404)
        self.assertFalse(CaseMembership.objects.filter(case=case).exists())
