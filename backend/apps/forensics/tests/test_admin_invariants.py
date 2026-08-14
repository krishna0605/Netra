from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AccessLog, OperationalEvent, UserProfile
from common.tenancy import netra_organization


SECURE_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_RATE_LIMITS_ENABLED=True,
)


@SECURE_SETTINGS
class AdministratorInvariantTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.organization = netra_organization()
        self.admin = get_user_model().objects.create_user(username="admin@netra.test", is_active=True)
        UserProfile.objects.create(user=self.admin, organization=self.organization, role=UserProfile.Role.ADMIN)
        self.target = get_user_model().objects.create_user(username="target@netra.test", is_active=True)
        UserProfile.objects.create(user=self.target, organization=self.organization, role=UserProfile.Role.INVESTIGATOR)

    def _headers(self, user, *, aal="aal1"):
        token = RefreshToken.for_user(user).access_token
        token["aal"] = aal
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def test_aal1_admin_cannot_mutate_users(self):
        response = self.client.post(
            "/api/users",
            data={"email": "viewer@netra.test", "role": "Viewer"},
            content_type="application/json",
            **self._headers(self.admin),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "aal2_required")

    def test_aal2_admin_can_create_only_non_admin_profile(self):
        response = self.client.post(
            "/api/users",
            data={"email": "viewer@netra.test", "role": "Viewer"},
            content_type="application/json",
            **self._headers(self.admin, aal="aal2"),
        )
        self.assertEqual(response.status_code, 201)
        rejected = self.client.post(
            "/api/users",
            data={"email": "second-admin@netra.test", "role": "Admin"},
            content_type="application/json",
            **self._headers(self.admin, aal="aal2"),
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertFalse(UserProfile.objects.filter(user__username="second-admin@netra.test").exists())

    def test_administrators_cannot_be_changed_through_the_generic_user_route(self):
        """Administrator changes belong in the administration namespace,
        where every one of them is sealed into the audit chain. The generic
        route stays shut even though several administrators are now allowed.

        The account here is the caller's own, so the narrower self-mutation
        rule answers first — resetting your own access locks you out of the
        console that would have fixed it.
        """
        response = self.client.patch(
            f"/api/users/{self.admin.id}",
            data={"role": "Investigator", "active": False},
            content_type="application/json",
            **self._headers(self.admin, aal="aal2"),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "self_mutation_forbidden")
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)
        self.assertEqual(self.admin.netra_profile.role, UserProfile.Role.ADMIN)

    def test_successful_transfer_is_atomic_and_audited(self):
        response = self.client.post(
            f"/api/admin/organizations/{self.organization.id}/admin-transfer",
            data={"targetUserId": self.target.id, "reason": "Approved rotation under ticket NETRA-1234."},
            content_type="application/json",
            **self._headers(self.admin, aal="aal2"),
        )
        self.assertEqual(response.status_code, 200)
        self.admin.netra_profile.refresh_from_db()
        self.target.netra_profile.refresh_from_db()
        self.assertEqual(self.admin.netra_profile.role, UserProfile.Role.INVESTIGATOR)
        self.assertEqual(self.target.netra_profile.role, UserProfile.Role.ADMIN)
        self.assertEqual(UserProfile.objects.filter(organization=self.organization, role="Admin").count(), 1)
        self.assertTrue(AccessLog.objects.filter(action="organization.admin_transfer").exists())
        self.assertTrue(OperationalEvent.objects.filter(event_type="organization.admin_transferred").exists())

    def test_audit_failure_rolls_back_both_role_changes(self):
        with patch("apps.forensics.services.administration.OperationalEvent.objects.create", side_effect=RuntimeError("audit failed")):
            with self.assertRaises(RuntimeError):
                self.client.post(
                    f"/api/admin/organizations/{self.organization.id}/admin-transfer",
                    data={"targetUserId": self.target.id, "reason": "Approved rotation under ticket NETRA-1234."},
                    content_type="application/json",
                    **self._headers(self.admin, aal="aal2"),
                )
        self.admin.netra_profile.refresh_from_db()
        self.target.netra_profile.refresh_from_db()
        self.assertEqual(self.admin.netra_profile.role, UserProfile.Role.ADMIN)
        self.assertEqual(self.target.netra_profile.role, UserProfile.Role.INVESTIGATOR)
        self.assertFalse(AccessLog.objects.filter(action="organization.admin_transfer").exists())

    def test_break_glass_command_requires_audit_context(self):
        with self.assertRaises(CommandError):
            call_command("provision_netra_user", "new@netra.test", role="Viewer", stdout=StringIO())

    def test_break_glass_command_records_both_audit_rows(self):
        call_command(
            "provision_netra_user",
            "new@netra.test",
            role="Viewer",
            ticket="NETRA-2000",
            reason="Approved emergency account provisioning.",
            operator="security-operator",
            stdout=StringIO(),
        )
        self.assertTrue(AccessLog.objects.filter(action="break_glass.profile_provisioned", user_label="security-operator").exists())
        event = OperationalEvent.objects.get(event_type="break_glass.profile_provisioned")
        self.assertEqual(event.payload_json["ticket"], "NETRA-2000")
        self.assertNotIn("password", event.payload_json)
