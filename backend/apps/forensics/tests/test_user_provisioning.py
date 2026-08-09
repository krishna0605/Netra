import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings

from apps.forensics.api.authentication import users
from apps.forensics.models import AccessLog, OperationalEvent, UserProfile
from common.audit import Actor
from common.supabase_admin import SupabaseAdminError, SupabaseAdminUser
from common.tenancy import netra_organization


SUPABASE_USER = SupabaseAdminUser(
    id="4fd41a62-bba3-4145-9c16-4d4bdf908c15",
    email="invitee@netra.test",
    invited_at="2026-08-09T00:00:00Z",
    email_confirmed_at="",
    last_sign_in_at="",
    mfa_state="unenrolled",
)


@override_settings(
    NETRA_AUTH_PROVIDER="supabase",
    NETRA_AUTH_INVITATIONS_ENABLED=True,
    NETRA_AUTH_INVITE_REDIRECT_URL="https://netra.example/auth/invite",
)
class SupabaseUserProvisioningTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.organization = netra_organization()
        self.admin = get_user_model().objects.create_user(username="admin@netra.test", is_active=True)
        UserProfile.objects.create(user=self.admin, organization=self.organization, role=UserProfile.Role.ADMIN)
        self.actor = Actor(
            user=self.admin.username,
            role=UserProfile.Role.ADMIN,
            authenticated=True,
            django_user_id=self.admin.id,
            organization_id=self.organization.id,
            organization_slug=self.organization.slug,
            aal="aal2",
        )

    def _request(self, payload):
        return self.factory.post("/api/users", data=json.dumps(payload), content_type="application/json")

    def _call(self, payload):
        with (
            patch("apps.forensics.api.authentication.require_permission", return_value=None),
            patch("apps.forensics.api.authentication.actor_from_request", return_value=self.actor),
        ):
            return users(self._request(payload))

    def _list(self, actor=None):
        request = self.factory.get("/api/users", {"limit": "50"})
        with (
            patch("apps.forensics.api.authentication.require_permission", return_value=None),
            patch("apps.forensics.api.authentication.actor_from_request", return_value=actor or self.actor),
        ):
            return users(request)

    @patch("apps.forensics.api.authentication.invite_user", return_value=SUPABASE_USER)
    def test_invitation_creates_unusable_local_identity_and_audit(self, invite):
        response = self._call({"email": "Invitee@Netra.Test", "name": "Invitee", "role": "Viewer"})
        self.assertEqual(response.status_code, 201)
        payload = json.loads(response.content)
        self.assertEqual(payload["invitationState"], "sent")
        user = get_user_model().objects.get(username="invitee@netra.test")
        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.netra_profile.organization_id, self.organization.id)
        self.assertEqual(user.netra_profile.role, UserProfile.Role.VIEWER)
        self.assertTrue(AccessLog.objects.filter(action="organization.user_invited", resource_id=str(user.id)).exists())
        self.assertTrue(OperationalEvent.objects.filter(event_type="organization.user_invited").exists())
        invite.assert_called_once_with("invitee@netra.test", redirect_to="https://netra.example/auth/invite")

    @patch("apps.forensics.api.authentication.invite_user", side_effect=SupabaseAdminError("offline"))
    def test_provider_failure_creates_no_local_user_or_success_audit(self, _invite):
        response = self._call({"email": "invitee@netra.test", "name": "Invitee", "role": "Viewer"})
        self.assertEqual(response.status_code, 503)
        self.assertFalse(get_user_model().objects.filter(username="invitee@netra.test").exists())
        self.assertFalse(AccessLog.objects.filter(action="organization.user_invited").exists())

    @patch("apps.forensics.api.authentication.invite_user", return_value=SUPABASE_USER)
    def test_password_and_admin_role_are_rejected_before_provider_call(self, invite):
        password_response = self._call(
            {"email": "invitee@netra.test", "name": "Invitee", "role": "Viewer", "password": "NotAllowed1!"}
        )
        admin_response = self._call({"email": "invitee@netra.test", "name": "Invitee", "role": "Admin"})
        self.assertEqual(password_response.status_code, 400)
        self.assertEqual(admin_response.status_code, 400)
        invite.assert_not_called()

    def test_disabled_invitation_is_truthful_and_side_effect_free(self):
        with override_settings(NETRA_AUTH_INVITATIONS_ENABLED=False):
            response = self._call({"email": "invitee@netra.test", "name": "Invitee", "role": "Viewer"})
        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.content)
        self.assertEqual(payload["error"]["code"], "feature_disabled")
        self.assertEqual(payload["error"]["feature"], "user_invitations")
        self.assertFalse(get_user_model().objects.filter(username="invitee@netra.test").exists())

    @patch("apps.forensics.api.authentication.list_auth_users", return_value=([SUPABASE_USER], None))
    def test_user_list_adds_bounded_auth_metadata(self, _list_users):
        invited = get_user_model().objects.create_user(username="invitee@netra.test", email="invitee@netra.test")
        UserProfile.objects.create(user=invited, organization=self.organization, role=UserProfile.Role.VIEWER)
        response = self._list()
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        row = next(item for item in payload["results"] if item["email"] == "invitee@netra.test")
        self.assertEqual(row["authState"], "invited")
        self.assertEqual(row["mfaState"], "unenrolled")
        self.assertEqual(row["organization"]["slug"], "netra")
        self.assertIn("nextCursor", payload)

    @patch("apps.forensics.api.authentication.list_auth_users", side_effect=SupabaseAdminError("offline"))
    def test_auth_metadata_failure_degrades_without_hiding_local_users(self, _list_users):
        response = self._list()
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["authMetadataStatus"], "degraded")
        self.assertEqual(payload["results"][0]["mfaState"], "unknown")

    def test_aal1_admin_cannot_list_user_security_metadata(self):
        aal1_actor = Actor(**{**self.actor.__dict__, "aal": "aal1"})
        response = self._list(aal1_actor)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)["error"]["code"], "aal2_required")
