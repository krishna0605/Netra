from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import ConsoleContext, UserProfile
from apps.forensics.services.console_context import (
    ConsoleContextProblem,
    create_console_context,
    switch_console_workspace,
    validate_console_context,
    workspace_contract,
)
from common.audit import Actor, ROLE_PERMISSIONS
from common.permissions import bump_permissions_version
from common.tenancy import netra_organization


@override_settings(
    NETRA_MFA_POLICY="all_required",
    NETRA_CONSOLE_CONTEXT_MAX_AGE_SECONDS=28800,
    NETRA_INVESTIGATION_IDLE_SECONDS=1800,
    NETRA_ADMINISTRATION_IDLE_SECONDS=900,
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_CONSOLE_CONTEXT_REQUIRED=True,
    NETRA_RATE_LIMITS_ENABLED=False,
)
class ConsoleContextTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        self.user = get_user_model().objects.create_user(
            username="officer@netra.test", email="officer@netra.test", is_active=True
        )
        self.profile = UserProfile.objects.create(
            user=self.user,
            organization=self.organization,
            role=UserProfile.Role.INVESTIGATOR,
            display_name="Officer",
        )
        self.client = Client()

    def actor(self, **changes):
        values = {
            "user": "Officer",
            "role": self.profile.role,
            "authenticated": True,
            "django_user_id": self.user.id,
            "email": self.user.email,
            "organization_id": self.organization.id,
            "organization_slug": self.organization.slug,
            "aal": "aal2",
            "permissions": frozenset(ROLE_PERMISSIONS[self.profile.role]),
            "session_id": "session-one",
        }
        values.update(changes)
        return Actor(**values)

    def test_investigator_context_is_bound_to_identity_session_and_organization(self):
        context = create_console_context(self.actor())
        self.assertEqual(context.allowed_workspaces_json, ["investigation"])
        self.assertEqual(validate_console_context(self.actor(), str(context.id)).id, context.id)
        with self.assertRaises(ConsoleContextProblem) as refused:
            validate_console_context(self.actor(session_id="forged-session"), str(context.id))
        self.assertEqual(refused.exception.code, "console_context_expired")

    def test_manage_users_is_the_administration_gate(self):
        permissions = frozenset({*ROLE_PERMISSIONS[UserProfile.Role.INVESTIGATOR], "manage_users"})
        actor = self.actor(permissions=permissions)
        self.assertTrue(workspace_contract(actor)["administration"]["available"])
        context = create_console_context(actor)
        switched = switch_console_workspace(actor, str(context.id), "administration")
        self.assertEqual(switched.active_workspace, "administration")

    def test_aal1_password_and_mfa_reset_states_fail_closed(self):
        with self.assertRaises(ConsoleContextProblem) as aal1:
            create_console_context(self.actor(aal="aal1"))
        self.assertEqual(aal1.exception.code, "aal2_required")

        self.profile.must_change_password = True
        self.profile.save(update_fields=["must_change_password", "updated_at"])
        with self.assertRaises(ConsoleContextProblem) as password:
            create_console_context(self.actor())
        self.assertEqual(password.exception.code, "password_change_required")

        self.profile.must_change_password = False
        self.profile.mfa_reset_required = True
        self.profile.save(update_fields=["must_change_password", "mfa_reset_required", "updated_at"])
        with self.assertRaises(ConsoleContextProblem) as mfa:
            create_console_context(self.actor())
        self.assertEqual(mfa.exception.code, "mfa_enrollment_required")

    def test_permissions_change_and_idle_timeout_revoke_existing_context(self):
        context = create_console_context(self.actor())
        bump_permissions_version(self.organization)
        with self.assertRaises(ConsoleContextProblem):
            validate_console_context(self.actor(), str(context.id))

        replacement = create_console_context(self.actor())
        ConsoleContext.objects.filter(pk=replacement.pk).update(
            last_seen_at=timezone.now() - timedelta(seconds=1801)
        )
        with self.assertRaises(ConsoleContextProblem) as idle:
            validate_console_context(self.actor(), str(replacement.id))
        self.assertEqual(idle.exception.code, "console_context_expired")

    def test_http_contract_requires_context_after_auth_me_and_fails_closed(self):
        token = RefreshToken.for_user(self.user).access_token
        token["aal"] = "aal2"
        authorization = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

        profile = self.client.get("/api/auth/me", **authorization)
        self.assertEqual(profile.status_code, 200)
        body = profile.json()
        self.assertTrue(body["account"]["mfaRequired"])
        self.assertTrue(body["workspaces"]["investigation"]["available"])
        self.assertFalse(body["workspaces"]["administration"]["available"])

        missing = self.client.get("/api/cases", **authorization)
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.json()["code"], "console_context_required")

        created = self.client.post("/api/auth/context", **authorization)
        self.assertEqual(created.status_code, 201)
        context_id = created.json()["context"]["contextId"]
        allowed = self.client.get(
            "/api/cases",
            HTTP_X_NETRA_CONTEXT_ID=context_id,
            **authorization,
        )
        self.assertEqual(allowed.status_code, 200)

        forged = self.client.get(
            "/api/cases",
            HTTP_X_NETRA_CONTEXT_ID="11111111-1111-4111-8111-111111111111",
            **authorization,
        )
        self.assertEqual(forged.status_code, 401)
        self.assertEqual(forged.json()["code"], "console_context_invalid")
