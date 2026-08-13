"""Contract tests for the administration console read path.

The console is the one surface that can change who holds which permission, so
these tests are written against the ways it could wrongly say yes rather than
against the happy path alone.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AccessLog, Case, CaseHistoryEvent, OperationalEvent, UserProfile
from apps.forensics.services.admin_directory import PERMISSION_CATALOGUE
from common.audit import ROLE_PERMISSIONS
from common.tenancy import netra_organization


SECURE_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_RATE_LIMITS_ENABLED=False,
    # Identity-provider calls are never made from a test. The directory must
    # degrade to "unknown" rather than assert anything about enrolment.
    SUPABASE_URL="",
    SUPABASE_SECRET_KEY="",
)

DIRECTORY = "/api/admin/v1/directory"
SESSION = "/api/admin/v1/session"


class AdminConsoleTestBase(TestCase):
    def setUp(self):
        self.client = Client()
        self.organization = netra_organization()
        User = get_user_model()
        self.admin = User.objects.create_user(username="chief@netra.test", email="chief@netra.test", is_active=True)
        UserProfile.objects.create(
            user=self.admin,
            organization=self.organization,
            role=UserProfile.Role.ADMIN,
            display_name="Chief A. Rao",
        )
        self.investigator = User.objects.create_user(
            username="inspector@netra.test", email="inspector@netra.test", is_active=True
        )
        UserProfile.objects.create(
            user=self.investigator,
            organization=self.organization,
            role=UserProfile.Role.INVESTIGATOR,
            display_name="Inspector B. Shah",
        )

    def _headers(self, user, *, aal="aal2"):
        token = RefreshToken.for_user(user).access_token
        token["aal"] = aal
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _code(self, response) -> str:
        """Two error shapes are in play and both are correct.

        NetraApiAuthMiddleware refuses before the view is reached and answers
        with a flat body; api_error nests under "error". Which one a request
        meets tells you which layer stopped it, so the helper reads both rather
        than hiding the difference.
        """
        body = response.json()
        error = body.get("error")
        if isinstance(error, dict):
            return error.get("code", "")
        return body.get("code", "")


@SECURE_SETTINGS
class AdminConsoleAccessTests(AdminConsoleTestBase):
    def test_anonymous_request_is_refused(self):
        for route in (DIRECTORY, SESSION):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 401)

    def test_non_administrator_is_refused_even_at_aal2(self):
        """Refused by the middleware's manage_users gate, before the view runs.

        Two independent layers say no to this request: the namespace-wide
        permission check in NetraApiAuthMiddleware and require_privileged_admin
        inside the view. The middleware simply gets there first.
        """
        response = self.client.get(DIRECTORY, **self._headers(self.investigator))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._code(response), "permission_denied")

    def test_view_refuses_a_non_administrator_even_if_the_middleware_is_bypassed(self):
        """The middleware is not the only thing standing here.

        If NETRA_PUBLIC_API_AUTH_REQUIRED were ever turned off, or the
        privileged-prefix table drifted, the console must still refuse. This
        pins the inner check independently of the outer one.
        """
        with override_settings(NETRA_PUBLIC_API_AUTH_REQUIRED=False):
            response = self.client.get(DIRECTORY, **self._headers(self.investigator))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._code(response), "permission_denied")

    def test_administrator_without_second_factor_is_refused(self):
        """A password alone must not open the console, only a verified factor."""
        response = self.client.get(DIRECTORY, **self._headers(self.admin, aal="aal1"))

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._code(response), "aal2_required")

    def test_administrator_demoted_in_the_database_loses_access_immediately(self):
        """The token still says what it said; the database is what decides.

        This is the property the frozen console URL cannot provide, and the
        reason authorization is re-read per request instead of trusted from
        whatever the edge served.
        """
        headers = self._headers(self.admin)
        self.assertEqual(self.client.get(DIRECTORY, **headers).status_code, 200)

        UserProfile.objects.filter(user=self.admin).update(role=UserProfile.Role.VIEWER)

        self.assertEqual(self.client.get(DIRECTORY, **headers).status_code, 403)

    def test_deactivated_administrator_loses_access_immediately(self):
        """401, not 403: deactivating the account invalidates the identity
        itself, so the request never resolves to an authenticated actor. The
        outstanding token stops working without being revoked."""
        headers = self._headers(self.admin)
        self.assertEqual(self.client.get(DIRECTORY, **headers).status_code, 200)

        get_user_model().objects.filter(pk=self.admin.pk).update(is_active=False)

        self.assertEqual(self.client.get(DIRECTORY, **headers).status_code, 401)

    def test_refused_attempts_are_recorded(self):
        """A rejected reach for the administration namespace is the event an
        audit reviewer most wants to find, and it is invisible if only
        successful calls are written."""
        self.client.get(DIRECTORY, **self._headers(self.admin, aal="aal1"))

        self.assertTrue(
            AccessLog.objects.filter(action="admin_console.denied", result="denied").exists()
        )


@SECURE_SETTINGS
class AdminConsoleOriginTests(AdminConsoleTestBase):
    @override_settings(NETRA_ADMIN_ORIGINS=["https://console.example"])
    def test_disallowed_origin_gets_404_not_403(self):
        """404 so nothing confirms the namespace exists. A 403 would tell an
        attacker the route is real and worth pursuing."""
        response = self.client.get(DIRECTORY, HTTP_ORIGIN="https://evil.example", **self._headers(self.admin))

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["code"], "resource_not_found")

    @override_settings(NETRA_ADMIN_ORIGINS=["https://console.example"])
    def test_allowed_origin_passes(self):
        response = self.client.get(DIRECTORY, HTTP_ORIGIN="https://console.example", **self._headers(self.admin))

        self.assertEqual(response.status_code, 200)

    @override_settings(NETRA_ADMIN_ORIGINS=["https://console.example"])
    def test_request_without_origin_passes_to_the_real_authorization_check(self):
        """Server-to-server calls carry no Origin. Rejecting them would break
        operational tooling while stopping nothing, since anything that can omit
        a header can forge one. The aal2 administrator check still applies."""
        self.assertEqual(self.client.get(DIRECTORY, **self._headers(self.admin)).status_code, 200)
        self.assertEqual(self.client.get(DIRECTORY, **self._headers(self.admin, aal="aal1")).status_code, 403)

    @override_settings(NETRA_ADMIN_ORIGINS=["https://console.example"])
    def test_guard_does_not_touch_the_investigator_namespace(self):
        response = self.client.get("/api/health", HTTP_ORIGIN="https://evil.example")

        self.assertEqual(response.status_code, 200)


@SECURE_SETTINGS
class AdminDirectoryContentTests(AdminConsoleTestBase):
    def _snapshot(self):
        response = self.client.get(DIRECTORY, **self._headers(self.admin))
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_snapshot_carries_every_key_the_console_reads(self):
        snapshot = self._snapshot()

        for key in ("users", "sessions", "activity", "audit", "roles", "organization", "permissions", "capabilities"):
            self.assertIn(key, snapshot)

    def test_users_come_from_profiles_not_fixtures(self):
        snapshot = self._snapshot()
        by_email = {row["email"]: row for row in snapshot["users"]}

        self.assertEqual(set(by_email), {"chief@netra.test", "inspector@netra.test"})
        self.assertEqual(by_email["chief@netra.test"]["roleSlug"], "admin")
        self.assertTrue(by_email["chief@netra.test"]["isOwner"])
        self.assertEqual(by_email["inspector@netra.test"]["roleSlug"], "investigator")
        self.assertFalse(by_email["inspector@netra.test"]["isOwner"])

    def test_effective_permissions_match_what_the_checker_enforces(self):
        """If these drift, the console shows one thing and the API does another."""
        snapshot = self._snapshot()
        by_email = {row["email"]: row for row in snapshot["users"]}

        for email, role in (("chief@netra.test", "Admin"), ("inspector@netra.test", "Investigator")):
            granted = {entry["key"] for entry in by_email[email]["permissions"]}
            self.assertEqual(granted, ROLE_PERMISSIONS[role], email)

    def test_authenticator_state_is_unknown_rather_than_guessed_when_unreachable(self):
        """Reporting "no authenticator enrolled" because a network call failed
        would send an administrator to reset a factor that is already fine."""
        snapshot = self._snapshot()

        self.assertTrue(all(row["mfa"] == "unknown" for row in snapshot["users"]))
        self.assertEqual(snapshot["sources"]["identityProvider"], "unavailable")

    def test_deactivated_accounts_are_reported_as_deactivated(self):
        get_user_model().objects.filter(pk=self.investigator.pk).update(is_active=False)
        snapshot = self._snapshot()
        row = next(entry for entry in snapshot["users"] if entry["email"] == "inspector@netra.test")

        self.assertEqual(row["status"], "deactivated")

    def test_roles_report_real_member_counts(self):
        snapshot = self._snapshot()
        by_slug = {row["slug"]: row for row in snapshot["roles"]}

        self.assertEqual(by_slug["admin"]["memberCount"], 1)
        self.assertEqual(by_slug["investigator"]["memberCount"], 1)
        self.assertEqual(by_slug["viewer"]["memberCount"], 0)

    def test_permission_catalogue_covers_exactly_the_enforced_vocabulary(self):
        """A permission the checker knows but the catalogue does not cannot be
        granted from the console; the reverse offers one that does nothing."""
        catalogued = {entry["key"] for entry in PERMISSION_CATALOGUE}
        enforced = set().union(*ROLE_PERMISSIONS.values())

        self.assertEqual(catalogued, enforced)

    def test_organization_reports_its_own_settings(self):
        snapshot = self._snapshot()

        self.assertEqual(snapshot["organization"]["id"], str(self.organization.id))
        self.assertEqual(snapshot["organization"]["ownerUserId"], self.admin.id)
        self.assertEqual(snapshot["organization"]["mfaPolicy"], "admin_required")

    def test_activity_merges_the_streams_django_owns(self):
        case = Case.objects.create(
            id="case-admin-console-1",
            organization=self.organization,
            title="Directory activity",
            investigator="Inspector B. Shah",
        )
        AccessLog.objects.create(
            organization=self.organization,
            user=self.investigator,
            user_label="Inspector B. Shah",
            role="Investigator",
            action="permission:export",
            result="denied",
        )
        OperationalEvent.objects.create(
            organization=self.organization,
            event_type="capture.started",
            payload_json={"operator": "Chief A. Rao"},
        )
        CaseHistoryEvent.objects.create(case=case, actor_name="Chief A. Rao", action="case.opened", details="Opened")

        snapshot = self._snapshot()
        sources = {row["source"] for row in snapshot["activity"]}

        self.assertIn("AccessLog", sources)
        self.assertIn("OperationalEvent", sources)
        self.assertIn("CaseHistory", sources)

    def test_activity_is_newest_first(self):
        older = timezone.now() - timedelta(hours=3)
        for index in range(3):
            AccessLog.objects.create(
                organization=self.organization,
                user=self.admin,
                user_label="Chief A. Rao",
                role="Admin",
                action=f"permission:view-{index}",
                result="allowed",
            )
        AccessLog.objects.filter(action="permission:view-0").update(created_at=older)

        stamps = [row["at"] for row in self._snapshot()["activity"]]

        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_denied_counts_only_span_the_last_day(self):
        for action in ("permission:export", "permission:report"):
            AccessLog.objects.create(
                organization=self.organization,
                user=self.investigator,
                user_label="Inspector B. Shah",
                role="Investigator",
                action=action,
                result="denied",
            )
        stale = AccessLog.objects.create(
            organization=self.organization,
            user=self.investigator,
            user_label="Inspector B. Shah",
            role="Investigator",
            action="permission:export",
            result="denied",
        )
        AccessLog.objects.filter(pk=stale.pk).update(created_at=timezone.now() - timedelta(days=2))

        row = next(entry for entry in self._snapshot()["users"] if entry["email"] == "inspector@netra.test")

        self.assertEqual(row["deniedLast24h"], 2)

    def test_sessions_and_audit_are_empty_rather_than_invented(self):
        """Both need work that lands in later phases. An empty list makes the
        console show its empty state, which is true. Plausible rows here would
        put fiction in front of someone deciding whether to revoke access."""
        snapshot = self._snapshot()

        self.assertEqual(snapshot["sessions"], [])
        self.assertEqual(snapshot["audit"], [])
        self.assertEqual(snapshot["sources"]["sessions"], "pending")
        self.assertEqual(snapshot["sources"]["audit"], "pending")

    def test_capabilities_come_from_the_registry(self):
        snapshot = self._snapshot()
        keys = {row["key"] for row in snapshot["capabilities"]}

        self.assertIn("user_invitations", keys)
        self.assertTrue(all("state" in row and "requiresAal2" in row for row in snapshot["capabilities"]))


@SECURE_SETTINGS
class AdminSessionTests(AdminConsoleTestBase):
    def test_session_reports_the_callers_own_standing(self):
        response = self.client.get(SESSION, **self._headers(self.admin))

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["userId"], self.admin.id)
        self.assertEqual(body["role"], "Admin")
        self.assertEqual(body["roleSlug"], "admin")
        self.assertEqual(body["aal"], "aal2")
        self.assertEqual(set(body["permissions"]), ROLE_PERMISSIONS["Admin"])
        self.assertEqual(body["organization"]["id"], str(self.organization.id))

    def test_session_never_returns_a_token_or_secret(self):
        body = self.client.get(SESSION, **self._headers(self.admin)).content.decode()

        for forbidden in ("Bearer", "secret", "service_role", "password"):
            self.assertNotIn(forbidden, body)
