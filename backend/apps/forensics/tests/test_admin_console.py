"""Contract tests for the administration console read path.

The console is the one surface that can change who holds which permission, so
these tests are written against the ways it could wrongly say yes rather than
against the happy path alone.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import (
    AccessLog,
    Case,
    CaseHistoryEvent,
    OperationalEvent,
    PermissionGrant,
    Role,
    UserProfile,
)
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


def backdate_access_logs(queryset, moment):
    """Move access-log timestamps for a test.

    AccessLog is append-only in PostgreSQL — a trigger refuses UPDATE and
    DELETE outside a maintenance window — so a test that needs an older row has
    to open that window explicitly rather than quietly discovering the guard.
    """
    from django.db import connection

    if connection.vendor != "postgresql":
        queryset.update(created_at=moment)
        return
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('netra.access_log_maintenance', 'on', true)")
        queryset.update(created_at=moment)
        cursor.execute("SELECT set_config('netra.access_log_maintenance', 'off', true)")


class AdminConsoleTestBase(TestCase):
    def setUp(self):
        self.client = Client()
        self.organization = netra_organization()
        User = get_user_model()
        self.admin = User.objects.create_user(
            username="chief@netra.test", email="chief@netra.test", is_active=True
        )
        UserProfile.objects.create(
            user=self.admin,
            organization=self.organization,
            role=UserProfile.Role.ADMIN,
            display_name="Chief A. Rao",
        )
        self.investigator = User.objects.create_user(
            username="inspector@netra.test",
            email="inspector@netra.test",
            is_active=True,
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
            AccessLog.objects.filter(
                action="admin_console.denied", result="denied"
            ).exists()
        )


@SECURE_SETTINGS
class AdminConsoleOriginTests(AdminConsoleTestBase):
    @override_settings(NETRA_ADMIN_ORIGINS=["https://console.example"])
    def test_disallowed_origin_gets_404_not_403(self):
        """404 so nothing confirms the namespace exists. A 403 would tell an
        attacker the route is real and worth pursuing."""
        response = self.client.get(
            DIRECTORY, HTTP_ORIGIN="https://evil.example", **self._headers(self.admin)
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["code"], "resource_not_found")

    @override_settings(NETRA_ADMIN_ORIGINS=["https://console.example"])
    def test_allowed_origin_passes(self):
        response = self.client.get(
            DIRECTORY,
            HTTP_ORIGIN="https://console.example",
            **self._headers(self.admin),
        )

        self.assertEqual(response.status_code, 200)

    @override_settings(NETRA_ADMIN_ORIGINS=["https://console.example"])
    def test_request_without_origin_passes_to_the_real_authorization_check(self):
        """Server-to-server calls carry no Origin. Rejecting them would break
        operational tooling while stopping nothing, since anything that can omit
        a header can forge one. The aal2 administrator check still applies."""
        self.assertEqual(
            self.client.get(DIRECTORY, **self._headers(self.admin)).status_code, 200
        )
        self.assertEqual(
            self.client.get(
                DIRECTORY, **self._headers(self.admin, aal="aal1")
            ).status_code,
            403,
        )

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

        for key in (
            "users",
            "sessions",
            "activity",
            "audit",
            "roles",
            "organization",
            "permissions",
            "capabilities",
        ):
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

        for email, role in (
            ("chief@netra.test", "Admin"),
            ("inspector@netra.test", "Investigator"),
        ):
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
        row = next(
            entry
            for entry in snapshot["users"]
            if entry["email"] == "inspector@netra.test"
        )

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
        self.assertEqual(snapshot["organization"]["mfaPolicy"], "all_required")

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
        CaseHistoryEvent.objects.create(
            case=case, actor_name="Chief A. Rao", action="case.opened", details="Opened"
        )

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
        backdate_access_logs(
            AccessLog.objects.filter(action="permission:view-0"), older
        )

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
        backdate_access_logs(
            AccessLog.objects.filter(pk=stale.pk), timezone.now() - timedelta(days=2)
        )

        row = next(
            entry
            for entry in self._snapshot()["users"]
            if entry["email"] == "inspector@netra.test"
        )

        self.assertEqual(row["deniedLast24h"], 2)

    def test_sessions_say_why_they_are_empty(self):
        """Sessions live in GoTrue's auth.sessions, which exists only on the
        PostgreSQL deployment. On SQLite the console is told that rather than
        shown an empty table, because "nobody is signed in" and "nobody can
        tell" must not look the same."""
        snapshot = self._snapshot()

        self.assertEqual(snapshot["sessions"], [])
        # The value depends on what the deployment can actually establish, and
        # all three answers here are true ones: SQLite has no auth schema to
        # read, PostgreSQL without Supabase cannot reach the table, and with no
        # linked identities there is genuinely nothing to look up. What matters
        # is that the console is told which — "nobody is signed in" and "nobody
        # can tell" must never render the same. The reasons themselves are
        # covered in test_live_sessions.
        self.assertIn(
            snapshot["sources"]["sessions"],
            {"live", "unavailable_not_postgres", "unavailable_no_access"},
        )

    def test_the_audit_chain_is_live_and_empty_until_something_is_recorded(self):
        """Empty because nothing has happened, not because nothing is wired.
        The source marker is what tells those two apart."""
        snapshot = self._snapshot()

        self.assertEqual(snapshot["audit"], [])
        self.assertEqual(snapshot["sources"]["audit"], "live")

    def test_capabilities_come_from_the_registry(self):
        snapshot = self._snapshot()
        keys = {row["key"] for row in snapshot["capabilities"]}

        self.assertIn("user_invitations", keys)
        self.assertTrue(
            all(
                "state" in row and "requiresAal2" in row
                for row in snapshot["capabilities"]
            )
        )


@SECURE_SETTINGS
class AdminDirectoryScaleTests(AdminConsoleTestBase):
    def test_directory_query_count_stays_flat_for_a_realistic_roster(self):
        """A console load must not issue permission queries per member."""
        headers = self._headers(self.admin)

        with CaptureQueriesContext(connection) as baseline_queries:
            baseline_response = self.client.get(DIRECTORY, **headers)
            self.assertEqual(baseline_response.status_code, 200)

        User = get_user_model()
        users = User.objects.bulk_create(
            [
                User(
                    username=f"member-{index:03d}@netra.test",
                    email=f"member-{index:03d}@netra.test",
                    is_active=True,
                )
                for index in range(250)
            ]
        )
        viewer_role = Role.objects.get(organization=self.organization, slug="viewer")
        UserProfile.objects.bulk_create(
            [
                UserProfile(
                    user=user,
                    organization=self.organization,
                    role=UserProfile.Role.VIEWER,
                    role_ref=viewer_role,
                    display_name=f"Member {index:03d}",
                )
                for index, user in enumerate(users)
            ]
        )

        with CaptureQueriesContext(connection) as loaded_queries:
            response = self.client.get(DIRECTORY, **headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()["users"]), 252)

        self.assertLessEqual(
            len(loaded_queries),
            len(baseline_queries) + 4,
            f"directory queries grew from {len(baseline_queries)} to {len(loaded_queries)}",
        )


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

    def test_session_reports_real_ownership_and_effective_permissions(self):
        self.organization.owner = self.admin
        self.organization.save(update_fields=["owner"])
        PermissionGrant.objects.create(
            organization=self.organization,
            user=self.admin,
            permission_id="export",
            mode=PermissionGrant.Mode.REVOKE,
            reason="Export removed for this test.",
        )

        body = self.client.get(SESSION, **self._headers(self.admin)).json()

        self.assertTrue(body["isOwner"])
        self.assertNotIn("export", body["permissions"])


@SECURE_SETTINGS
class AdminAuditEndpointTests(AdminConsoleTestBase):
    def _record(self, count=3):
        from common.admin_audit import record_admin_event
        from common.audit import Actor

        actor = Actor(
            user="Chief A. Rao",
            role="Admin",
            authenticated=True,
            django_user_id=self.admin.id,
            email="chief@netra.test",
            organization_id=self.organization.id,
            organization_slug="netra",
            aal="aal2",
        )
        for index in range(count):
            record_admin_event(
                organization=self.organization,
                actor=actor,
                action=f"user.action_{index}",
                target_type="User",
                target_id=str(self.investigator.id),
                reason="Recorded under test.",
            )

    def test_the_directory_carries_the_chain(self):
        self._record()
        snapshot = self.client.get(DIRECTORY, **self._headers(self.admin)).json()

        self.assertEqual(len(snapshot["audit"]), 3)
        self.assertEqual(snapshot["sources"]["audit"], "live")
        # Newest first, by chain index rather than by time: the index cannot be
        # tampered with without breaking verification, a timestamp sort could
        # let a forged row present itself out of position.
        self.assertEqual([row["chainIndex"] for row in snapshot["audit"]], [3, 2, 1])

    def test_administrator_events_appear_in_activity(self):
        self._record(count=1)
        snapshot = self.client.get(DIRECTORY, **self._headers(self.admin)).json()

        self.assertIn("AdminAudit", {row["source"] for row in snapshot["activity"]})

    def test_verify_reports_an_intact_chain(self):
        self._record()
        response = self.client.get(
            "/api/admin/v1/audit/verify", **self._headers(self.admin)
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["verified"])
        self.assertEqual(body["eventCount"], 3)
        self.assertIsNone(body["firstBrokenIndex"])

    def test_verify_reports_where_a_tampered_chain_breaks(self):
        from apps.forensics.models import AdminAuditEvent

        self._record()
        AdminAuditEvent.objects.filter(chain_index=2).update(
            reason="Routine maintenance."
        )

        body = self.client.get(
            "/api/admin/v1/audit/verify", **self._headers(self.admin)
        ).json()

        self.assertFalse(body["verified"])
        self.assertEqual(body["firstBrokenIndex"], 2)

    def test_verify_does_not_grow_the_chain_it_verifies(self):
        """Recording the check would add an entry every time anyone looked."""
        from apps.forensics.models import AdminAuditEvent

        self._record()
        for _ in range(3):
            self.client.get("/api/admin/v1/audit/verify", **self._headers(self.admin))

        self.assertEqual(AdminAuditEvent.objects.count(), 3)

    def test_verify_requires_an_administrator(self):
        self.assertEqual(
            self.client.get(
                "/api/admin/v1/audit/verify", **self._headers(self.investigator)
            ).status_code,
            403,
        )
        self.assertEqual(self.client.get("/api/admin/v1/audit/verify").status_code, 401)


@SECURE_SETTINGS
class StepUpGateTests(AdminConsoleTestBase):
    def _headers_with_factor(self, user, *, seconds_ago: int):
        import time

        token = RefreshToken.for_user(user).access_token
        token["aal"] = "aal2"
        token["amr"] = [
            {"method": "password", "timestamp": int(time.time()) - 40_000},
            {"method": "totp", "timestamp": int(time.time()) - seconds_ago},
        ]
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def test_reading_the_directory_does_not_require_a_recent_factor(self):
        """Prompting for a code to look at a list would train operators to keep
        their authenticator permanently open, defeating the control where it
        actually matters."""
        response = self.client.get(DIRECTORY, **self._headers(self.admin, aal="aal2"))

        self.assertEqual(response.status_code, 200)

    def test_a_recent_challenge_reports_as_fresh(self):
        body = self.client.get(
            SESSION, **self._headers_with_factor(self.admin, seconds_ago=30)
        ).json()

        self.assertTrue(body["stepUp"]["fresh"])
        self.assertIsNotNone(body["stepUp"]["verifiedAt"])
        self.assertEqual(body["stepUp"]["maxAgeSeconds"], 300)

    def test_a_stale_challenge_reports_as_not_fresh(self):
        """The nine-in-the-morning session. Still aal2, still signed in, and no
        longer sufficient to reset someone's credentials."""
        body = self.client.get(
            SESSION, **self._headers_with_factor(self.admin, seconds_ago=8 * 3600)
        ).json()

        self.assertFalse(body["stepUp"]["fresh"])
        self.assertIsNotNone(body["stepUp"]["verifiedAt"])

    def test_a_session_with_no_second_factor_reports_as_not_fresh(self):
        body = self.client.get(SESSION, **self._headers(self.admin, aal="aal2")).json()

        self.assertFalse(body["stepUp"]["fresh"])
        self.assertIsNone(body["stepUp"]["verifiedAt"])

    def test_the_gate_refuses_a_stale_session(self):
        from apps.forensics.services.administration import (
            AdministrationProblem,
            require_recent_factor,
        )
        from common.audit import Actor
        from django.utils import timezone
        from datetime import timedelta

        stale = Actor(
            user="Chief A. Rao",
            role="Admin",
            authenticated=True,
            aal="aal2",
            factor_verified_at=timezone.now() - timedelta(hours=8),
        )
        with self.assertRaises(AdministrationProblem) as raised:
            require_recent_factor(stale)

        self.assertEqual(raised.exception.code, "step_up_required")
        self.assertEqual(raised.exception.status, 401)

    def test_the_gate_accepts_a_fresh_session(self):
        from apps.forensics.services.administration import require_recent_factor
        from common.audit import Actor
        from django.utils import timezone
        from datetime import timedelta

        fresh = Actor(
            user="Chief A. Rao",
            role="Admin",
            authenticated=True,
            aal="aal2",
            factor_verified_at=timezone.now() - timedelta(seconds=30),
        )

        self.assertIsNone(require_recent_factor(fresh))
