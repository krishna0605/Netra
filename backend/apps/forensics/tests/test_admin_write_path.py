"""Administrative writes.

Supabase is patched at the module boundary, as test_user_provisioning already
does. A suite that needs a real secret key cannot run in CI, and one that
creates real accounts in a live police project in order to test itself is
worse.

Written against the ways a write can go wrong quietly: a local record of a
change the identity provider refused, a credential replaced with nothing
recorded, an administrator locking themselves out, or the last administrator
being removed.
"""

import json
import time
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AdminAuditEvent, SessionRevocation, UserProfile
from common.supabase_admin import SupabaseAdminError, SupabaseAdminUser
from common.tenancy import netra_organization


SECURE_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_RATE_LIMITS_ENABLED=False,
    SUPABASE_URL="https://test.supabase.co",
    SUPABASE_SECRET_KEY="placeholder-for-tests-only",
)

IDENTITY = SupabaseAdminUser(
    id="11111111-2222-3333-4444-555555555555",
    email="new.officer@gcc.gov.in",
    invited_at="",
    email_confirmed_at="2026-08-14T00:00:00Z",
    last_sign_in_at="",
    mfa_state="unenrolled",
)

USERS = "/api/admin/v1/users"


class AdminWriteTestBase(TestCase):
    """Fixture and helpers only. Inheriting a class that also holds tests
    silently re-runs all of them under the subclass."""

    def setUp(self):
        self.client = Client()
        self.organization = netra_organization()
        User = get_user_model()
        self.head = User.objects.create_user(username="head@gcc.gov.in", email="head@gcc.gov.in", is_active=True)
        self.deputy = User.objects.create_user(username="deputy@gcc.gov.in", email="deputy@gcc.gov.in", is_active=True)
        self.officer = User.objects.create_user(
            username="officer@gcc.gov.in", email="officer@gcc.gov.in", is_active=True
        )
        for user, role, name in (
            (self.head, UserProfile.Role.ADMIN, "Chief A. Rao"),
            (self.deputy, UserProfile.Role.ADMIN, "Dy. B. Shah"),
            (self.officer, UserProfile.Role.INVESTIGATOR, "Insp. C. Desai"),
        ):
            UserProfile.objects.create(user=user, organization=self.organization, role=role, display_name=name)

    def _headers(self, user, *, fresh=True, aal="aal2"):
        token = RefreshToken.for_user(user).access_token
        token["aal"] = aal
        now = int(time.time())
        token["amr"] = [
            {"method": "password", "timestamp": now - 40_000},
            {"method": "totp", "timestamp": now - (30 if fresh else 8 * 3600)},
        ]
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def _code(self, response) -> str:
        body = response.json()
        error = body.get("error")
        return error.get("code", "") if isinstance(error, dict) else body.get("code", "")

    def _post(self, path, payload, user=None, **kwargs):
        return self.client.post(
            path, data=payload, content_type="application/json", **self._headers(user or self.head, **kwargs)
        )

    def _patch(self, path, payload, user=None):
        return self.client.patch(
            path, data=payload, content_type="application/json", **self._headers(user or self.head)
        )


@SECURE_SETTINGS
class AdminWritePathTests(AdminWriteTestBase):
    # ── Creating an account ────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.create_user", return_value=IDENTITY)
    def test_creating_an_account_returns_the_password_exactly_once(self, created):
        response = self._post(
            USERS,
            {
                "email": "new.officer@gcc.gov.in",
                "name": "Insp. D. Joshi",
                "role": "Investigator",
                "department": "Cyber Cell",
                "reason": "Joined the unit this week.",
            },
        )

        self.assertEqual(response.status_code, 201)
        password = response.json()["password"]
        self.assertGreaterEqual(len(password), 20)
        created.assert_called_once()

        # Returned, then held nowhere. The audit entry records that a
        # credential was set, never what it was.
        entry = AdminAuditEvent.objects.get(action="user.created")
        self.assertNotIn(password, json.dumps(entry.after_json))
        self.assertNotIn(password, entry.reason)

    @patch("apps.forensics.services.admin_users.create_user", return_value=IDENTITY)
    def test_the_generated_password_avoids_characters_misread_when_dictated(self, _created):
        """An administrator reads this to a colleague in another building."""
        seen = set()
        for index in range(8):
            response = self._post(
                USERS,
                {
                    "email": f"officer{index}@gcc.gov.in",
                    "name": "Officer",
                    "role": "Viewer",
                    "department": "Cell",
                    "reason": "Bulk creation for this test.",
                },
            )
            seen.add(response.json()["password"])
        joined = "".join(seen)

        for ambiguous in ("I", "l", "O", "0", "1"):
            self.assertNotIn(ambiguous, joined)
        self.assertEqual(len(seen), 8, "passwords must not repeat")

    @patch("apps.forensics.services.admin_users.create_user", side_effect=SupabaseAdminError("offline"))
    def test_no_local_account_survives_a_refused_identity(self, _created):
        """The order is Supabase first for exactly this reason. A local row
        saying an account exists while the credential does not is a lie the
        console keeps telling."""
        response = self._post(
            USERS,
            {
                "email": "ghost@gcc.gov.in",
                "name": "Ghost",
                "role": "Viewer",
                "department": "Cell",
                "reason": "Should not be created at all.",
            },
        )

        self.assertEqual(response.status_code, 503)
        self.assertFalse(get_user_model().objects.filter(username="ghost@gcc.gov.in").exists())
        self.assertFalse(AdminAuditEvent.objects.filter(target_id="ghost@gcc.gov.in").exists())

    @patch("apps.forensics.services.admin_users.create_user", return_value=IDENTITY)
    def test_a_duplicate_address_is_refused_before_the_provider_is_called(self, created):
        response = self._post(
            USERS,
            {
                "email": "officer@gcc.gov.in",
                "name": "Duplicate",
                "role": "Viewer",
                "department": "Cell",
                "reason": "Already present in the directory.",
            },
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "email_in_use")
        created.assert_not_called()

    # ── Step-up ────────────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.create_user", return_value=IDENTITY)
    def test_a_stale_authenticator_refuses_the_write(self, created):
        """Still signed in, still an administrator, and no longer recent enough
        to create an account."""
        response = self._post(
            USERS,
            {
                "email": "late@gcc.gov.in",
                "name": "Late",
                "role": "Viewer",
                "department": "Cell",
                "reason": "Should be refused for staleness.",
            },
            fresh=False,
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(self._code(response), "step_up_required")
        created.assert_not_called()

    # ── Reasons ────────────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.create_user", return_value=IDENTITY)
    def test_a_write_without_a_reason_is_refused(self, created):
        """The reason is what makes the audit entry answer "why" a year later."""
        response = self._post(
            USERS,
            {"email": "x@gcc.gov.in", "name": "X", "role": "Viewer", "department": "Cell", "reason": "too short"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._code(response), "invalid_reason")
        created.assert_not_called()

    # ── Passwords ──────────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.set_password", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_replacing_a_password_ends_every_session(self, _found, _set):
        """A reset that leaves an old session signed in has locked nobody out,
        which is the entire reason for performing one."""
        response = self._post(f"{USERS}/{self.officer.id}/password", {"reason": "Credential reported as shared."})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(SessionRevocation.objects.filter(user=self.officer).exists())
        self.assertTrue(AdminAuditEvent.objects.filter(action="credential.password_set").exists())

    @patch("apps.forensics.services.admin_users.set_password", side_effect=SupabaseAdminError("offline"))
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_a_refused_password_change_records_nothing(self, _found, _set):
        response = self._post(f"{USERS}/{self.officer.id}/password", {"reason": "Provider is unreachable."})

        self.assertEqual(response.status_code, 503)
        self.assertFalse(SessionRevocation.objects.filter(user=self.officer).exists())
        self.assertFalse(AdminAuditEvent.objects.filter(action="credential.password_set").exists())

    # ── Self-mutation ──────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.set_password", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_an_administrator_cannot_reset_their_own_credential(self, _found, _set):
        """Doing so locks you out of the console that would have fixed it."""
        response = self._post(f"{USERS}/{self.head.id}/password", {"reason": "Trying to reset my own account."})

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "self_mutation_forbidden")

    @patch("apps.forensics.services.admin_users.set_password", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_a_deputy_can_restore_the_station_head(self, _found, _set):
        """The recovery case the old single-administrator rule made impossible."""
        response = self._post(
            f"{USERS}/{self.head.id}/password",
            {"reason": "Head lost their authenticator device."},
            user=self.deputy,
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(SessionRevocation.objects.filter(user=self.head).exists())

    # ── Authenticator ──────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.delete_factor")
    @patch("apps.forensics.services.admin_users.list_factors", return_value=[])
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_clearing_an_authenticator_also_ends_sessions(self, _found, _list, _delete):
        response = self.client.delete(
            f"{USERS}/{self.officer.id}/factors",
            data=json.dumps({"reason": "Officer changed phone this morning."}),
            content_type="application/json",
            **self._headers(self.head),
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(SessionRevocation.objects.filter(user=self.officer).exists())
        self.assertTrue(AdminAuditEvent.objects.filter(action="credential.authenticator_reset").exists())

    # ── Status ─────────────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.set_ban", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_deactivating_an_account_disables_it_and_ends_its_sessions(self, _found, _ban):
        response = self._post(
            f"{USERS}/{self.officer.id}/status", {"active": False, "reason": "Transferred out of the unit."}
        )

        self.assertEqual(response.status_code, 200)
        self.officer.refresh_from_db()
        self.assertFalse(self.officer.is_active)
        self.assertTrue(SessionRevocation.objects.filter(user=self.officer).exists())

    @patch("apps.forensics.services.admin_users.set_ban", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_one_administrator_may_deactivate_another(self, _found, _ban):
        """Turnover has to work. The organization keeps an administrator
        because the actor is one and cannot act on themselves."""
        response = self._post(
            f"{USERS}/{self.deputy.id}/status", {"active": False, "reason": "Posted to another district."}
        )

        self.assertEqual(response.status_code, 200)
        self.deputy.refresh_from_db()
        self.assertFalse(self.deputy.is_active)
        self.assertTrue(
            UserProfile.objects.filter(
                organization=self.organization, role=UserProfile.Role.ADMIN, user__is_active=True
            ).exists()
        )

    @patch("apps.forensics.services.admin_users.set_ban", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_owner_must_be_transferred_before_deactivation(self, found, ban):
        self.organization.owner = self.deputy
        self.organization.save(update_fields=["owner"])

        response = self._post(
            f"{USERS}/{self.deputy.id}/status",
            {"active": False, "reason": "Posted to another district."},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "owner_transfer_required")
        found.assert_not_called()
        ban.assert_not_called()

    @patch("apps.forensics.services.admin_users.set_ban", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_an_organization_cannot_be_left_without_an_administrator(self, _found, ban):
        """The invariant, approached the only way the API allows.

        Reaching the last-administrator guard through HTTP turns out to be
        impossible, and that is the design working rather than a gap: removing
        the last administrator means acting either on yourself, which is
        refused, or on someone else while you remain one. So the last
        administrator standing is stopped by the self-mutation rule, and the
        guard itself is defence in depth for any future path that is not
        self-mutation gated. It is tested directly in test_admin_audit.py.
        """
        UserProfile.objects.filter(user=self.deputy).update(role=UserProfile.Role.INVESTIGATOR)

        response = self._post(
            f"{USERS}/{self.head.id}/status", {"active": False, "reason": "Attempting to remove the last one."}
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "self_mutation_forbidden")
        self.head.refresh_from_db()
        self.assertTrue(self.head.is_active)
        ban.assert_not_called()

    # ── Roles ──────────────────────────────────────────────────────────────

    def test_changing_a_role_records_both_sides_of_the_change(self):
        response = self._patch(
            f"{USERS}/{self.officer.id}/role", {"role": "Analyst", "reason": "Moved to the analysis desk."}
        )

        self.assertEqual(response.status_code, 200)
        entry = AdminAuditEvent.objects.get(action="user.role_changed")
        self.assertEqual(entry.before_json["role"], "Investigator")
        self.assertEqual(entry.after_json["role"], "Analyst")

    def test_an_administrator_cannot_demote_themselves(self):
        """The same invariant from the role side: the only way to remove the
        last administrator is to be them, and that is refused."""
        UserProfile.objects.filter(user=self.deputy).update(role=UserProfile.Role.INVESTIGATOR)

        response = self._patch(
            f"{USERS}/{self.head.id}/role", {"role": "Investigator", "reason": "Attempting to step down alone."}
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "self_mutation_forbidden")
        self.assertEqual(UserProfile.objects.get(user=self.head).role, UserProfile.Role.ADMIN)

    def test_one_administrator_may_promote_another(self):
        response = self._patch(
            f"{USERS}/{self.officer.id}/role", {"role": "Admin", "reason": "Appointed deputy for the station."}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(UserProfile.objects.get(user=self.officer).role, UserProfile.Role.ADMIN)

    def test_owner_must_be_transferred_before_demotion(self):
        self.organization.owner = self.deputy
        self.organization.save(update_fields=["owner"])

        response = self._patch(
            f"{USERS}/{self.deputy.id}/role",
            {"role": "viewer", "reason": "Posted to another district."},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self._code(response), "owner_transfer_required")
        self.assertEqual(UserProfile.objects.get(user=self.deputy).role, UserProfile.Role.ADMIN)

    # ── Isolation ──────────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.set_password", return_value=IDENTITY)
    @patch("apps.forensics.services.admin_users.find_user_by_email", return_value=IDENTITY)
    def test_an_account_in_another_organization_is_not_found(self, _found, set_password):
        """404 rather than 403: a head at one station must not learn who exists
        at another by watching which identifiers answer differently."""
        from apps.forensics.models import Organization

        other = Organization.objects.create(name="Station B", slug="station-b")
        elsewhere = get_user_model().objects.create_user(username="elsewhere@gcc.gov.in")
        UserProfile.objects.create(user=elsewhere, organization=other, role=UserProfile.Role.VIEWER)

        response = self._post(f"{USERS}/{elsewhere.id}/password", {"reason": "Should not be reachable."})

        self.assertEqual(response.status_code, 404)
        set_password.assert_not_called()

    # ── The chain ──────────────────────────────────────────────────────────

    @patch("apps.forensics.services.admin_users.create_user", return_value=IDENTITY)
    def test_every_write_extends_one_verifiable_chain(self, _created):
        from common.admin_audit import verify_admin_chain

        for index in range(3):
            self._post(
                USERS,
                {
                    "email": f"chain{index}@gcc.gov.in",
                    "name": "Chain",
                    "role": "Viewer",
                    "department": "Cell",
                    "reason": "Recorded for the chain test.",
                },
            )
        self._patch(f"{USERS}/{self.officer.id}/role", {"role": "Analyst", "reason": "Moved to the analysis desk."})

        report = verify_admin_chain(self.organization)

        self.assertEqual(report["eventCount"], 4)
        self.assertTrue(report["verified"])


@SECURE_SETTINGS
class SessionRevocationTests(AdminWriteTestBase):
    """Revoking a session has to stop the token that already exists.

    Netra verifies tokens offline, so revoking at the identity provider alone
    invalidates the refresh token and leaves the access token in the browser
    working until it expires. These pin the part that closes that window.
    """

    def test_a_token_issued_before_revocation_stops_working(self):
        headers = self._headers(self.officer, aal="aal1")
        directory = "/api/cases"
        self.assertNotEqual(self.client.get(directory, **headers).status_code, 401)

        self._post(
            f"{USERS}/{self.officer.id}/sessions/revoke", {"reason": "Device reported lost this morning."}
        )

        # Same token, unchanged and not expired.
        self.assertEqual(self.client.get(directory, **headers).status_code, 401)

    def test_a_token_issued_after_revocation_still_works(self):
        """Revocation must not lock the account out permanently — signing in
        again has to restore it."""
        self._post(f"{USERS}/{self.officer.id}/sessions/revoke", {"reason": "Device reported lost this morning."})

        import time as _time

        _time.sleep(1.1)
        fresh = self._headers(self.officer, aal="aal1")

        self.assertNotEqual(self.client.get("/api/cases", **fresh).status_code, 401)

    def test_revoking_leaves_other_accounts_alone(self):
        other = self._headers(self.deputy)
        self._post(f"{USERS}/{self.officer.id}/sessions/revoke", {"reason": "Device reported lost this morning."})

        self.assertEqual(self.client.get("/api/admin/v1/directory", **other).status_code, 200)

    def test_revocation_is_recorded_in_the_chain(self):
        self._post(f"{USERS}/{self.officer.id}/sessions/revoke", {"reason": "Device reported lost this morning."})

        entry = AdminAuditEvent.objects.get(action="session.revoked")
        self.assertEqual(entry.target_id, "officer@gcc.gov.in")
        self.assertIn("lost", entry.reason)
