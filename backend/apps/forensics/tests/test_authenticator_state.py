"""The roster's authenticator column has to be answerable, or say so.

It reported "Not enrolled" for every account in the directory, including
accounts that had just completed an administrative action by typing a code from
the authenticator the column claimed did not exist. The cause was structural
rather than a bad value: enrolment was read from a key GoTrue's admin *list*
endpoint does not return, so the expression evaluated to "no" for everyone and
could never have evaluated to anything else.

These cover the three answers the column has to be able to give, because the
one that used to be missing is the one that matters most operationally.
"""

from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from apps.forensics.services.admin_directory import _mfa_state, _supabase_identities
from common.supabase_admin import SupabaseAdminUser


def _account(identifier: str, email: str, mfa_state: str = "unenrolled") -> SupabaseAdminUser:
    return SupabaseAdminUser(
        id=identifier,
        email=email,
        invited_at="",
        email_confirmed_at="2026-08-01T00:00:00Z",
        last_sign_in_at="2026-08-18T00:00:00Z",
        mfa_state=mfa_state,
    )


ENROLLED = _account("11111111-1111-4111-8111-111111111111", "enrolled@netra.test")
BARE = _account("22222222-2222-4222-8222-222222222222", "bare@netra.test")


class MfaStateResolutionTests(SimpleTestCase):
    def test_a_verified_factor_is_reported_even_though_the_listing_omits_it(self):
        # The listing says "unenrolled" for both because it carries no factors
        # at all. The factor table is what separates them.
        self.assertEqual(_mfa_state(ENROLLED, {ENROLLED.id}, True), "verified")
        self.assertEqual(_mfa_state(BARE, {ENROLLED.id}, True), "unenrolled")

    def test_an_unreadable_factor_table_reports_unknown_rather_than_a_gap(self):
        # "Unenrolled" is a finding an administrator acts on, and acting on it
        # means resetting an authenticator that may be working perfectly well.
        # A failed read must not be able to produce that instruction.
        self.assertEqual(_mfa_state(ENROLLED, set(), False), "unknown")
        self.assertEqual(_mfa_state(BARE, set(), False), "unknown")

    def test_a_listing_that_does_carry_factors_is_believed(self):
        # If a future GoTrue includes factors in the list payload, that answer
        # stands rather than being overridden by a second lookup.
        carried = _account("33333333-3333-4333-8333-333333333333", "carried@netra.test", "verified")
        self.assertEqual(_mfa_state(carried, set(), True), "verified")


@override_settings(SUPABASE_URL="https://project.supabase.co", SUPABASE_SECRET_KEY="secret")
class IdentityAssemblyTests(SimpleTestCase):
    def test_enrolment_comes_from_the_factor_table_not_the_listing(self):
        with (
            patch(
                "apps.forensics.services.admin_directory.list_users",
                return_value=([ENROLLED, BARE], None),
            ),
            patch(
                "apps.forensics.services.admin_directory.verified_factor_owners",
                return_value=({ENROLLED.id}, True),
            ),
        ):
            identities, known = _supabase_identities()

        self.assertTrue(known)
        self.assertEqual(identities["enrolled@netra.test"].mfa_state, "verified")
        self.assertEqual(identities["bare@netra.test"].mfa_state, "unenrolled")

    def test_the_factor_lookup_is_one_call_for_the_whole_roster(self):
        # Asking the Admin API per user would answer correctly and turn one
        # console load into a request per row on a page that already fans out.
        with (
            patch(
                "apps.forensics.services.admin_directory.list_users",
                return_value=([ENROLLED, BARE], None),
            ),
            patch(
                "apps.forensics.services.admin_directory.verified_factor_owners",
                return_value=({ENROLLED.id}, True),
            ) as lookup,
        ):
            _supabase_identities()

        lookup.assert_called_once_with([ENROLLED.id, BARE.id])
