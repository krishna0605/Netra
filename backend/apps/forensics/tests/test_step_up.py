"""Authenticator freshness.

The distinction under test throughout: aal2 says a second factor was used at
some point in this session; freshness says it was used just now. Only the
second can authorise a destructive action, and every case below is a way the
first could be mistaken for the second.
"""

from datetime import UTC, datetime, timedelta

from django.test import SimpleTestCase, override_settings

from common.step_up import SECOND_FACTOR_METHODS, factor_verified_at, is_fresh


def stamp(moment: datetime) -> int:
    return int(moment.timestamp())


NOW = datetime(2026, 8, 13, 12, 0, 0, tzinfo=UTC)


class FactorTimestampTests(SimpleTestCase):
    def test_reads_the_totp_challenge_time(self):
        amr = [
            {"method": "password", "timestamp": stamp(NOW - timedelta(hours=8))},
            {"method": "totp", "timestamp": stamp(NOW - timedelta(minutes=2))},
        ]

        self.assertEqual(factor_verified_at(amr), NOW - timedelta(minutes=2))

    def test_a_password_alone_establishes_nothing(self):
        """Re-entering a password proves knowledge of a secret that may have
        been written on a card. It is not possession of the device."""
        amr = [{"method": "password", "timestamp": stamp(NOW)}]

        self.assertIsNone(factor_verified_at(amr))

    def test_takes_the_most_recent_of_several_challenges(self):
        amr = [
            {"method": "totp", "timestamp": stamp(NOW - timedelta(hours=3))},
            {"method": "totp", "timestamp": stamp(NOW - timedelta(minutes=1))},
            {"method": "totp", "timestamp": stamp(NOW - timedelta(hours=1))},
        ]

        self.assertEqual(factor_verified_at(amr), NOW - timedelta(minutes=1))

    def test_every_recognised_second_factor_counts(self):
        for method in SECOND_FACTOR_METHODS:
            with self.subTest(method=method):
                self.assertEqual(factor_verified_at([{"method": method, "timestamp": stamp(NOW)}]), NOW)

    def test_method_matching_ignores_case_and_padding(self):
        self.assertEqual(factor_verified_at([{"method": " TOTP ", "timestamp": stamp(NOW)}]), NOW)

    def test_malformed_claims_establish_nothing_rather_than_raising(self):
        """A claim this module cannot read must not become an exception on the
        hot path of every request, nor a value that passes the gate."""
        for claim in (
            None,
            "totp",
            {},
            [],
            [None],
            ["totp"],
            [{"method": "totp"}],
            [{"timestamp": stamp(NOW)}],
            [{"method": "totp", "timestamp": "recently"}],
            [{"method": 7, "timestamp": stamp(NOW)}],
        ):
            with self.subTest(claim=claim):
                self.assertIsNone(factor_verified_at(claim))

    def test_a_boolean_timestamp_is_refused(self):
        """True is an int in Python and would survive a numeric check, landing
        in 1970 — old enough to fail closed, but for the wrong reason."""
        self.assertIsNone(factor_verified_at([{"method": "totp", "timestamp": True}]))

    def test_milliseconds_are_refused_rather_than_read_as_the_year_58000(self):
        """A caller passing milliseconds would otherwise produce a timestamp so
        far in the future that the session never expires. Failing open is the
        one outcome this must not have."""
        self.assertIsNone(factor_verified_at([{"method": "totp", "timestamp": stamp(NOW) * 1000}]))


@override_settings(NETRA_STEP_UP_MAX_AGE_SECONDS=300)
class FreshnessTests(SimpleTestCase):
    def test_a_challenge_within_the_window_is_fresh(self):
        self.assertTrue(is_fresh(NOW - timedelta(minutes=4), now=NOW))

    def test_a_challenge_outside_the_window_is_not(self):
        self.assertFalse(is_fresh(NOW - timedelta(minutes=6), now=NOW))

    def test_the_boundary_is_inclusive(self):
        self.assertTrue(is_fresh(NOW - timedelta(seconds=300), now=NOW))
        self.assertFalse(is_fresh(NOW - timedelta(seconds=301), now=NOW))

    def test_absence_is_a_refusal_not_a_pass(self):
        """The single most important line in this module. Every path that
        cannot establish a timestamp arrives here."""
        self.assertFalse(is_fresh(None, now=NOW))

    def test_small_clock_skew_is_tolerated(self):
        self.assertTrue(is_fresh(NOW + timedelta(seconds=10), now=NOW))

    def test_a_challenge_far_in_the_future_is_refused(self):
        """Either the clock is wrong or the claim is forged. Neither is a
        reason to permit a password reset."""
        self.assertFalse(is_fresh(NOW + timedelta(hours=2), now=NOW))

    @override_settings(NETRA_STEP_UP_MAX_AGE_SECONDS=60)
    def test_the_window_is_configurable(self):
        self.assertFalse(is_fresh(NOW - timedelta(minutes=2), now=NOW))


class SettingsBoundsTests(SimpleTestCase):
    def test_the_window_cannot_be_configured_into_uselessness(self):
        """Below a minute an operator cannot finish a form and will be trained
        to keep their authenticator permanently open, which defeats the
        control. Above an hour it stops being a step-up at all."""
        from django.conf import settings

        self.assertGreaterEqual(settings.NETRA_STEP_UP_MAX_AGE_SECONDS, 60)
        self.assertLessEqual(settings.NETRA_STEP_UP_MAX_AGE_SECONDS, 3600)
