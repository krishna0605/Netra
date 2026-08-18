"""Reading live sessions out of GoTrue's own table.

The interesting cases are the ones where the answer is "cannot tell". An empty
sessions table means either nobody is signed in or nobody can find out, and a
console that renders those identically is worse than one that renders neither.
"""

from datetime import UTC, datetime
from unittest.mock import patch

from django.db import connection
from django.test import SimpleTestCase

from common import supabase_sessions
from common.supabase_sessions import LiveSession, _mask, list_sessions, session_payload


class MaskingTests(SimpleTestCase):
    def test_an_address_keeps_enough_to_recognise_a_place(self):
        """An administrator needs to tell "the station" from "somewhere else".
        The last octet adds nothing to that and turns a session list into a
        record of where officers physically are."""
        self.assertEqual(_mask("203.0.113.42"), "203.0.113.…")

    def test_ipv6_is_shortened_too(self):
        self.assertTrue(_mask("2001:db8:85a3:0:0:8a2e:370:7334").endswith("::…"))

    def test_a_missing_address_stays_missing(self):
        self.assertEqual(_mask(""), "")

    def test_an_unparseable_address_is_dropped_rather_than_shown_raw(self):
        self.assertEqual(_mask("not-an-address"), "")


class AvailabilityTests(SimpleTestCase):
    databases = {"default"}

    def test_an_empty_identity_list_is_answered_without_a_query(self):
        rows, status = list_sessions([])

        self.assertEqual(rows, [])
        # "live" and not "unavailable": an organization whose people are all
        # signed out is a fact, not a failure to establish one.
        self.assertEqual(status, "live" if connection.vendor == "postgresql" else "unavailable_not_postgres")

    def test_a_backend_without_the_table_says_so_rather_than_raising(self):
        """A page with nine other things on it must not fail because one of
        them is unavailable."""
        rows, status = list_sessions(["11111111-2222-3333-4444-555555555555"])

        self.assertEqual(rows, [])
        self.assertTrue(status.startswith("unavailable"))

    def test_the_success_path_answers_with_rows_and_a_status(self):
        """The path that reads actual sessions, which neither of the tests above
        reaches: SQLite stops at _readable, and a bare PostgreSQL container has
        no auth schema, so both take an early return.

        It returned a bare list instead of the pair every other path returns.
        The caller unpacks two values, so it raised ValueError the moment the
        table held any number of rows other than two, and the administration
        console — nine screens behind one read — answered 500.
        """
        started = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)
        refreshed = datetime(2026, 8, 14, 9, 40, tzinfo=UTC)
        # Three rows: enough that unpacking the list itself cannot coincidentally
        # succeed, which is what hid this for a pair of sessions.
        stored = [
            (f"sess-{n}", f"user-{n}", "aal2", started, refreshed, "Mozilla/5.0", "203.0.113.42")
            for n in range(3)
        ]

        with patch.object(supabase_sessions, "_readable", return_value=True), patch.object(
            supabase_sessions, "connection"
        ) as fake_connection:
            cursor = fake_connection.cursor.return_value.__enter__.return_value
            cursor.fetchall.return_value = stored

            result = list_sessions([f"user-{n}" for n in range(3)])

        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

        rows, status = result
        self.assertEqual(status, "live")
        self.assertEqual([row.id for row in rows], ["sess-0", "sess-1", "sess-2"])
        self.assertEqual(rows[0].ip, "203.0.113.…")


class PayloadTests(SimpleTestCase):
    def test_the_console_shape_carries_what_the_screen_renders(self):
        session = LiveSession(
            id="sess-1",
            supabase_user_id="11111111-2222-3333-4444-555555555555",
            aal="aal2",
            started_at="2026-08-14T09:00:00+00:00",
            last_seen_at="2026-08-14T09:40:00+00:00",
            user_agent="Mozilla/5.0",
            ip="203.0.113.…",
        )

        row = session_payload(session, user_id=41, name="Insp. C. Desai", email="c.desai@gcc.gov.in")

        self.assertEqual(row["userId"], 41)
        self.assertEqual(row["aal"], "aal2")
        self.assertEqual(row["origin"], "Mozilla/5.0")
        self.assertEqual(row["ipHint"], "203.0.113.…")

    def test_an_unknown_assurance_level_reads_as_the_weaker_one(self):
        """Anything that is not demonstrably aal2 is shown as aal1. Guessing
        upward would tell an administrator a session is better protected than
        it is."""
        session = LiveSession("s", "u", "", "", "", "", "")

        self.assertEqual(session_payload(session, user_id=1, name="", email="")["aal"], "aal1")

    def test_a_client_that_did_not_identify_itself_is_labelled(self):
        session = LiveSession("s", "u", "aal1", "", "", "", "")

        self.assertEqual(session_payload(session, user_id=1, name="", email="")["origin"], "Unknown client")
