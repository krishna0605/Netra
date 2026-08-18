"""Authenticator enrolment, read from where GoTrue actually keeps it.

The administration console showed every account as "Not enrolled" — including
accounts that had completed a step-up with a working authenticator minutes
earlier. The cause is a property of Supabase's Auth Admin API rather than of
the data: ``GET /admin/users`` returns a page of users with no ``factors``
array on each one. Only ``GET /admin/users/{id}`` carries factors. The roster's
enrolment column was therefore derived from a key that is never present, and
answered "no" for everybody.

Asking per user would give the right answer at the cost of one request per row
on a page that already fans out. GoTrue keeps enrolment in ``auth.mfa_factors``
on the same PostgreSQL instance Django is already connected to, so this reads
it directly — the approach common/supabase_sessions.py takes, for the same
reason, with the same two boundaries.

It is read-only and narrow: one column from one table, filtered to the
identities the console is already displaying. Nothing here writes; unenrolling
an authenticator stays with the Admin API, which has an endpoint for it.

And it fails closed as *unknown*, never as *unenrolled*. That distinction
carries more weight than it looks. "Unenrolled" is a finding an administrator
is expected to act on, and acting on it means resetting an authenticator and
walking somebody through enrolment again. Reporting it because a query failed
sends an operator to repair something that was never broken.
"""

from __future__ import annotations

import logging

from django.db import DatabaseError, connection

logger = logging.getLogger(__name__)


def _readable() -> bool:
    return connection.vendor == "postgresql"


def verified_factor_owners(supabase_user_ids: list[str]) -> tuple[set[str], bool]:
    """Which of these identities hold a verified authenticator.

    Returns the ids and whether the read succeeded. An empty set with ``True``
    means nobody is enrolled; an empty set with ``False`` means the question
    could not be answered, and the caller must not render the two the same way.
    """
    if not _readable():
        return set(), False
    if not supabase_user_ids:
        return set(), True

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT DISTINCT user_id::text
                  FROM auth.mfa_factors
                 WHERE status::text = 'verified'
                   AND user_id::text = ANY(%s)
                """,
                [list(supabase_user_ids)],
            )
            rows = cursor.fetchall()
    except DatabaseError as problem:
        # Most often a database role without rights on the auth schema, which
        # is a deployment choice rather than a fault. Recorded once, quietly,
        # and reported to the caller as "could not tell".
        logger.info("auth.mfa_factors is not readable: %s", problem.__class__.__name__)
        return set(), False

    return {row[0] for row in rows if row[0]}, True
