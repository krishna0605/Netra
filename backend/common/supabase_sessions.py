"""Live sessions, read from where GoTrue actually keeps them.

The administration console has shown an empty sessions table since it was
built, marked "pending", because Supabase's Auth Admin REST API has no
endpoint that lists a user's sessions. That was true and it stayed true.

What changed is noticing that we do not need the REST API. Netra's Django
connects to the same PostgreSQL instance Supabase runs GoTrue on, and GoTrue
keeps every live session in ``auth.sessions``. Reading it is a query, not an
integration.

Two boundaries are worth stating because this reaches into another service's
schema.

It is read-mostly and narrow: five columns from one table, plus a delete of a
single row when a session is revoked. Deleting that row is exactly what
Supabase's own ``auth.admin.signOut`` does — the refresh token dies with it —
so this is the platform's own mechanism rather than an invention on top of it.

And it fails closed and quietly. A deployment on SQLite, a database role
without rights on the auth schema, or a future GoTrue that renames the table
all produce "unavailable" rather than an exception on a page that has nine
other things to show. The console reports which of those it is instead of
showing an empty table that could mean either nobody is signed in or nobody
can tell.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from django.db import DatabaseError, connection

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LiveSession:
    id: str
    supabase_user_id: str
    aal: str
    started_at: str
    last_seen_at: str
    user_agent: str
    ip: str


def _readable() -> bool:
    return connection.vendor == "postgresql"


def _mask(ip: str) -> str:
    """Enough to recognise a location, not enough to be a record of one.

    An administrator needs to tell "signed in from the station" from "signed in
    from somewhere else". The last octet adds nothing to that judgement and
    turns a session list into a log of where officers physically are.
    """
    if not ip:
        return ""
    if ":" in ip:  # IPv6
        head = ip.split(":")[:3]
        return ":".join(head) + "::…"
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".…" if len(parts) == 4 else ""


def list_sessions(supabase_user_ids: list[str]) -> tuple[list[LiveSession], str]:
    """Sessions for the given Supabase identities.

    Returns the rows and a status: "live", or a reason it could not be read.
    The reason is carried to the console rather than logged and swallowed,
    because an empty table with no explanation is indistinguishable from an
    organization where nobody happens to be signed in.
    """
    if not _readable():
        return [], "unavailable_not_postgres"
    if not supabase_user_ids:
        return [], "live"

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id::text,
                       user_id::text,
                       COALESCE(aal::text, 'aal1'),
                       created_at,
                       COALESCE(refreshed_at, updated_at, created_at),
                       COALESCE(user_agent, ''),
                       COALESCE(host(ip), '')
                  FROM auth.sessions
                 WHERE user_id::text = ANY(%s)
                   AND (not_after IS NULL OR not_after > NOW())
                 ORDER BY created_at DESC
                 LIMIT 500
                """,
                [list(supabase_user_ids)],
            )
            rows = cursor.fetchall()
    except DatabaseError as problem:
        # Most often a database role without rights on the auth schema, which
        # is a deployment choice rather than a fault. Recorded once, at a level
        # that does not shout, and reported to the console as a state.
        logger.info("auth.sessions is not readable: %s", problem.__class__.__name__)
        return [], "unavailable_no_access"

    return [
        LiveSession(
            id=row[0],
            supabase_user_id=row[1],
            aal=row[2],
            started_at=row[3].isoformat() if row[3] else "",
            last_seen_at=row[4].isoformat() if row[4] else "",
            user_agent=(row[5] or "")[:200],
            ip=_mask(row[6] or ""),
        )
        for row in rows
    ], "live"


def end_session(session_id: str) -> bool:
    """Delete one session. Returns whether a row was actually removed.

    The same thing GoTrue does on sign-out: the refresh token dies with the
    row, so no further access tokens can be minted for it. An access token
    already issued survives until it expires, which is why the account-level
    revocation keeps its own denylist — see common/session_revocation.py.
    """
    if not _readable():
        return False
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM auth.sessions WHERE id = %s", [session_id])
            return cursor.rowcount > 0
    except DatabaseError as problem:
        logger.info("auth.sessions could not be modified: %s", problem.__class__.__name__)
        return False


def end_sessions_for(supabase_user_ids: list[str]) -> int:
    """Delete every session belonging to the given identities."""
    if not _readable() or not supabase_user_ids:
        return 0
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM auth.sessions WHERE user_id::text = ANY(%s)", [list(supabase_user_ids)])
            return cursor.rowcount
    except DatabaseError as problem:
        logger.info("auth.sessions could not be modified: %s", problem.__class__.__name__)
        return 0


def session_payload(session: LiveSession, *, user_id: int, name: str, email: str) -> dict[str, Any]:
    return {
        "id": session.id,
        "userId": user_id,
        "userName": name,
        "userEmail": email,
        "origin": session.user_agent or "Unknown client",
        "aal": "aal2" if session.aal == "aal2" else "aal1",
        "startedAt": session.started_at,
        "lastSeenAt": session.last_seen_at,
        "ipHint": session.ip,
    }
