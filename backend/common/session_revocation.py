"""Make revoking a session actually revoke it.

Netra verifies Supabase access tokens offline against a public key. That is
what keeps authorization cheap enough to run on every one of 183 routes, and it
is also why revocation at the identity provider does not reach us: GoTrue
invalidates the refresh token, so no new access tokens can be minted, but the
one already sitting in a browser stays valid until it expires.

So "set a new password and revoke all sessions" leaves the session it was meant
to kill alive for the remainder of the access token's life. For an ordinary
product that is a tolerable trade. When the reset is happening *because* an
account is compromised, the window is the whole point of the operation.

Two things close it and both are needed. Shortening the token lifetime in the
Supabase dashboard bounds the window for every path, including ones this module
never sees. This module makes it exact for Netra: a token issued before the
revocation moment is refused, whatever it says about itself.
"""

from __future__ import annotations

from datetime import datetime

from django.utils import timezone

from apps.forensics.models import Organization, SessionRevocation


def revoke_sessions(
    *,
    user_id: int,
    organization: Organization,
    reason: str = "",
    revoked_by_label: str = "",
) -> SessionRevocation:
    """Refuse every token this account already holds.

    One row per account, rewritten rather than appended: only the most recent
    revocation decides anything, and a growing table consulted on every
    authenticated request would cost something for nothing. The audit chain is
    where the history of who revoked what belongs.
    """
    revocation, _ = SessionRevocation.objects.update_or_create(
        user_id=user_id,
        defaults={
            "organization": organization,
            "revoked_at": timezone.now(),
            "reason": reason,
            "revoked_by_label": revoked_by_label,
        },
    )
    return revocation


def token_is_revoked(user, issued_at: datetime | None) -> bool:
    """Whether a token predates its account's most recent revocation.

    A token with no readable issue time is refused when a revocation exists.
    The alternative is accepting a token that cannot prove it was issued after
    the moment an administrator said "this account's sessions end now", which
    is the one thing this function exists to prevent.
    """
    revocation = getattr(user, "netra_session_revocation", None)
    if revocation is None:
        return False
    if issued_at is None:
        return True
    # Tokens carry whole-second issue times while revoked_at has microseconds,
    # so a token minted in the same second as the revocation rounds down and
    # compares as older. The comparison is inclusive, which refuses it — the
    # safe way to be wrong, and it costs at most the remainder of one second
    # before a fresh sign-in is accepted again.
    return issued_at.timestamp() <= revocation.revoked_at.timestamp()
