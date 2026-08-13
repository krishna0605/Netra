"""Authenticator freshness, read from the Supabase ``amr`` claim.

There are two different questions an administration console has to ask, and
conflating them is the usual mistake.

    Has this person enrolled a second factor and used it in this session?
        -> the ``aal`` claim. ``aal2`` answers yes.

    Did this person prove possession of that factor *just now*?
        -> this module.

Only the second is a step-up. An administrator who verified their authenticator
at nine in the morning still carries ``aal2`` at five in the afternoon, on the
same session, from an unattended desk. For reading a directory that is fine.
For resetting a colleague's password it is not, which is why destructive
operations ask again and this is what makes the asking mean something.

The timestamp lives in ``amr`` — Supabase's record of which methods
authenticated the session and when:

    "amr": [{"method": "password", "timestamp": 1786600000},
            {"method": "totp",     "timestamp": 1786600042}]

Only second-factor methods count. Re-entering a password proves knowledge of a
secret that may have been written down or reused; it does not prove possession
of the device, which is the entire point of the second factor.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from django.conf import settings


# Methods that demonstrate possession. "password", "email", "magiclink",
# "recovery" and the OAuth family are deliberately absent: they re-prove
# knowledge or delegate to another issuer, and neither is a step-up.
SECOND_FACTOR_METHODS = frozenset({"totp", "mfa", "webauthn", "phone"})

# A reference point below which a value is a bug rather than a date. Supabase
# emits seconds; a caller passing milliseconds would otherwise land in the year
# 58000 and read as permanently fresh, which fails open.
_MIN_PLAUSIBLE_EPOCH = 1_000_000_000  # 2001-09-09
_MAX_PLAUSIBLE_EPOCH = 4_102_444_800  # 2100-01-01


def factor_verified_at(amr: Any) -> datetime | None:
    """The most recent second-factor challenge in an ``amr`` claim.

    Returns None when the claim is absent, malformed, or records no
    second-factor method. None means "cannot be established", never "fine" —
    every caller must treat it as a refusal.
    """
    if not isinstance(amr, (list, tuple)):
        return None

    latest: float | None = None
    for entry in amr:
        if not isinstance(entry, dict):
            continue
        method = entry.get("method")
        if not isinstance(method, str) or method.strip().lower() not in SECOND_FACTOR_METHODS:
            continue
        stamp = entry.get("timestamp")
        # Booleans are ints in Python and would sail through a numeric check.
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
            continue
        if not _MIN_PLAUSIBLE_EPOCH <= stamp <= _MAX_PLAUSIBLE_EPOCH:
            continue
        if latest is None or stamp > latest:
            latest = stamp

    return datetime.fromtimestamp(latest, UTC) if latest is not None else None


def step_up_max_age_seconds() -> int:
    return int(getattr(settings, "NETRA_STEP_UP_MAX_AGE_SECONDS", 300))


def is_fresh(verified_at: datetime | None, *, now: datetime | None = None) -> bool:
    """Whether a challenge is recent enough to authorise a destructive action."""
    if verified_at is None:
        return False
    moment = now or datetime.now(UTC)
    age = (moment - verified_at).total_seconds()
    # A challenge timestamped in the future is a clock problem or a forged
    # claim. Small skew is tolerated because clocks genuinely drift; beyond
    # that, refuse rather than trust it.
    if age < -30:
        return False
    return age <= step_up_max_age_seconds()
