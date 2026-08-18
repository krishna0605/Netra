"""Deliver an issued credential to the officer it belongs to.

Netra has never sent mail of its own. Supabase's invitation is the only message
the platform has ever produced, and it carries a magic link rather than a
credential, so a deployment whose officers cannot receive that invitation had no
way to hand an account over except in person.

This module exists for that case. It is deliberately small and deliberately
inert unless a deployment configures a mail host: an administration console that
silently fails to send a credential is worse than one that says it cannot.

A word on what this sends. Mailing a credential to the address it signs in with
puts both halves of the login in one mailbox, which is why the console has
always told the operator to hand credentials over in person instead. That
guidance still stands and is still printed on the handover panel. This path
exists because a deployment without reachable officers has no better option, and
the choice belongs to the operator rather than to this module. It is off unless
NETRA_CREDENTIAL_EMAIL_ENABLED is set, and the credential is still shown on
screen so delivery never becomes the only copy.
"""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass

from django.conf import settings
from django.core.mail import EmailMessage, get_connection

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Delivery:
    """What happened, in terms the console can render.

    `sent` is the only field that asserts anything. `reason` explains a false so
    the operator knows whether to configure a mail host or to walk down the
    corridor, and is never shown as a success.
    """

    sent: bool
    reason: str = ""


SUBJECT = "Your Netra account"

BODY = """\
{name},

An account has been created for you on Netra.

    Address:  {email}
    Password: {password}
    Sign in:  {url}

You will be asked to enrol an authenticator the first time you sign in. Netra
cannot be entered without one.

{rotation}

If you were not expecting this message, tell the person who administers Netra
for your unit. Do not forward it.
"""

ROTATION_ADMIN_HELD = """\
This password does not expire. Your administrator can replace it, and doing so
will end every session you have open."""

ROTATION_SELF_SERVICE = """\
You will be asked to replace this password immediately after signing in. It
cannot be used again afterwards."""


def _configured() -> tuple[bool, str]:
    if not getattr(settings, "NETRA_CREDENTIAL_EMAIL_ENABLED", False):
        return False, "credential_email_disabled"
    if not getattr(settings, "EMAIL_HOST", ""):
        return False, "no_mail_host_configured"
    if not getattr(settings, "DEFAULT_FROM_EMAIL", ""):
        return False, "no_sender_address_configured"
    return True, ""


def send_credential(
    *,
    email: str,
    name: str,
    password: str,
    must_change_password: bool,
) -> Delivery:
    """Mail one credential. Never raises into the request that issued it.

    A failure here must not undo the account that was just created, and must not
    be reported as a success. The caller receives a Delivery either way and the
    console tells the operator which one it got.
    """
    ok, reason = _configured()
    if not ok:
        return Delivery(sent=False, reason=reason)

    message = EmailMessage(
        subject=SUBJECT,
        body=BODY.format(
            name=(name or "Officer").strip(),
            email=email,
            password=password,
            url=getattr(settings, "NETRA_PUBLIC_BASE_URL", "") or "your Netra console",
            rotation=ROTATION_SELF_SERVICE if must_change_password else ROTATION_ADMIN_HELD,
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[email],
        connection=get_connection(fail_silently=False),
    )
    try:
        delivered = message.send(fail_silently=False)
    except (smtplib.SMTPException, OSError, ValueError) as problem:
        # The address is recorded; the credential never is.
        logger.error("credential mail failed for %s: %s", email, problem.__class__.__name__)
        return Delivery(sent=False, reason="mail_host_refused")
    if not delivered:
        return Delivery(sent=False, reason="mail_host_accepted_nothing")
    return Delivery(sent=True)
