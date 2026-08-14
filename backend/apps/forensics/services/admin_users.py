"""Administrative operations on accounts.

Each one changes two systems that cannot be changed together: Supabase Auth
holds the credential, Netra's database holds the authorization. There is no
transaction spanning both, so the order matters and is the same everywhere —
call Supabase first, and only record locally once it has succeeded.

Getting that backwards produces the worse failure. A local row saying an
account was deactivated while the credential still works is a lie the console
will keep telling; the reverse is a credential change with no local record,
which is visible the moment anyone looks and can be repeated safely.

Every operation here is sealed into the audit chain in the same transaction as
its local effect, so a change that happened without a record, or a record of a
change that did not happen, cannot survive a rollback.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from typing import Any

from django.contrib.auth import get_user_model
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.forensics.models import Organization, Role, RolePermission, UserProfile
from apps.forensics.services.administration import (
    AdministrationProblem,
    ensure_administrator_remains,
    ensure_console_mutation_allowed,
    require_recent_factor,
)
from apps.forensics.services.console_context import revoke_user_console_contexts
from common.admin_audit import record_admin_event
from common.audit import ROLE_PERMISSIONS, Actor
from common.permissions import bump_permissions_version, ceiling_for
from common.session_revocation import revoke_sessions
from common.supabase_sessions import end_session, end_sessions_for
from common.supabase_admin import (
    SupabaseAdminConflict,
    SupabaseAdminError,
    create_user,
    delete_factor,
    find_user_by_email,
    list_factors,
    set_ban,
    set_password,
    invite_user,
)


# Excludes characters that are misread when a password is written on a handover
# note or dictated over a radio: I, l, O, 0, 1. An administrator setting a
# credential for a colleague in another building has to be able to say it.
_ALPHABET = "".join(
    c for c in string.ascii_letters + string.digits + "!@#$%^&*-_=+" if c not in "Il0O1"
)
_PASSWORD_LENGTH = 20
_MIN_REASON, _MAX_REASON = 10, 1000

ASSIGNABLE_ROLES = {
    UserProfile.Role.INVESTIGATOR,
    UserProfile.Role.ANALYST,
    UserProfile.Role.VIEWER,
    UserProfile.Role.ADMIN,
}


def resolve_role_assignment(organization: Organization, value: str) -> tuple[Role | None, str]:
    """Resolve either a role slug or its display name to the database role.

    During the dual-write transition, standard roles retain their legacy value
    while custom roles fall back to Viewer in that column. Authorization reads
    role_ref first, so a rollback is fail-closed instead of granting a custom
    role more authority than the old release understands.
    """
    requested = (value or "").strip()
    role_ref = Role.objects.filter(organization=organization, slug=requested).first()
    if role_ref is None:
        role_ref = Role.objects.filter(organization=organization, name__iexact=requested).first()

    if role_ref is not None:
        legacy_role = role_ref.name if role_ref.name in ASSIGNABLE_ROLES else UserProfile.Role.VIEWER
        return role_ref, legacy_role
    if requested in ASSIGNABLE_ROLES:
        # Compatibility for organizations created before their system-role rows
        # are provisioned. The resolver safely falls back to the code catalogue.
        return None, requested
    raise AdministrationProblem("invalid_role", "Select a role this console can assign.", 400)


def ensure_role_within_ceiling(actor: Actor, role_ref: Role | None, legacy_role: str) -> None:
    requested = (
        set(RolePermission.objects.filter(role=role_ref).values_list("permission_id", flat=True))
        if role_ref is not None
        else set(ROLE_PERMISSIONS.get(legacy_role, set()))
    )
    beyond = requested - ceiling_for(actor)
    if beyond:
        raise AdministrationProblem(
            "beyond_your_permissions",
            f"You cannot assign a role containing permissions you do not hold: {', '.join(sorted(beyond))}.",
            403,
        )


@dataclass(frozen=True)
class AccountChange:
    profile: UserProfile
    password: str = ""


_MIN_PASSWORD, _MAX_PASSWORD = 12, 128


def generate_password() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(_PASSWORD_LENGTH))


def resolve_password(candidate: str | None) -> str:
    """Use the administrator's password if they typed one, else generate.

    The console offers a generated password and lets it be replaced, because an
    administrator sometimes needs to set a specific credential. Strength is
    therefore checked here rather than only in the browser: a rule enforced in
    JavaScript is a rule that holds until someone posts to the endpoint
    directly, which is precisely when it matters.

    Length carries most of the weight. Character-class rules produce
    "Password1!" and stop there, so the floor is high enough that a short
    password fails whatever classes it mixes, and three of four classes is
    asked for on top rather than instead.
    """
    candidate = (candidate or "").strip()
    if not candidate:
        return generate_password()
    if not _MIN_PASSWORD <= len(candidate) <= _MAX_PASSWORD:
        raise AdministrationProblem(
            "weak_password",
            f"A password between {_MIN_PASSWORD} and {_MAX_PASSWORD} characters is required.",
            400,
        )
    classes = sum(
        (
            any(c.islower() for c in candidate),
            any(c.isupper() for c in candidate),
            any(c.isdigit() for c in candidate),
            any(not c.isalnum() for c in candidate),
        )
    )
    if classes < 3:
        raise AdministrationProblem(
            "weak_password",
            "Use at least three of: lowercase, uppercase, digits, symbols.",
            400,
        )
    return candidate


def require_reason(reason: str) -> str:
    """Shared with admin_permissions: every administrative write carries one."""
    reason = (reason or "").strip()
    if not _MIN_REASON <= len(reason) <= _MAX_REASON:
        raise AdministrationProblem(
            "invalid_reason",
            f"A reason between {_MIN_REASON} and {_MAX_REASON} characters is required.",
            400,
        )
    return reason


def resolve_target(actor: Actor, user_id: int) -> UserProfile:
    profile = (
        UserProfile.objects.select_related("user", "organization")
        .filter(user_id=user_id, organization_id=actor.organization_id)
        .first()
    )
    if profile is None:
        # 404 rather than 403: an administrator of one station must not be able
        # to discover who exists at another by watching which identifiers
        # answer differently.
        raise AdministrationProblem("resource_not_found", "The requested resource was not found.", 404)
    return profile


def _upstream(problem: SupabaseAdminError) -> AdministrationProblem:
    if isinstance(problem, SupabaseAdminConflict):
        return AdministrationProblem("identity_conflict", "The identity provider rejected the change.", 409)
    return AdministrationProblem(
        "identity_provider_unavailable",
        "The identity provider is temporarily unavailable. No change was made.",
        503,
    )


def _supabase_id(profile: UserProfile) -> str:
    identity = find_user_by_email(profile.user.email or profile.user.get_username())
    if identity is None or not identity.id:
        raise AdministrationProblem(
            "identity_not_found",
            "This account has no identity at the provider.",
            409,
        )
    return identity.id


def provision_account(
    *,
    actor: Actor,
    organization: Organization,
    email: str,
    name: str,
    role: str,
    department: str,
    reason: str,
    password: str | None = None,
) -> AccountChange:
    """Create an account with a password the administrator hands over.

    Deliberately not the invitation flow. Invitations need an approved custom
    SMTP domain the deployment does not have, so an invited officer would wait
    on an email that never arrives.
    """
    require_recent_factor(actor)
    ensure_console_mutation_allowed(actor)
    reason = require_reason(reason)

    email = (email or "").strip().lower()
    if not email or "@" not in email or len(email) > 320:
        raise AdministrationProblem("invalid_email", "A valid official email address is required.", 400)
    role_ref, legacy_role = resolve_role_assignment(organization, role)
    ensure_role_within_ceiling(actor, role_ref, legacy_role)

    User = get_user_model()
    if User.objects.filter(username__iexact=email).exists():
        raise AdministrationProblem("email_in_use", "An account with that address already exists.", 409)

    if password:
        raise AdministrationProblem(
            "password_not_accepted",
            "Temporary credentials are generated by Netra and cannot be selected by an administrator.",
            400,
        )
    try:
        if settings.NETRA_AUTH_INVITATIONS_ENABLED:
            identity = invite_user(email, redirect_to=settings.NETRA_AUTH_INVITE_REDIRECT_URL)
            password = ""
        else:
            password = generate_password()
            identity = create_user(email, password)
    except SupabaseAdminError as problem:
        raise _upstream(problem) from problem

    with transaction.atomic():
        user = User.objects.create(username=email, email=email, is_active=True)
        user.set_unusable_password()
        user.save(update_fields=["password"])
        profile = UserProfile.objects.create(
            user=user,
            organization=organization,
            role=legacy_role,
            role_ref=role_ref,
            display_name=(name or "").strip()[:160],
            department=(department or "").strip()[:160] or "Gujarat Cyber Crime Cell",
            must_change_password=bool(password),
            mfa_reset_required=True,
        )
        record_admin_event(
            organization=organization,
            actor=actor,
            action="user.created",
            target_type="User",
            target_id=email,
            after={
                "role": role_ref.name if role_ref else legacy_role,
                "department": profile.department,
                "supabaseId": identity.id,
            },
            reason=reason,
        )
    return AccountChange(profile=profile, password=password)


def replace_password(
    *, actor: Actor, organization: Organization, user_id: int, reason: str, password: str | None = None
) -> AccountChange:
    """Set a new password and end every session the account already holds.

    The revocation is not optional. A password reset that leaves an existing
    session signed in has not locked anybody out, which is the entire reason
    for performing one.
    """
    require_recent_factor(actor)
    profile = resolve_target(actor, user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)

    if password:
        raise AdministrationProblem(
            "password_not_accepted",
            "Temporary credentials are generated by Netra and cannot be selected by an administrator.",
            400,
        )
    password = generate_password()
    try:
        set_password(_supabase_id(profile), password)
    except SupabaseAdminError as problem:
        raise _upstream(problem) from problem

    with transaction.atomic():
        UserProfile.objects.filter(pk=profile.pk).update(must_change_password=True)
        revoke_user_console_contexts(profile.user_id, "password_changed")
        revoke_sessions(
            user_id=profile.user_id,
            organization=organization,
            reason=reason,
            revoked_by_label=actor.user,
        )
        record_admin_event(
            organization=organization,
            actor=actor,
            action="credential.password_set",
            target_type="User",
            target_id=profile.user.email or profile.user.get_username(),
            # The password itself is never written here, and there is nowhere
            # in this function it could be: it is returned once to the caller
            # and held nowhere else.
            after={"sessionsRevoked": True, "passwordReplaced": True},
            reason=reason,
        )
    return AccountChange(profile=profile, password=password)


def clear_authenticator(*, actor: Actor, organization: Organization, user_id: int, reason: str) -> UserProfile:
    """Remove enrolled second factors so the account can enrol again.

    The most-used operation in practice: an officer changes phone, or loses one.
    """
    require_recent_factor(actor)
    profile = resolve_target(actor, user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)

    identity_id = _supabase_id(profile)
    try:
        factors = list_factors(identity_id)
        for factor in factors:
            delete_factor(identity_id, factor.id)
    except SupabaseAdminError as problem:
        raise _upstream(problem) from problem

    with transaction.atomic():
        UserProfile.objects.filter(pk=profile.pk).update(mfa_reset_required=True)
        revoke_user_console_contexts(profile.user_id, "mfa_reset")
        revoke_sessions(
            user_id=profile.user_id,
            organization=organization,
            reason=reason,
            revoked_by_label=actor.user,
        )
        record_admin_event(
            organization=organization,
            actor=actor,
            action="credential.authenticator_reset",
            target_type="User",
            target_id=profile.user.email or profile.user.get_username(),
            before={"factors": len(factors)},
            after={"factors": 0, "sessionsRevoked": True},
            reason=reason,
        )
    return profile


def set_account_active(
    *, actor: Actor, organization: Organization, user_id: int, active: bool, reason: str
) -> UserProfile:
    """Disable or restore an account.

    A ban at the provider, never a delete. Deleting the identity would orphan
    every custody and audit row naming it, and those are evidence-handling
    records that must keep resolving to a person long after they have left.
    """
    require_recent_factor(actor)
    profile = resolve_target(actor, user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)

    if not active and profile.role == UserProfile.Role.ADMIN:
        if organization.owner_id == profile.user_id:
            raise AdministrationProblem(
                "owner_transfer_required",
                "Transfer organization ownership before deactivating this account.",
                409,
            )
        ensure_administrator_remains(organization, losing_user_id=profile.user_id)

    try:
        set_ban(_supabase_id(profile), banned=not active)
    except SupabaseAdminError as problem:
        raise _upstream(problem) from problem

    with transaction.atomic():
        get_user_model().objects.filter(pk=profile.user_id).update(is_active=active)
        revoke_user_console_contexts(profile.user_id, "account_status_changed")
        if not active:
            revoke_sessions(
                user_id=profile.user_id,
                organization=organization,
                reason=reason,
                revoked_by_label=actor.user,
            )
        record_admin_event(
            organization=organization,
            actor=actor,
            action="user.reactivated" if active else "user.deactivated",
            target_type="User",
            target_id=profile.user.email or profile.user.get_username(),
            before={"active": not active},
            after={"active": active},
            reason=reason,
        )
    profile.refresh_from_db()
    return profile


def end_sessions(*, actor: Actor, organization: Organization, user_id: int, reason: str) -> UserProfile:
    """End every session this account holds, on both sides.

    The denylist refuses the access tokens Netra already trusts; deleting the
    GoTrue rows kills the refresh tokens behind them. Doing only the first
    leaves the account able to mint new tokens; doing only the second leaves
    the current one working until it expires.
    """
    require_recent_factor(actor)
    profile = resolve_target(actor, user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)

    # The GoTrue rows are the better half of this, but the denylist is the half
    # Netra owns. If the identity provider cannot be reached the account is
    # still refused here on the next request, which is the guarantee that
    # matters most; failing the whole operation would leave a compromised
    # session alive because a lookup timed out.
    try:
        identity = find_user_by_email(profile.user.email or profile.user.get_username())
        if identity and identity.id:
            end_sessions_for([identity.id])
    except SupabaseAdminError:
        pass

    with transaction.atomic():
        revoke_user_console_contexts(profile.user_id, "sessions_revoked")
        revoke_sessions(
            user_id=profile.user_id,
            organization=organization,
            reason=reason,
            revoked_by_label=actor.user,
        )
        record_admin_event(
            organization=organization,
            actor=actor,
            action="session.revoked",
            target_type="User",
            target_id=profile.user.email or profile.user.get_username(),
            after={"revokedAt": timezone.now().isoformat()},
            reason=reason,
        )
    return profile


def revoke_one_session(*, actor: Actor, organization: Organization, session_id: str, reason: str) -> bool:
    """End a single sign-in without touching the account's other sessions.

    Deliberately not step-up gated. Ending one session is small, recoverable
    and often urgent — an officer reports a laptop left open in a canteen — and
    a prompt there buys nothing while costing the seconds that matter.
    """
    ensure_console_mutation_allowed(actor)
    reason = require_reason(reason)

    if not end_session(session_id):
        raise AdministrationProblem("resource_not_found", "That session is no longer active.", 404)

    record_admin_event(
        organization=organization,
        actor=actor,
        action="session.ended",
        target_type="Session",
        target_id=session_id,
        reason=reason,
    )
    return True


def end_all_sessions(*, actor: Actor, organization: Organization, reason: str) -> int:
    """End every session in the organization.

    The break-glass action: a shared credential, a suspected compromise, an
    officer who cannot say which device is theirs. Every account is denylisted
    and every GoTrue session deleted, so nothing survives on either side.

    The acting administrator is included. Exempting themselves would leave the
    one session an attacker in this seat is already using, which is the session
    the operation most needs to end.
    """
    require_recent_factor(actor)
    ensure_console_mutation_allowed(actor)
    reason = require_reason(reason)

    profiles = list(
        UserProfile.objects.select_related("user").filter(organization=organization, user__is_active=True)
    )
    identities = []
    try:
        for profile in profiles:
            identity = find_user_by_email(profile.user.email or profile.user.get_username())
            if identity and identity.id:
                identities.append(identity.id)
    except SupabaseAdminError:
        # Same reasoning as end_sessions: the denylist alone still ends every
        # session as far as Netra is concerned.
        identities = []

    with transaction.atomic():
        for profile in profiles:
            revoke_user_console_contexts(profile.user_id, "organization_sessions_revoked")
            revoke_sessions(
                user_id=profile.user_id,
                organization=organization,
                reason=reason,
                revoked_by_label=actor.user,
            )
        deleted = end_sessions_for(identities)
        record_admin_event(
            organization=organization,
            actor=actor,
            action="session.all_revoked",
            target_type="Organization",
            target_id=organization.slug,
            after={"accounts": len(profiles), "sessionsDeleted": deleted},
            reason=reason,
        )
    return len(profiles)


def change_role(
    *, actor: Actor, organization: Organization, user_id: int, role: str, reason: str
) -> UserProfile:
    require_recent_factor(actor)
    profile = resolve_target(actor, user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)

    role_ref, legacy_role = resolve_role_assignment(organization, role)
    ensure_role_within_ceiling(actor, role_ref, legacy_role)
    previous = profile.role_ref.name if profile.role_ref_id else profile.role
    next_role = role_ref.name if role_ref else legacy_role
    if profile.role_ref_id == (role_ref.id if role_ref else None) and profile.role == legacy_role:
        raise AdministrationProblem("no_change", "That account already holds this role.", 409)
    if organization.owner_id == profile.user_id and legacy_role != UserProfile.Role.ADMIN:
        raise AdministrationProblem(
            "owner_transfer_required",
            "Transfer organization ownership before changing this account's role.",
            409,
        )
    if profile.role == UserProfile.Role.ADMIN:
        ensure_administrator_remains(organization, losing_user_id=profile.user_id)

    with transaction.atomic():
        profile.role = legacy_role
        profile.role_ref = role_ref
        profile.save(update_fields=["role", "role_ref", "updated_at"])
        bump_permissions_version(organization)
        revoke_user_console_contexts(profile.user_id, "role_changed")
        record_admin_event(
            organization=organization,
            actor=actor,
            action="user.role_changed",
            target_type="User",
            target_id=profile.user.email or profile.user.get_username(),
            before={"role": previous},
            after={"role": next_role},
            reason=reason,
        )
    return profile


def account_payload(profile: UserProfile) -> dict[str, Any]:
    return {
        "id": profile.user_id,
        "email": profile.user.email or profile.user.get_username(),
        "name": profile.display_name,
        "roleSlug": profile.role_ref.slug if profile.role_ref_id else profile.role.strip().lower().replace(" ", "_"),
        "department": profile.department,
        "status": "active" if profile.user.is_active else "deactivated",
    }
