from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from apps.forensics.models import AccessLog, OperationalEvent, Organization, UserProfile
from common.audit import Actor
from common.step_up import is_fresh


@dataclass(frozen=True)
class AdministrationProblem(Exception):
    code: str
    message: str
    status: int = 403


def require_privileged_admin(actor: Actor, organization_id=None) -> None:
    if not actor.authenticated or actor.role != UserProfile.Role.ADMIN:
        raise AdministrationProblem("permission_denied", "Administrator permission is required.")
    if not actor.organization_id or (organization_id and str(actor.organization_id) != str(organization_id)):
        raise AdministrationProblem("resource_not_found", "The requested resource was not found.", 404)
    if actor.aal != "aal2":
        raise AdministrationProblem("aal2_required", "Multi-factor authentication is required for this operation.")
    profile = UserProfile.objects.select_related("user").filter(
        user_id=actor.django_user_id,
        organization_id=actor.organization_id,
        role=UserProfile.Role.ADMIN,
        user__is_active=True,
    ).first()
    if profile is None:
        raise AdministrationProblem("permission_denied", "Administrator permission is required.")


@transaction.atomic
def transfer_administrator(*, actor: Actor, organization_id, target_user_id: int, reason: str) -> dict:
    require_privileged_admin(actor, organization_id)
    reason = (reason or "").strip()
    if not 10 <= len(reason) <= 1000:
        raise AdministrationProblem("invalid_transfer_reason", "A transfer reason between 10 and 1000 characters is required.", 400)
    organization = Organization.objects.select_for_update().filter(pk=organization_id).first()
    if organization is None:
        raise AdministrationProblem("resource_not_found", "The requested resource was not found.", 404)
    profiles = UserProfile.objects.select_for_update().select_related("user").filter(organization=organization)
    # Transfer hands over the acting administrator's own role, so it is their
    # profile that must be read — not "the" administrator. With several
    # administrators permitted, "the first Admin row" is an arbitrary person who
    # may not be the caller at all.
    current = profiles.filter(user_id=actor.django_user_id, role=UserProfile.Role.ADMIN).first()
    target = profiles.filter(user_id=target_user_id).first()
    if current is None:
        raise AdministrationProblem("admin_transfer_conflict", "The current administrator state has changed.", 409)
    if target is None:
        raise AdministrationProblem("resource_not_found", "The requested resource was not found.", 404)
    if target.user_id == current.user_id or not target.user.is_active:
        raise AdministrationProblem("admin_transfer_conflict", "Select a different active user in this organization.", 409)

    previous_admin_id = current.user_id
    current.role = UserProfile.Role.INVESTIGATOR
    current.save(update_fields=["role", "updated_at"])
    target.role = UserProfile.Role.ADMIN
    target.save(update_fields=["role", "updated_at"])
    occurred_at = timezone.now()
    details = {
        "reason": reason,
        "previousAdminId": previous_admin_id,
        "newAdminId": target.user_id,
    }
    AccessLog.objects.create(
        organization=organization,
        user_id=actor.django_user_id,
        user_label=actor.user,
        role=UserProfile.Role.ADMIN,
        action="organization.admin_transfer",
        resource_type="Organization",
        resource_id=str(organization.id),
        result="allowed",
    )
    OperationalEvent.objects.create(
        organization=organization,
        event_type="organization.admin_transferred",
        payload_json={**details, "operator": actor.user},
    )
    return {
        "organizationId": str(organization.id),
        "previousAdminId": previous_admin_id,
        "newAdminId": target.user_id,
        "transferredAt": occurred_at.isoformat(),
    }


def require_recent_factor(actor: Actor) -> None:
    """Refuse unless the authenticator was used in the last few minutes.

    require_privileged_admin already establishes that a second factor exists
    and was used at some point in this session. That is not the same claim. An
    administrator who verified at nine in the morning still satisfies it at
    five in the afternoon, on the same session, at an unattended desk.

    Destructive operations ask again, and this is what makes the asking mean
    something. It is separate from require_privileged_admin rather than folded
    into it because read endpoints correctly need the weaker check — prompting
    for a code to look at a list would train operators to keep their
    authenticator permanently open, which would defeat both.
    """
    if not is_fresh(actor.factor_verified_at):
        raise AdministrationProblem(
            "step_up_required",
            "Confirm this action with your authenticator.",
            401,
        )


def ensure_admin_mutation_allowed(actor: Actor, target: UserProfile | None = None) -> None:
    """Gate every administrative change to another account.

    This used to refuse any operation targeting an administrator. Combined with
    the one-administrator-per-organization rule that has now gone, it meant
    nobody could act on the only person who could act — a station head who lost
    their authenticator could not be restored by the console built to restore
    people, only by editing the database directly.

    Two narrower rules replace it, and they are the ones that were actually
    worth having.
    """
    require_privileged_admin(actor, actor.organization_id)
    if target is None:
        return

    # An administrator acting on their own account is how a mistake becomes
    # unrecoverable: reset your own authenticator and you are locked out of the
    # console that would have fixed it. Someone else does it, and the audit
    # trail names two people rather than one.
    if actor.django_user_id and target.user_id == actor.django_user_id:
        raise AdministrationProblem(
            "self_mutation_forbidden",
            "Ask another administrator to perform this on your account.",
            409,
        )

    # This guards the generic /api/users route, which predates the audit chain
    # and writes nothing to it. Administrator accounts are still changed only
    # through the administration console, where every change is sealed — so a
    # deputy restoring a station head goes through a recorded path rather than
    # this one. The administration namespace uses its own guard and permits it.
    if target.role == UserProfile.Role.ADMIN:
        raise AdministrationProblem(
            "administrator_change_forbidden",
            "Administrator accounts are managed through the administration console.",
            409,
        )


def ensure_console_mutation_allowed(actor: Actor, target: UserProfile | None = None) -> None:
    """Gate for the administration console namespace.

    Differs from ensure_admin_mutation_allowed in exactly one way, and it is the
    whole point of the change: a deputy may act on the station head. That is the
    recovery case — a head who loses their authenticator is restored by a
    colleague rather than by someone editing the database.

    Every operation reached through this guard is sealed into the audit chain,
    which is why it can afford to permit what the older, unrecorded route
    refuses.
    """
    require_privileged_admin(actor, actor.organization_id)
    if target is None:
        return
    if actor.django_user_id and target.user_id == actor.django_user_id:
        raise AdministrationProblem(
            "self_mutation_forbidden",
            "Ask another administrator to perform this on your account.",
            409,
        )


def ensure_administrator_remains(organization, *, losing_user_id: int) -> None:
    """Refuse a change that would leave an organization with no administrator.

    The database cannot express this — a constraint can forbid a second row,
    not require a first — so it lives here and every path that demotes or
    deactivates an administrator must call it. An organization without one
    cannot add users, reset credentials or recover anyone, and nothing inside
    the application can undo it.
    """
    remaining = (
        UserProfile.objects.filter(
            organization=organization,
            role=UserProfile.Role.ADMIN,
            user__is_active=True,
        )
        .exclude(user_id=losing_user_id)
        .exists()
    )
    if not remaining:
        raise AdministrationProblem(
            "last_administrator",
            "Appoint another administrator before removing this one.",
            409,
        )
