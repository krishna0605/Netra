"""Administering permissions, roles, the organization and its ownership.

Everything here shares one rule with the account operations: the change and the
audit entry are written in the same transaction, so a change without a record
cannot survive and a record of a change that did not happen cannot either.

The rule specific to this module is the ceiling. An administrator may confer
only what they themselves hold, checked live against the database at the moment
of the grant. Without it, any account with manage_users can grant itself every
permission in the system and the hierarchy is decoration.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.text import slugify

from apps.forensics.models import Organization, Permission, PermissionGrant, Role, RolePermission, UserProfile
from apps.forensics.services.administration import (
    AdministrationProblem,
    ensure_console_mutation_allowed,
    require_recent_factor,
)
from apps.forensics.services.admin_users import require_reason, resolve_target
from common.admin_audit import record_admin_event
from common.audit import Actor
from common.permissions import bump_permissions_version, ceiling_for, effective_permissions

MAX_ROLE_NAME = 80


def _permission(key: str) -> Permission:
    permission = Permission.objects.filter(pk=(key or "").strip()).first()
    if permission is None:
        raise AdministrationProblem("unknown_permission", "That permission does not exist.", 400)
    return permission


def _within_ceiling_or_refuse(actor: Actor, keys: set[str]) -> None:
    """Refuse rather than narrow.

    Silently storing the subset an administrator is allowed to confer would
    report success for a grant that was partly ignored, and they would find out
    when the officer could not do the thing they were told they could.
    """
    beyond = set(keys) - ceiling_for(actor)
    if beyond:
        raise AdministrationProblem(
            "beyond_your_permissions",
            f"You cannot grant what you do not hold: {', '.join(sorted(beyond))}.",
            403,
        )


def grant_permission(
    *,
    actor: Actor,
    organization: Organization,
    user_id: int,
    key: str,
    reason: str,
    expires_at: datetime | None = None,
    mode: str = PermissionGrant.Mode.GRANT,
) -> UserProfile:
    require_recent_factor(actor)
    profile = resolve_target(actor, user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)
    permission = _permission(key)

    if mode not in {PermissionGrant.Mode.GRANT, PermissionGrant.Mode.REVOKE}:
        raise AdministrationProblem("invalid_mode", "A grant is either a grant or a revocation.", 400)

    # Only granting is ceilinged. Taking a permission away is always allowed:
    # an administrator who cannot export should still be able to stop someone
    # else exporting, and requiring the permission in order to remove it would
    # make the safest action the hardest one.
    if mode == PermissionGrant.Mode.GRANT:
        _within_ceiling_or_refuse(actor, {permission.pk})

    if expires_at is not None and expires_at <= timezone.now():
        raise AdministrationProblem("invalid_expiry", "An expiry must be in the future.", 400)

    with transaction.atomic():
        before = sorted(effective_permissions(profile))
        PermissionGrant.objects.update_or_create(
            user_id=profile.user_id,
            permission=permission,
            defaults={
                "organization": organization,
                "mode": mode,
                "reason": reason,
                "expires_at": expires_at,
                "granted_by_id": actor.django_user_id,
                "granted_by_label": actor.user,
            },
        )
        bump_permissions_version(organization)
        profile.refresh_from_db()
        record_admin_event(
            organization=organization,
            actor=actor,
            action="permission.granted" if mode == PermissionGrant.Mode.GRANT else "permission.revoked",
            target_type="User",
            target_id=profile.user.email or profile.user.get_username(),
            before={"permissions": before},
            after={
                "permissions": sorted(effective_permissions(profile)),
                "expiresAt": expires_at.isoformat() if expires_at else None,
            },
            reason=reason,
        )
    return profile


def remove_grant(*, actor: Actor, organization: Organization, user_id: int, key: str, reason: str) -> UserProfile:
    """Drop an override so the role decides again."""
    require_recent_factor(actor)
    profile = resolve_target(actor, user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)
    permission = _permission(key)

    with transaction.atomic():
        before = sorted(effective_permissions(profile))
        deleted, _ = PermissionGrant.objects.filter(user_id=profile.user_id, permission=permission).delete()
        if not deleted:
            raise AdministrationProblem("grant_not_found", "That account has no such override.", 404)
        bump_permissions_version(organization)
        profile.refresh_from_db()
        record_admin_event(
            organization=organization,
            actor=actor,
            action="permission.override_removed",
            target_type="User",
            target_id=profile.user.email or profile.user.get_username(),
            before={"permissions": before},
            after={"permissions": sorted(effective_permissions(profile))},
            reason=reason,
        )
    return profile


def create_role(
    *, actor: Actor, organization: Organization, name: str, description: str, base_slug: str, reason: str
) -> Role:
    """Clone an existing role rather than start from nothing.

    A role built from an empty set is one somebody has to remember to finish,
    and a half-finished role looks identical to a deliberate one.
    """
    require_recent_factor(actor)
    ensure_console_mutation_allowed(actor)
    reason = require_reason(reason)

    name = (name or "").strip()
    if not 2 <= len(name) <= MAX_ROLE_NAME:
        raise AdministrationProblem("invalid_role_name", "A role name between 2 and 80 characters is required.", 400)

    slug = slugify(name).replace("-", "_")[:64]
    if not slug:
        raise AdministrationProblem("invalid_role_name", "That role name has no usable slug.", 400)

    base = Role.objects.filter(organization=organization, slug=(base_slug or "").strip()).first()
    if base is None:
        raise AdministrationProblem("unknown_base_role", "Choose an existing role to copy.", 400)

    inherited = set(RolePermission.objects.filter(role=base).values_list("permission_id", flat=True))
    _within_ceiling_or_refuse(actor, inherited)

    with transaction.atomic():
        try:
            role = Role.objects.create(
                organization=organization,
                slug=slug,
                name=name,
                description=(description or "").strip(),
                is_system=False,
            )
        except IntegrityError as problem:
            raise AdministrationProblem("role_exists", "A role with that name already exists.", 409) from problem

        RolePermission.objects.bulk_create([RolePermission(role=role, permission_id=key) for key in inherited])
        bump_permissions_version(organization)
        record_admin_event(
            organization=organization,
            actor=actor,
            action="role.created",
            target_type="Role",
            target_id=slug,
            after={"copiedFrom": base.slug, "permissions": sorted(inherited)},
            reason=reason,
        )
    return role


def set_role_permission(
    *, actor: Actor, organization: Organization, slug: str, key: str, held: bool, reason: str
) -> Role:
    require_recent_factor(actor)
    ensure_console_mutation_allowed(actor)
    reason = require_reason(reason)

    role = Role.objects.filter(organization=organization, slug=(slug or "").strip()).first()
    if role is None:
        raise AdministrationProblem("resource_not_found", "The requested resource was not found.", 404)
    if role.is_system:
        # An organization that could strip manage_users from the only role
        # holding it would lock itself out with no way back in.
        raise AdministrationProblem(
            "system_role_locked",
            "Standard roles cannot be edited. Copy this role and change the copy.",
            409,
        )

    permission = _permission(key)
    if held:
        _within_ceiling_or_refuse(actor, {permission.pk})

    with transaction.atomic():
        before = sorted(RolePermission.objects.filter(role=role).values_list("permission_id", flat=True))
        if held:
            RolePermission.objects.get_or_create(role=role, permission=permission)
        else:
            RolePermission.objects.filter(role=role, permission=permission).delete()
        bump_permissions_version(organization)
        record_admin_event(
            organization=organization,
            actor=actor,
            action="role.permission_changed",
            target_type="Role",
            target_id=role.slug,
            before={"permissions": before},
            after={"permissions": sorted(RolePermission.objects.filter(role=role).values_list("permission_id", flat=True))},
            reason=reason,
        )
    return role


def update_organization(*, actor: Actor, organization: Organization, changes: dict[str, Any], reason: str) -> Organization:
    require_recent_factor(actor)
    ensure_console_mutation_allowed(actor)
    reason = require_reason(reason)

    applied: dict[str, Any] = {}
    before: dict[str, Any] = {}

    if "name" in changes:
        name = str(changes["name"] or "").strip()
        if not 2 <= len(name) <= 120:
            raise AdministrationProblem("invalid_name", "An organization name between 2 and 120 characters is required.", 400)
        before["name"] = organization.name
        applied["name"] = name

    if "maxQueuedAnalyses" in changes:
        try:
            queued = int(changes["maxQueuedAnalyses"])
        except (TypeError, ValueError) as problem:
            raise AdministrationProblem("invalid_queue_limit", "The queue limit must be a whole number.", 400) from problem
        if not 1 <= queued <= 100:
            raise AdministrationProblem("invalid_queue_limit", "The queue limit must be between 1 and 100.", 400)
        before["maxQueuedAnalyses"] = organization.max_queued_analyses
        applied["maxQueuedAnalyses"] = queued

    if not applied:
        raise AdministrationProblem("no_change", "Nothing was changed.", 400)

    with transaction.atomic():
        if "name" in applied:
            organization.name = applied["name"]
        if "maxQueuedAnalyses" in applied:
            organization.max_queued_analyses = applied["maxQueuedAnalyses"]
        organization.save(update_fields=["name", "max_queued_analyses", "updated_at"])
        record_admin_event(
            organization=organization,
            actor=actor,
            action="organization.updated",
            target_type="Organization",
            target_id=organization.slug,
            before=before,
            after=applied,
            reason=reason,
        )
    return organization


def transfer_ownership(*, actor: Actor, organization: Organization, target_user_id: int, reason: str) -> Organization:
    """Hand the organization to someone else.

    Only the owner may do this. Several people can administer an organization,
    but ownership moves by a deliberate act of the person who holds it — that
    separation is what stops an administrator quietly promoting themselves past
    everyone else.
    """
    require_recent_factor(actor)
    profile = resolve_target(actor, target_user_id)
    ensure_console_mutation_allowed(actor, profile)
    reason = require_reason(reason)

    if organization.owner_id and organization.owner_id != actor.django_user_id:
        raise AdministrationProblem("owner_only", "Only the current owner can transfer ownership.", 403)
    if organization.owner_id == profile.user_id:
        raise AdministrationProblem("already_owner", "That account already owns this organization.", 409)
    if not profile.user.is_active:
        raise AdministrationProblem("inactive_target", "Choose an active account.", 409)
    if profile.role != UserProfile.Role.ADMIN:
        # Handing the organization to somebody who cannot administer it leaves
        # nobody able to undo the mistake.
        raise AdministrationProblem("target_not_administrator", "Make them an administrator first.", 409)

    previous = organization.owner_id
    with transaction.atomic():
        organization.owner_id = profile.user_id
        organization.save(update_fields=["owner", "updated_at"])
        record_admin_event(
            organization=organization,
            actor=actor,
            action="organization.ownership_transferred",
            target_type="Organization",
            target_id=organization.slug,
            before={"ownerUserId": previous},
            after={"ownerUserId": profile.user_id},
            reason=reason,
        )
    return organization
