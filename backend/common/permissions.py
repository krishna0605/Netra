"""What someone can actually do.

    effective = (role ∪ grants) − revocations

and then, when one person is deciding what another may hold:

    stored = effective ∩ the acting administrator's own set

That second line is the one that matters. Without it, anyone holding
manage_users can grant themselves every permission in the system, and the
hierarchy is decoration — a lock whose key is kept in the lock.

Performance is not a side concern here. can() sits on the hot path of every one
of the platform's routes and used to be a dict lookup, so this resolves once
per request — in actor_from_request, where the profile is already loaded — and
can() goes back to a set membership test.

There is deliberately no cross-request cache. One was written first, keyed on
(organization, user, permissions_version), and it was wrong in a way worth
recording: that triple does not identify a database state. Two different people
can be user 42 in the same organization at version 1, and the cache cannot tell
them apart. It surfaced as tests passing alone and failing together, which is
the same shape as a stale answer being served to the wrong person in production.

Resolving per request costs a few queries and removes the entire class of
problem, including the one that matters most — an administrator demoted a
moment ago is refused on their next request rather than when a cache expires.
"""

from __future__ import annotations

from django.db.models import F, Q
from django.utils import timezone

from apps.forensics.models import Organization, PermissionGrant, Role, RolePermission, UserProfile


def role_permission_keys(role: Role) -> set[str]:
    return set(
        RolePermission.objects.filter(role=role).values_list("permission_id", flat=True)
    )


def _from_role(profile: UserProfile) -> set[str]:
    """The role's permissions, preferring the database and falling back to code.

    The fallback exists because role_ref is nullable during the transition. A
    profile that has not been backfilled must not silently lose everything it
    could do, which is what returning an empty set would mean.
    """
    if profile.role_ref_id:
        return role_permission_keys(profile.role_ref)

    role = Role.objects.filter(organization_id=profile.organization_id, slug=profile.role.strip().lower().replace(" ", "_")).first()
    if role:
        return role_permission_keys(role)

    from common.audit import ROLE_PERMISSIONS

    return set(ROLE_PERMISSIONS.get(profile.role, set()))


def _overrides(profile: UserProfile) -> tuple[set[str], set[str]]:
    """Explicit grants and revocations, with expired grants already dropped."""
    now = timezone.now()
    rows = PermissionGrant.objects.filter(
        user_id=profile.user_id, organization_id=profile.organization_id
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))

    granted, revoked = set(), set()
    for row in rows:
        (granted if row.mode == PermissionGrant.Mode.GRANT else revoked).add(row.permission_id)
    return granted, revoked


def effective_permissions(profile: UserProfile) -> set[str]:
    """Everything this person holds right now."""
    granted, revoked = _overrides(profile)
    return (_from_role(profile) | granted) - revoked


def bump_permissions_version(organization: Organization) -> None:
    """Invalidate every cached answer for an organization.

    An increment rather than a cache purge: the old entries become unreachable
    instead of needing to be found and deleted, so this is correct across
    processes and across cache backends that cannot enumerate keys.
    """
    Organization.objects.filter(pk=organization.pk).update(permissions_version=F("permissions_version") + 1)


def permissions_for(user_id: int, organization_id) -> set[str]:
    """Resolve from the database. One call per request, from actor_from_request."""
    profile = (
        UserProfile.objects.select_related("role_ref")
        .filter(user_id=user_id, organization_id=organization_id)
        .first()
    )
    return effective_permissions(profile) if profile else set()


def ceiling_for(actor) -> set[str]:
    """What the acting administrator may confer: exactly what they hold.

    Read live rather than taken from the actor, because "may this person grant
    that" has to be answered against the database at the moment of the grant,
    not against what was true when the request began.
    """
    if not actor.django_user_id or not actor.organization_id:
        return set()
    return permissions_for(actor.django_user_id, actor.organization_id)


def within_ceiling(actor, requested: set[str]) -> set[str]:
    """Intersect a requested set with the actor's own.

    Returns what may be stored. The caller decides whether a request that loses
    keys is refused outright or applied narrowed — the console refuses, so an
    administrator is never told a grant succeeded when part of it did not.
    """
    return set(requested) & ceiling_for(actor)
