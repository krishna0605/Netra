"""Assemble the administration console's directory snapshot.

The console loads all nine of its screens from one state object, so this builds
one response rather than eight. That is a deliberate trade: the operator
experiences the console as a single thing, and splitting the read into eight
requests would give them eight loading states and eight ways to half-fail.

Two systems own the truth here and they are joined by email address. Django's
UserProfile is authoritative for *authorization* — role, organization,
department — because it is the only side Netra controls and the only side that
cannot be edited by the account holder. Supabase Auth is authoritative for
*identity* — whether an authenticator is enrolled, when the account last signed
in. Neither is complete alone.

Where Supabase cannot be reached the snapshot still returns, with the
identity-owned fields marked unknown rather than guessed. An administration
console that reports "no authenticator enrolled" because a network call failed
would be worse than one that admits it does not know.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model

from apps.forensics.models import (
    AccessLog,
    AdminAuditEvent,
    Permission,
    PermissionGrant,
    Role,
    RolePermission,
    CaseHistoryEvent,
    CustodyLedgerEvent,
    OperationalEvent,
    Organization,
    UserProfile,
)
from common.admin_audit import admin_event_dict
from common.audit import ROLE_PERMISSIONS
from common.permissions import effective_permissions
from common.capabilities import capability_registry
from common.supabase_admin import SupabaseAdminError, list_users
from common.supabase_sessions import list_sessions, session_payload


# The catalogue is server-owned so that a screen cannot drift from what the
# permission checker actually enforces. Keys are exactly ROLE_PERMISSIONS'
# vocabulary; a key added there without a description here fails a test.
PERMISSION_CATALOGUE: tuple[dict[str, str], ...] = (
    {
        "key": "view",
        "label": "View cases",
        "description": "Open cases and read analysis results.",
        "category": "Analysis",
        "risk": "standard",
    },
    {
        "key": "review",
        "label": "Review findings",
        "description": "Triage alerts and annotate detections.",
        "category": "Analysis",
        "risk": "standard",
    },
    {
        "key": "upload",
        "label": "Upload evidence",
        "description": "Add capture files and structured logs to a case.",
        "category": "Evidence",
        "risk": "standard",
    },
    {
        "key": "confirm",
        "label": "Confirm findings",
        "description": "Mark a detection as confirmed on the record.",
        "category": "Analysis",
        "risk": "elevated",
    },
    {
        "key": "report",
        "label": "Generate reports",
        "description": "Produce case reports for disclosure.",
        "category": "Reporting",
        "risk": "elevated",
    },
    {
        "key": "export",
        "label": "Export evidence",
        "description": "Download evidence and analysis outside Netra.",
        "category": "Reporting",
        "risk": "high",
    },
    {
        "key": "compliance",
        "label": "Compliance review",
        "description": "Read compliance checklists and the access log.",
        "category": "Reporting",
        "risk": "elevated",
    },
    {
        "key": "integrations",
        "label": "Manage integrations",
        "description": "Configure SIEM and webhook delivery.",
        "category": "Administration",
        "risk": "high",
    },
    {
        "key": "operations",
        "label": "Operate capture",
        "description": "Start, stop and schedule capture jobs.",
        "category": "Administration",
        "risk": "high",
    },
    {
        "key": "manage_users",
        "label": "Manage users",
        "description": "Create accounts, set roles and reset credentials.",
        "category": "Administration",
        "risk": "high",
    },
)

_ROLE_DESCRIPTIONS = {
    "Admin": "Full administration of the organization, its users and its integrations.",
    "Investigator": "Runs cases end to end, including reporting and export.",
    "Analyst": "Works inside assigned cases without export or reporting rights.",
    "Viewer": "Read-only access to assigned cases.",
    "LAN Operator": "Operates capture on the local network without user administration.",
}

# How much history one snapshot carries. The activity screen pages beyond this
# through its own endpoint once the volume justifies it; until then a bounded
# slice keeps the response predictable.
ACTIVITY_LIMIT = 200


def role_slug(role: str) -> str:
    return role.strip().lower().replace(" ", "_")


@dataclass(frozen=True)
class _Identity:
    """What Supabase Auth knows about an account, keyed by email."""

    supabase_id: str
    mfa_state: str
    last_sign_in_at: str
    invited_at: str
    email_confirmed_at: str


def _supabase_identities() -> tuple[dict[str, _Identity], bool]:
    """Return identities by email, and whether the lookup actually succeeded.

    The boolean matters. An empty mapping because Supabase is unconfigured and
    an empty mapping because the organization has no accounts are the same
    value and must not produce the same answer.
    """
    if not getattr(settings, "SUPABASE_URL", "") or not getattr(settings, "SUPABASE_SECRET_KEY", ""):
        return {}, False
    identities: dict[str, _Identity] = {}
    page: int | None = 1
    # Bounded so an unexpectedly large directory cannot turn one console load
    # into an unbounded fan-out against Supabase.
    for _ in range(settings.NETRA_AUTH_ADMIN_MAX_LIST_PAGES):
        if page is None:
            break
        try:
            rows, page = list_users(page=page)
        except SupabaseAdminError:
            return identities, False
        for row in rows:
            if row.email:
                identities[row.email] = _Identity(
                    supabase_id=row.id,
                    mfa_state=row.mfa_state,
                    last_sign_in_at=row.last_sign_in_at,
                    invited_at=row.invited_at,
                    email_confirmed_at=row.email_confirmed_at,
                )
    return identities, True


def _status(user, identity: _Identity | None) -> str:
    if not user.is_active:
        return "deactivated"
    if identity and not identity.email_confirmed_at and identity.invited_at:
        return "invited"
    if identity and not identity.last_sign_in_at:
        return "invited"
    return "active"


def _invitation_state(identity: _Identity | None) -> str:
    if identity is None:
        return "none"
    if identity.email_confirmed_at or identity.last_sign_in_at:
        return "accepted"
    if identity.invited_at:
        return "pending"
    return "none"


def _denied_counts(organization: Organization) -> dict[int, int]:
    from django.db.models import Count
    from django.utils import timezone
    from datetime import timedelta

    since = timezone.now() - timedelta(hours=24)
    rows = (
        AccessLog.objects.filter(organization=organization, result="denied", created_at__gte=since)
        .exclude(user_id=None)
        .values("user_id")
        .annotate(total=Count("id"))
    )
    return {row["user_id"]: row["total"] for row in rows}


def _last_activity(organization: Organization) -> dict[int, str]:
    from django.db.models import Max

    rows = (
        AccessLog.objects.filter(organization=organization)
        .exclude(user_id=None)
        .values("user_id")
        .annotate(latest=Max("created_at"))
    )
    return {row["user_id"]: row["latest"].isoformat() for row in rows if row["latest"]}


def resolve_owner_id(organization: Organization) -> int:
    """Who owns this organization.

    One function because two callers need the answer and they must not disagree
    — the organization screen naming one person while the users table flags a
    different one is the kind of contradiction nobody reports and everybody
    distrusts.

    The fallback covers organizations that predate the owner column: the
    earliest administrator, who is the closest thing the data remembers to an
    original owner.
    """
    if organization.owner_id:
        return organization.owner_id
    earliest = (
        UserProfile.objects.filter(organization=organization, role=UserProfile.Role.ADMIN)
        .order_by("created_at", "id")
        .first()
    )
    return earliest.user_id if earliest else 0


def _permission_rows(profile: UserProfile, grants: list) -> list[dict[str, Any]]:
    """Effective permissions, each saying where it came from.

    The source is what makes the screen useful. An administrator looking at an
    account needs to tell which permissions arrive with the role from which
    somebody decided by hand, because only the second kind carries a reason and
    an expiry.
    """
    overrides = {grant.permission_id: grant for grant in grants}
    rows = []
    for key in sorted(effective_permissions(profile)):
        grant = overrides.get(key)
        granted = grant is not None and grant.mode == PermissionGrant.Mode.GRANT
        rows.append(
            {
                "key": key,
                "source": "granted" if granted else "role",
                "expiresAt": grant.expires_at.isoformat() if granted and grant.expires_at else None,
                "reason": grant.reason if granted else "",
                "grantedBy": grant.granted_by_label if granted else "",
            }
        )
    # Revocations are absent from the effective set by definition. Hiding them
    # would leave an administrator wondering why somebody lacks what their role
    # says they should have.
    for key, grant in sorted(overrides.items()):
        if grant.mode == PermissionGrant.Mode.REVOKE:
            rows.append(
                {
                    "key": key,
                    "source": "revoked",
                    "expiresAt": grant.expires_at.isoformat() if grant.expires_at else None,
                    "reason": grant.reason,
                    "grantedBy": grant.granted_by_label,
                }
            )
    return rows


def user_rows(organization: Organization) -> tuple[list[dict[str, Any]], bool]:
    identities, identities_known = _supabase_identities()
    owner_id = resolve_owner_id(organization)
    grants_by_user: dict[int, list] = {}
    for grant in PermissionGrant.objects.filter(organization=organization):
        grants_by_user.setdefault(grant.user_id, []).append(grant)
    denied = _denied_counts(organization)
    last_activity = _last_activity(organization)
    profiles = (
        UserProfile.objects.select_related("user", "organization", "role_ref")
        .filter(organization=organization)
        .order_by("user__username")
    )
    rows: list[dict[str, Any]] = []
    for profile in profiles:
        user = profile.user
        email = (user.email or user.get_username() or "").strip().lower()
        identity = identities.get(email)
        permissions = _permission_rows(profile, grants_by_user.get(profile.user_id, []))
        rows.append(
            {
                "id": user.id,
                "email": email,
                "name": profile.display_name or user.get_username(),
                "roleSlug": role_slug(profile.role),
                "isOwner": owner_id == profile.user_id,
                "status": _status(user, identity),
                # Never guessed. When Supabase could not be consulted the
                # console shows "unknown" and the overview excludes the account
                # from its enrolment ratio rather than counting it as a gap.
                "mfa": identity.mfa_state if identity else ("unenrolled" if identities_known else "unknown"),
                "department": profile.department,
                "supabaseId": identity.supabase_id if identity else "",
                "joinedAt": profile.created_at.isoformat(),
                "lastSignInAt": (identity.last_sign_in_at or None) if identity else None,
                "lastActivityAt": last_activity.get(user.id),
                "invitationState": _invitation_state(identity),
                "deniedLast24h": denied.get(user.id, 0),
                "permissions": permissions,
                # Case membership is per-case authorization rather than
                # directory state; the console reads it from the case API.
                "caseMemberships": [],
            }
        )
    return rows, identities_known


def role_rows(organization: Organization) -> list[dict[str, Any]]:
    """Roles as the database holds them, including any the console created.

    isSystem now means something. The seeded roles cannot be edited and a clone
    of one can; before permissions were data every role lived in code, so the
    flag was always true and told nobody anything.
    """
    from django.db.models import Count

    counts = {
        row["role"]: row["total"]
        for row in UserProfile.objects.filter(organization=organization).values("role").annotate(total=Count("id"))
    }
    by_ref = {
        row["role_ref"]: row["total"]
        for row in UserProfile.objects.filter(organization=organization, role_ref__isnull=False)
        .values("role_ref")
        .annotate(total=Count("id"))
    }

    rows = []
    for role in Role.objects.filter(organization=organization).order_by("is_system", "name"):
        keys = sorted(RolePermission.objects.filter(role=role).values_list("permission_id", flat=True))
        rows.append(
            {
                "slug": role.slug,
                "name": role.name,
                "description": role.description,
                "isSystem": role.is_system,
                "permissions": keys,
                # Profiles carry both pointers through the transition, so a
                # member counts under either rather than vanishing from the
                # tally because one has not been backfilled.
                "memberCount": by_ref.get(role.id, 0) or counts.get(role.name, 0),
            }
        )
    return rows


def organization_row(organization: Organization) -> dict[str, Any]:
    owner_id = resolve_owner_id(organization)
    return {
        "id": str(organization.id),
        "name": organization.name,
        "slug": organization.slug,
        "ownerUserId": owner_id or 0,
        "maxQueuedAnalyses": organization.max_queued_analyses,
        "accessLogRetentionDays": settings.NETRA_ACCESS_LOG_RETENTION_DAYS,
        "mfaPolicy": settings.NETRA_MFA_POLICY,
        "createdAt": organization.created_at.isoformat(),
    }


def permission_catalogue_rows() -> list[dict[str, Any]]:
    """The catalogue from the database, falling back to the constant.

    The fallback covers a database migrated but not yet seeded. An empty
    catalogue would leave the console unable to offer any permission at all.
    """
    rows = [
        {
            "key": row.key,
            "label": row.label,
            "description": row.description,
            "category": row.category,
            "risk": row.risk_level,
        }
        for row in Permission.objects.all()
    ]
    return rows or [dict(entry) for entry in PERMISSION_CATALOGUE]


def capability_rows() -> list[dict[str, Any]]:
    return [
        {
            "key": definition.key,
            "state": definition.state,
            "reason": definition.reason,
            "requiresAal2": definition.requires_aal2,
            "durableConsumer": definition.durable_consumer,
        }
        for definition in capability_registry().values()
    ]


def _activity_from_access_logs(organization: Organization, limit: int) -> list[dict[str, Any]]:
    rows = (
        AccessLog.objects.filter(organization=organization)
        .select_related("user")
        .order_by("-created_at", "-id")[:limit]
    )
    return [
        {
            "id": f"access-{row.id}",
            "at": row.created_at.isoformat(),
            "actor": row.user_label,
            "actorEmail": (row.user.email if row.user else "") or "",
            "role": row.role,
            "action": row.action,
            "target": " ".join(part for part in (row.resource_type, row.resource_id) if part) or row.case_id or "",
            "result": row.result if row.result in {"allowed", "denied"} else "recorded",
            "source": "AccessLog",
            "chainIndex": None,
        }
        for row in rows
    ]


def _activity_from_operational_events(organization: Organization, limit: int) -> list[dict[str, Any]]:
    rows = OperationalEvent.objects.filter(organization=organization).order_by("-created_at", "-id")[:limit]
    return [
        {
            "id": f"ops-{row.id}",
            "at": row.created_at.isoformat(),
            "actor": str(row.payload_json.get("operator") or "System"),
            "actorEmail": "",
            "role": "",
            "action": row.event_type,
            "target": row.case_id or "",
            "result": "recorded",
            "source": "OperationalEvent",
            "chainIndex": None,
        }
        for row in rows
    ]


def _activity_from_case_history(organization: Organization, limit: int) -> list[dict[str, Any]]:
    rows = (
        CaseHistoryEvent.objects.filter(case__organization=organization)
        .select_related("case")
        .order_by("-created_at", "-id")[:limit]
    )
    return [
        {
            "id": f"history-{row.id}",
            "at": row.created_at.isoformat(),
            "actor": row.actor_name,
            "actorEmail": "",
            "role": "",
            "action": row.action,
            "target": row.case_id,
            "result": "recorded",
            "source": "CaseHistory",
            "chainIndex": None,
        }
        for row in rows
    ]


def _activity_from_custody(organization: Organization, limit: int) -> list[dict[str, Any]]:
    rows = (
        CustodyLedgerEvent.objects.filter(case__organization=organization)
        .select_related("case")
        .order_by("-created_at", "-chain_index")[:limit]
    )
    return [
        {
            "id": f"custody-{row.id}",
            "at": row.created_at.isoformat(),
            "actor": row.actor_label,
            "actorEmail": "",
            "role": row.actor_role,
            "action": row.action,
            "target": " ".join(part for part in (row.resource_type, row.resource_id) if part) or row.case_id,
            "result": "recorded",
            "source": "Custody",
            "chainIndex": row.chain_index,
        }
        for row in rows
    ]


def audit_rows(organization: Organization, limit: int = ACTIVITY_LIMIT) -> list[dict[str, Any]]:
    """The administrator chain, newest first.

    Ordered by chain_index rather than time. The index is the chain's own
    sequence and cannot be tampered with without breaking verification, while a
    timestamp sort would let a forged row present itself out of position.
    """
    rows = (
        AdminAuditEvent.objects.filter(organization=organization).order_by("-chain_index")[:limit]
    )
    return [admin_event_dict(row) for row in rows]


def _activity_from_admin_audit(organization: Organization, limit: int) -> list[dict[str, Any]]:
    rows = AdminAuditEvent.objects.filter(organization=organization).order_by("-chain_index")[:limit]
    return [
        {
            "id": f"admin-{row.id}",
            "at": row.recorded_at.isoformat(),
            "actor": row.actor_label,
            "actorEmail": row.actor_email,
            "role": row.actor_role,
            "action": row.action,
            "target": " ".join(part for part in (row.target_type, row.target_id) if part),
            "result": "recorded",
            "source": "AdminAudit",
            "chainIndex": row.chain_index,
        }
        for row in rows
    ]


def activity_rows(organization: Organization, limit: int = ACTIVITY_LIMIT) -> list[dict[str, Any]]:
    """Merge the four streams Django owns into one reverse-chronological list.

    Each stream is capped before the merge so that one noisy source cannot
    starve the others out of the window.
    """
    merged = [
        *_activity_from_access_logs(organization, limit),
        *_activity_from_admin_audit(organization, limit),
        *_activity_from_operational_events(organization, limit),
        *_activity_from_case_history(organization, limit),
        *_activity_from_custody(organization, limit),
    ]
    merged.sort(key=lambda row: row["at"], reverse=True)
    return merged[:limit]


def session_rows(organization: Organization, users: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    """Live sessions, joined back to the people they belong to.

    Read straight from GoTrue's own table rather than through the Auth Admin
    REST API, which has no endpoint for this. See common/supabase_sessions.py
    for why that is legitimate and where it stops.
    """
    by_supabase_id = {row["supabaseId"]: row for row in users if row.get("supabaseId")}
    sessions, status = list_sessions(list(by_supabase_id))
    rows = []
    for session in sessions:
        owner = by_supabase_id.get(session.supabase_user_id)
        if owner is None:
            # A session belonging to somebody outside this organization. Not an
            # error — one Supabase project can serve several — and not ours to
            # show.
            continue
        rows.append(
            session_payload(session, user_id=owner["id"], name=owner["name"], email=owner["email"])
        )
    return rows, status


def directory_snapshot(organization: Organization) -> dict[str, Any]:
    users, identities_known = user_rows(organization)
    sessions, sessions_status = session_rows(organization, users)
    return {
        "users": users,
        "sessions": sessions,
        "activity": activity_rows(organization),
        "audit": audit_rows(organization),
        "roles": role_rows(organization),
        "organization": organization_row(organization),
        "permissions": permission_catalogue_rows(),
        "capabilities": capability_rows(),
        "sources": {
            "identityProvider": "supabase" if identities_known else "unavailable",
            "sessions": sessions_status,
            "audit": "live",
        },
    }
