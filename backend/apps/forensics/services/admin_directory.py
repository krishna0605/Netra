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
    CaseHistoryEvent,
    CustodyLedgerEvent,
    OperationalEvent,
    Organization,
    UserProfile,
)
from common.audit import ROLE_PERMISSIONS
from common.capabilities import capability_registry
from common.supabase_admin import SupabaseAdminError, list_users


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


def user_rows(organization: Organization) -> tuple[list[dict[str, Any]], bool]:
    identities, identities_known = _supabase_identities()
    denied = _denied_counts(organization)
    last_activity = _last_activity(organization)
    profiles = (
        UserProfile.objects.select_related("user", "organization")
        .filter(organization=organization)
        .order_by("user__username")
    )
    rows: list[dict[str, Any]] = []
    for profile in profiles:
        user = profile.user
        email = (user.email or user.get_username() or "").strip().lower()
        identity = identities.get(email)
        permissions = sorted(ROLE_PERMISSIONS.get(profile.role, set()))
        rows.append(
            {
                "id": user.id,
                "email": email,
                "name": profile.display_name or user.get_username(),
                "roleSlug": role_slug(profile.role),
                "isOwner": profile.role == UserProfile.Role.ADMIN,
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
                "permissions": [
                    {"key": key, "source": "role", "expiresAt": None, "reason": "", "grantedBy": ""}
                    for key in permissions
                ],
                # Case membership is per-case authorization rather than
                # directory state; the console reads it from the case API.
                "caseMemberships": [],
            }
        )
    return rows, identities_known


def role_rows(organization: Organization) -> list[dict[str, Any]]:
    from django.db.models import Count

    counts = {
        row["role"]: row["total"]
        for row in UserProfile.objects.filter(organization=organization).values("role").annotate(total=Count("id"))
    }
    return [
        {
            "slug": role_slug(role),
            "name": role,
            "description": _ROLE_DESCRIPTIONS.get(role, ""),
            # Every role is currently defined in code, so none may be edited
            # from the console. Phase 4 moves them into the database and this
            # flag starts telling the two apart.
            "isSystem": True,
            "permissions": sorted(permissions),
            "memberCount": counts.get(role, 0),
        }
        for role, permissions in ROLE_PERMISSIONS.items()
    ]


def organization_row(organization: Organization) -> dict[str, Any]:
    owner = (
        UserProfile.objects.filter(organization=organization, role=UserProfile.Role.ADMIN)
        .select_related("user")
        .first()
    )
    return {
        "id": str(organization.id),
        "name": organization.name,
        "slug": organization.slug,
        # Ownership is currently inferred from the sole-Admin constraint. Phase
        # 4 gives Organization its own owner column and this stops being a
        # derived value.
        "ownerUserId": owner.user_id if owner else 0,
        "maxQueuedAnalyses": organization.max_queued_analyses,
        "accessLogRetentionDays": settings.NETRA_ACCESS_LOG_RETENTION_DAYS,
        "mfaPolicy": settings.NETRA_MFA_POLICY,
        "createdAt": organization.created_at.isoformat(),
    }


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


def activity_rows(organization: Organization, limit: int = ACTIVITY_LIMIT) -> list[dict[str, Any]]:
    """Merge the four streams Django owns into one reverse-chronological list.

    Each stream is capped before the merge so that one noisy source cannot
    starve the others out of the window.
    """
    merged = [
        *_activity_from_access_logs(organization, limit),
        *_activity_from_operational_events(organization, limit),
        *_activity_from_case_history(organization, limit),
        *_activity_from_custody(organization, limit),
    ]
    merged.sort(key=lambda row: row["at"], reverse=True)
    return merged[:limit]


def directory_snapshot(organization: Organization) -> dict[str, Any]:
    users, identities_known = user_rows(organization)
    return {
        "users": users,
        # Supabase does not expose a session list through the client SDK, and
        # the Auth Admin call that does arrives with the write path. Returning
        # an empty list makes the console show its empty state, which is true;
        # inventing plausible rows here would put fiction in front of an
        # administrator deciding whether to revoke someone's access.
        "sessions": [],
        "activity": activity_rows(organization),
        # The hash-chained administrator audit table lands in the next phase.
        # Until it exists there is nothing truthful to return.
        "audit": [],
        "roles": role_rows(organization),
        "organization": organization_row(organization),
        "permissions": [dict(entry) for entry in PERMISSION_CATALOGUE],
        "capabilities": capability_rows(),
        "sources": {
            "identityProvider": "supabase" if identities_known else "unavailable",
            "sessions": "pending",
            "audit": "pending",
        },
    }
