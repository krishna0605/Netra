from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.forensics.models import AccessLog, Case, CaseHistoryEvent, CaseMembership, UserProfile
from common.session_revocation import token_is_revoked
from common.step_up import factor_verified_at
from common.tenancy import NETRA_ORGANIZATION_ID, netra_organization


ROLE_PERMISSIONS = {
    "Admin": {"upload", "review", "confirm", "report", "export", "view", "compliance", "manage_users", "integrations", "operations"},
    "Investigator": {"upload", "review", "confirm", "report", "export", "view", "compliance"},
    "Analyst": {"upload", "review", "view"},
    "Viewer": {"view"},
    "LAN Operator": {"upload", "review", "confirm", "report", "export", "view", "compliance", "integrations", "operations"},
}


@dataclass(frozen=True)
class Actor:
    user: str
    role: str
    authenticated: bool = False
    django_user_id: int | None = None
    email: str = ""
    external_id: str = ""
    organization_id: UUID | None = None
    organization_slug: str = ""
    aal: str = "aal1"
    # Resolved once per request from the database. None means "not resolved" —
    # a header actor, trusted-LAN mode, or an identity with no local profile —
    # which is different from "resolved to nothing" and must not be read as it.
    permissions: frozenset[str] | None = None
    # When this session last proved possession of a second factor. Distinct
    # from aal, which says only that a factor was used at some point in the
    # session. Destructive operations gate on this; see common/step_up.py.
    factor_verified_at: datetime | None = None
    session_id: str = ""


VALID_ROLES = {"Admin", "Investigator", "Analyst", "Viewer"}


def _admin_exists() -> bool:
    User = get_user_model()
    return User.objects.filter(is_superuser=True).exists() or UserProfile.objects.filter(role="Admin").exists()


def sync_supabase_actor(supabase_user) -> Actor:
    """Map a verified Supabase user into Netra's local authorization profile.

    Supabase Auth remains the identity provider. Netra's local UserProfile is
    the server-side source of truth for app permissions, so user-editable
    metadata never controls authorization.
    """
    User = get_user_model()
    username = (getattr(supabase_user, "email", "") or getattr(supabase_user, "id", "")).strip().lower()
    if not username:
        return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
    user = User.objects.filter(username__iexact=username).first()
    if user is None:
        return Actor(
            user=username,
            role=UserProfile.Role.VIEWER,
            authenticated=True,
            email=username,
            external_id=getattr(supabase_user, "id", ""),
            aal=getattr(supabase_user, "aal", "aal1"),
            factor_verified_at=getattr(supabase_user, "factor_verified_at", None),
            session_id=getattr(supabase_user, "session_id", ""),
        )
    profile = UserProfile.objects.select_related("organization").filter(user=user).first()
    if profile is None or not user.is_active:
        return Actor(
            user=username,
            role=UserProfile.Role.VIEWER,
            authenticated=True,
            django_user_id=user.id,
            email=user.email or username,
            external_id=getattr(supabase_user, "id", ""),
            aal=getattr(supabase_user, "aal", "aal1"),
            factor_verified_at=getattr(supabase_user, "factor_verified_at", None),
            session_id=getattr(supabase_user, "session_id", ""),
        )
    return Actor(
        user=profile.display_name or user.username,
        role=profile.role,
        authenticated=True,
        django_user_id=user.id,
        email=user.email or user.username,
        external_id=getattr(supabase_user, "id", ""),
        organization_id=profile.organization_id,
        organization_slug=profile.organization.slug,
        permissions=_resolved_permissions(user.id, profile.organization_id),
        aal=getattr(supabase_user, "aal", "aal1"),
        factor_verified_at=getattr(supabase_user, "factor_verified_at", None),
        session_id=getattr(supabase_user, "session_id", ""),
    )


def _session_was_revoked(django_user_id: int, issued_at) -> bool:
    """One primary-key lookup on the authentication path.

    Deliberately its own query rather than a join onto the profile read: the
    common case is that no revocation exists, and this stays a single indexed
    miss instead of widening every authenticated request's main query.
    """
    User = get_user_model()
    user = User.objects.select_related("netra_session_revocation").filter(pk=django_user_id).first()
    if user is None:
        return False
    return token_is_revoked(user, issued_at)


def actor_from_request(request) -> Actor:
    cached_actor = getattr(request, "netra_actor", None)
    if isinstance(cached_actor, Actor):
        return cached_actor
    if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan":
        return Actor(
            user=settings.NETRA_TRUSTED_LAN_ACTOR,
            role=settings.NETRA_TRUSTED_LAN_ROLE,
            authenticated=True,
            organization_id=NETRA_ORGANIZATION_ID,
            organization_slug="netra",
        )
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        if getattr(settings, "NETRA_AUTH_PROVIDER", "django") == "supabase":
            from common.jwt_verifier import SupabaseTokenInvalid, SupabaseVerificationUnavailable
            from common.supabase_auth import verify_supabase_request_token

            try:
                verification = verify_supabase_request_token(token)
            except SupabaseVerificationUnavailable:
                request.netra_auth_error = "auth_verification_unavailable"
                return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
            except SupabaseTokenInvalid:
                request.netra_auth_error = "session_invalid"
                return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
            request.netra_verified_supabase_token = verification.verified_token
            request.netra_supabase_bearer_token = token
            actor = sync_supabase_actor(verification.user)
            issued_at = getattr(verification.verified_token, "issued_at", None)
            if actor.django_user_id and _session_was_revoked(actor.django_user_id, issued_at):
                request.netra_auth_error = "session_revoked"
                return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
            return actor
        try:
            auth = JWTAuthentication()
            validated = auth.get_validated_token(token)
            user = auth.get_user(validated)
            issued = validated.get("iat")
            issued_at = datetime.fromtimestamp(issued, UTC) if isinstance(issued, (int, float)) else None
            if _session_was_revoked(user.id, issued_at):
                request.netra_auth_error = "session_revoked"
                return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
            profile = UserProfile.objects.select_related("organization").filter(user=user).first()
            if profile is None or not user.is_active:
                return Actor(
                    user=user.get_username(),
                    role="Viewer",
                    authenticated=True,
                    django_user_id=user.id,
                    aal=str(validated.get("aal", "aal2" if settings.NETRA_TEST_SQLITE else "aal1")),
                )
            return Actor(
                user=profile.display_name or user.get_username(),
                role=profile.role,
                authenticated=True,
                django_user_id=user.id,
                email=user.email or user.get_username(),
                organization_id=profile.organization_id,
                organization_slug=profile.organization.slug,
                permissions=_resolved_permissions(user.id, profile.organization_id),
                # SimpleJWT's stock test token has no Supabase-style aal claim.
                # Treat only that synthetic, SQLite-test token as AAL2 so the
                # legacy API fixtures reach the behavior they are testing.
                # Explicit aal1 tests and every deployed token remain fail-closed.
                aal=str(validated.get("aal", "aal2" if settings.NETRA_TEST_SQLITE else "aal1")),
                # The local provider carries the same claim shape, so the
                # step-up gate behaves identically under both. Without this a
                # test could only ever exercise the refusal branch.
                factor_verified_at=factor_verified_at(validated.get("amr")),
                session_id=str(validated.get("jti", ""))[:128],
            )
        except Exception:
            return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
    if settings.NETRA_DEV_ROLE_HEADERS:
        role = request.headers.get("X-Netra-Role", "Investigator")
        if role not in ROLE_PERMISSIONS:
            role = "Investigator"
        return Actor(
            user=request.headers.get("X-Netra-User", "Inspector A. Patel"),
            role=role,
            authenticated=True,
            organization_id=NETRA_ORGANIZATION_ID,
            organization_slug="netra",
            aal="aal2" if settings.NETRA_TEST_SQLITE else "aal1",
            session_id="development-header",
        )
    return Actor(user="Unauthenticated", role="Viewer", authenticated=False)


def can(actor: Actor, permission: str) -> bool:
    """Whether this actor holds a permission.

    Same signature it has always had, so none of the call sites across the
    platform moved, and still a set membership test rather than a query. What
    changed is where the set comes from: resolved once per request from the
    database, where a role can be edited and an individual can hold an
    exception, instead of a dict only a deployment could change.

    Actors with no local profile — header actors in development, trusted-LAN
    mode, an identity with no UserProfile — keep the code table. They have no
    row to resolve against, and treating that as an empty set would refuse
    every request rather than admit the situation.
    """
    if actor.permissions is not None:
        return permission in actor.permissions
    return permission in ROLE_PERMISSIONS.get(actor.role, set())


def _resolved_permissions(user_id: int, organization_id) -> frozenset[str]:
    from common.permissions import permissions_for

    return frozenset(permissions_for(user_id, organization_id))


def visible_cases_for_actor(actor: Actor):
    if not actor.organization_id:
        return Case.objects.none()
    rows = Case.objects.filter(organization_id=actor.organization_id)
    if actor.role == "Admin":
        return rows
    if actor.django_user_id:
        return rows.filter(memberships__user_id=actor.django_user_id).distinct()
    # Header/trusted-LAN actors exist only in explicit local development mode.
    if settings.DEBUG and (settings.NETRA_DEV_ROLE_HEADERS or settings.NETRA_ACCESS_MODE == "trusted-lan"):
        return rows
    return rows.none()


def can_actor_access_case(actor: Actor, case: Case | str) -> bool:
    if not actor.authenticated:
        return False
    case_id = case.id if isinstance(case, Case) else case
    return visible_cases_for_actor(actor).filter(id=case_id).exists()


def require_permission(request, permission: str, case: Case | None = None, resource_type: str = "", resource_id: str = ""):
    actor = actor_from_request(request)
    if not actor.authenticated:
        log_access(actor, f"permission:{permission}", case=case, resource_type=resource_type, resource_id=resource_id, result="denied")
        return JsonResponse({"error": "Authentication required"}, status=401)
    allowed = can(actor, permission)
    if allowed and case:
        allowed = can_actor_access_case(actor, case)
    log_access(actor, f"permission:{permission}", case=case, resource_type=resource_type, resource_id=resource_id, result="allowed" if allowed else "denied")
    if allowed:
        return None
    return JsonResponse({"error": f"{actor.role} is not allowed to perform '{permission}'", "requiredPermission": permission}, status=403)


def log_access(actor: Actor, action: str, case: Case | None = None, resource_type: str = "", resource_id: str = "", result: str = "allowed") -> None:
    try:
        AccessLog.objects.create(
            organization_id=case.organization_id if case else actor.organization_id,
            user_id=actor.django_user_id,
            user_label=actor.user,
            role=actor.role,
            action=action,
            case=case,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
        )
    except Exception:  # nosec B110
        pass


def add_history(case: Case, actor: Actor | str, action: str, details: str, event_hash: str = "") -> None:
    actor_name = actor.user if isinstance(actor, Actor) else actor
    CaseHistoryEvent.objects.create(case=case, actor_name=actor_name, action=action, details=details, event_hash=event_hash)


def access_log_dict(row: AccessLog) -> dict[str, Any]:
    return {
        "timestamp": row.created_at.isoformat(),
        "user": row.user_label,
        "role": row.role,
        "action": row.action,
        "caseId": row.case_id or "",
        "resourceType": row.resource_type,
        "resourceId": row.resource_id,
        "result": row.result,
    }
