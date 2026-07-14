from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.forensics.models import AccessLog, Case, CaseHistoryEvent, CaseMembership, UserProfile


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
    user, _ = User.objects.get_or_create(username=username, defaults={"email": username})
    display_name = getattr(supabase_user, "display_name", "") or username
    profile, _created = UserProfile.objects.get_or_create(
        user=user,
        defaults={"role": UserProfile.Role.VIEWER, "display_name": display_name},
    )
    if not profile.display_name or profile.display_name == user.username:
        profile.display_name = display_name
    profile.save(update_fields=["role", "display_name", "updated_at"])
    return Actor(
        user=profile.display_name or user.username,
        role=profile.role,
        authenticated=True,
        django_user_id=user.id,
        email=user.email or user.username,
        external_id=getattr(supabase_user, "id", ""),
    )


def actor_from_request(request) -> Actor:
    cached_actor = getattr(request, "netra_actor", None)
    if isinstance(cached_actor, Actor):
        return cached_actor
    if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan":
        return Actor(user=settings.NETRA_TRUSTED_LAN_ACTOR, role=settings.NETRA_TRUSTED_LAN_ROLE, authenticated=True)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        if getattr(settings, "NETRA_AUTH_PROVIDER", "django") == "supabase":
            from common.supabase_auth import verify_supabase_token

            user = verify_supabase_token(token)
            if user:
                return sync_supabase_actor(user)
            return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
        try:
            auth = JWTAuthentication()
            validated = auth.get_validated_token(token)
            user = auth.get_user(validated)
            profile, _ = UserProfile.objects.get_or_create(
                user=user,
                defaults={"role": UserProfile.Role.VIEWER, "display_name": user.get_full_name() or user.get_username()},
            )
            return Actor(user=profile.display_name or user.get_username(), role=profile.role, authenticated=True, django_user_id=user.id)
        except Exception:
            return Actor(user="Unauthenticated", role="Viewer", authenticated=False)
    if settings.NETRA_DEV_ROLE_HEADERS:
        role = request.headers.get("X-Netra-Role", "Investigator")
        if role not in ROLE_PERMISSIONS:
            role = "Investigator"
        return Actor(user=request.headers.get("X-Netra-User", "Inspector A. Patel"), role=role, authenticated=True)
    return Actor(user="Unauthenticated", role="Viewer", authenticated=False)


def can(actor: Actor, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(actor.role, set())


def visible_cases_for_actor(actor: Actor):
    rows = Case.objects.all()
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
        AccessLog.objects.create(user_id=actor.django_user_id, user_label=actor.user, role=actor.role, action=action, case=case, resource_type=resource_type, resource_id=resource_id, result=result)
    except Exception:
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
