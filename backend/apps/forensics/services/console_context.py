from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.forensics.models import ConsoleContext, UserProfile
from common.audit import Actor, can


@dataclass(frozen=True)
class ConsoleContextProblem(Exception):
    code: str
    message: str
    status: int = 403


def workspace_contract(actor: Actor) -> dict[str, dict[str, object]]:
    return {
        "investigation": {"available": bool(actor.organization_id), "requiredAal": "aal2"},
        "administration": {
            "available": bool(actor.organization_id and can(actor, "manage_users")),
            "permission": "manage_users",
            "requiredAal": "aal2",
            "stepUpRequired": True,
        },
    }


def _profile(actor: Actor) -> UserProfile:
    profile = UserProfile.objects.select_related("user", "organization").filter(
        user_id=actor.django_user_id,
        organization_id=actor.organization_id,
        user__is_active=True,
    ).first()
    if profile is None:
        raise ConsoleContextProblem("profile_not_provisioned", "Console access is not provisioned.")
    if profile.must_change_password:
        raise ConsoleContextProblem("password_change_required", "A password change is required.")
    if profile.mfa_reset_required:
        raise ConsoleContextProblem("mfa_enrollment_required", "Multi-factor enrollment is required.")
    return profile


def _require_aal2(actor: Actor) -> None:
    if settings.NETRA_MFA_POLICY == "all_required" and actor.aal != "aal2":
        raise ConsoleContextProblem("aal2_required", "Multi-factor authentication is required.")


@transaction.atomic
def create_console_context(actor: Actor) -> ConsoleContext:
    profile = _profile(actor)
    _require_aal2(actor)
    if not actor.session_id:
        raise ConsoleContextProblem("session_invalid", "The authenticated session has no stable identifier.", 401)
    now = timezone.now()
    ConsoleContext.objects.filter(
        user_id=profile.user_id,
        session_id=actor.session_id,
        revoked_at__isnull=True,
    ).update(revoked_at=now, revoked_reason="superseded")
    workspaces = [key for key, value in workspace_contract(actor).items() if value["available"]]
    return ConsoleContext.objects.create(
        user_id=profile.user_id,
        organization_id=profile.organization_id,
        session_id=actor.session_id,
        permissions_version=profile.organization.permissions_version,
        assurance_level=actor.aal,
        active_workspace="investigation",
        allowed_workspaces_json=workspaces,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=settings.NETRA_CONSOLE_CONTEXT_MAX_AGE_SECONDS),
    )


def context_payload(context: ConsoleContext) -> dict[str, object]:
    return {
        "contextId": str(context.id),
        "activeWorkspace": context.active_workspace,
        "allowedWorkspaces": list(context.allowed_workspaces_json),
        "assuranceLevel": context.assurance_level,
        "expiresAt": context.expires_at.isoformat(),
        "lastSeenAt": context.last_seen_at.isoformat(),
    }


@transaction.atomic
def validate_console_context(actor: Actor, raw_context_id: str, *, touch: bool = True) -> ConsoleContext:
    try:
        context_id = UUID(str(raw_context_id))
    except (TypeError, ValueError, AttributeError):
        raise ConsoleContextProblem("console_context_invalid", "Console context is invalid.", 401)
    context = ConsoleContext.objects.select_for_update().select_related("organization", "user").filter(pk=context_id).first()
    if context is None or context.revoked_at is not None:
        raise ConsoleContextProblem("console_context_invalid", "Console context is invalid.", 401)
    now = timezone.now()
    idle_limit = (
        settings.NETRA_ADMINISTRATION_IDLE_SECONDS
        if context.active_workspace == "administration"
        else settings.NETRA_INVESTIGATION_IDLE_SECONDS
    )
    invalid_reason = ""
    if context.user_id != actor.django_user_id or context.organization_id != actor.organization_id:
        invalid_reason = "identity_changed"
    elif not actor.session_id or context.session_id != actor.session_id:
        invalid_reason = "session_changed"
    elif context.permissions_version != context.organization.permissions_version:
        invalid_reason = "permissions_changed"
    elif context.expires_at <= now:
        invalid_reason = "expired"
    elif context.last_seen_at <= now - timedelta(seconds=idle_limit):
        invalid_reason = "idle_timeout"
    elif settings.NETRA_MFA_POLICY == "all_required" and actor.aal != "aal2":
        invalid_reason = "assurance_changed"
    if invalid_reason:
        context.revoked_at = now
        context.revoked_reason = invalid_reason
        context.save(update_fields=["revoked_at", "revoked_reason", "updated_at"])
        raise ConsoleContextProblem("console_context_expired", "Console context has expired.", 401)
    _profile(actor)
    if touch:
        context.last_seen_at = now
        context.save(update_fields=["last_seen_at", "updated_at"])
    return context


@transaction.atomic
def switch_console_workspace(actor: Actor, context_id: str, workspace: str) -> ConsoleContext:
    context = validate_console_context(actor, context_id, touch=False)
    if workspace not in {"investigation", "administration"} or workspace not in context.allowed_workspaces_json:
        raise ConsoleContextProblem("workspace_not_available", "The requested workspace is not available.", 403)
    if workspace == "administration" and (actor.aal != "aal2" or not can(actor, "manage_users")):
        raise ConsoleContextProblem("workspace_not_available", "The requested workspace is not available.", 403)
    context.active_workspace = workspace
    context.last_seen_at = timezone.now()
    context.save(update_fields=["active_workspace", "last_seen_at", "updated_at"])
    return context


def revoke_console_context(actor: Actor, raw_context_id: str, reason: str = "signed_out") -> None:
    context = validate_console_context(actor, raw_context_id, touch=False)
    context.revoked_at = timezone.now()
    context.revoked_reason = reason[:160]
    context.save(update_fields=["revoked_at", "revoked_reason", "updated_at"])


def revoke_user_console_contexts(user_id: int, reason: str) -> int:
    return ConsoleContext.objects.filter(user_id=user_id, revoked_at__isnull=True).update(
        revoked_at=timezone.now(),
        revoked_reason=reason[:160],
    )
