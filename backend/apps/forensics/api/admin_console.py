"""Administration console API.

Kept in its own module for the same reason authentication.py is: the routes
that can change who holds which permission should not be reachable by editing
a file whose job is something else. The module boundary test names this file
explicitly.

Every view here goes through require_privileged_admin, which re-reads the
administrator profile from the database on each request. That matters more than
it looks. The console is served from a frozen URL that never says "admin", and
that URL is privacy hardening — it hides which screen an operator is on from
browser history and shoulder-surfers. It authorizes nothing. Authorization is
this check, on every request, regardless of which bundle the edge happened to
serve.
"""

from __future__ import annotations

import json

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.forensics.api.errors import api_error
from apps.forensics.models import Organization, UserProfile
from apps.forensics.services.administration import AdministrationProblem, require_privileged_admin
from apps.forensics.services.admin_users import (
    account_payload,
    change_role,
    clear_authenticator,
    end_sessions,
    provision_account,
    replace_password,
    set_account_active,
)
from apps.forensics.services.admin_directory import directory_snapshot, role_slug
from common.admin_audit import verify_admin_chain
from common.audit import ROLE_PERMISSIONS, Actor, actor_from_request, log_access
from common.step_up import is_fresh
from common.supabase_admin import SupabaseAdminError


def _privileged_actor(request) -> tuple[Actor | None, JsonResponse | None]:
    actor = actor_from_request(request)
    if not actor.authenticated:
        return None, api_error(request, "authentication_required", "Authentication required.", status=401)
    try:
        require_privileged_admin(actor, actor.organization_id)
    except AdministrationProblem as problem:
        # Recorded whether or not it succeeded: a refused attempt to reach the
        # administration namespace is exactly the event an audit reviewer wants
        # to find, and it is invisible if only successes are written.
        log_access(actor, "admin_console.denied", resource_type="AdminConsole", result="denied")
        return None, api_error(request, problem.code, problem.message, status=problem.status)
    return actor, None


@require_http_methods(["GET"])
def admin_session(request):
    """Resolve the caller's own administrative standing.

    The console calls this before it offers Administration as a workspace. It
    replaces a local fallback in the browser that treated any account that
    could authenticate as an administrator — fenced behind a development flag,
    but the wrong shape of answer to trust for anything.
    """
    actor, denied = _privileged_actor(request)
    if denied:
        return denied
    organization = Organization.objects.filter(pk=actor.organization_id).first()
    if organization is None:
        return api_error(request, "resource_not_found", "The requested resource was not found.", status=404)
    log_access(actor, "admin_console.session", resource_type="AdminConsole", result="allowed")
    return JsonResponse(
        {
            "userId": actor.django_user_id,
            "name": actor.user,
            "email": actor.email,
            "role": actor.role,
            "roleSlug": role_slug(actor.role),
            # Ownership is inferred from the sole-Admin constraint until
            # Organization grows its own owner column.
            "isOwner": actor.role == UserProfile.Role.ADMIN,
            "aal": actor.aal,
            # Advisory only. The console reads this to decide whether to prompt
            # before showing a destructive dialog; the server re-checks it when
            # the operation actually arrives, because a value computed here is
            # stale by the time anyone acts on it.
            "stepUp": {
                "fresh": is_fresh(actor.factor_verified_at),
                "verifiedAt": actor.factor_verified_at.isoformat() if actor.factor_verified_at else None,
                "maxAgeSeconds": settings.NETRA_STEP_UP_MAX_AGE_SECONDS,
            },
            "permissions": sorted(ROLE_PERMISSIONS.get(actor.role, set())),
            "organization": {
                "id": str(organization.id),
                "name": organization.name,
                "slug": organization.slug,
            },
        }
    )


@require_http_methods(["GET"])
def admin_audit_verify(request):
    """Recompute the audit chain and report where it stops agreeing.

    Behind the console's Verify button. Deliberately a read: verification must
    never be able to alter what it is verifying, so it takes no step-up and
    writes nothing — including no audit entry of its own, which would grow the
    chain every time someone checked it.
    """
    actor, denied = _privileged_actor(request)
    if denied:
        return denied
    organization = Organization.objects.filter(pk=actor.organization_id).first()
    if organization is None:
        return api_error(request, "resource_not_found", "The requested resource was not found.", status=404)
    log_access(actor, "admin_console.audit_verify", resource_type="AdminAuditEvent", result="allowed")
    return JsonResponse(verify_admin_chain(organization))


@require_http_methods(["GET"])
def admin_directory(request):
    """One read for all nine screens. See services/admin_directory.py."""
    actor, denied = _privileged_actor(request)
    if denied:
        return denied
    organization = Organization.objects.filter(pk=actor.organization_id).first()
    if organization is None:
        return api_error(request, "resource_not_found", "The requested resource was not found.", status=404)
    log_access(actor, "admin_console.directory", resource_type="AdminConsole", result="allowed")
    return JsonResponse(directory_snapshot(organization))


def _json_body(request) -> tuple[dict, JsonResponse | None]:
    try:
        return (json.loads(request.body.decode("utf-8")) if request.body else {}), None
    except (UnicodeDecodeError, ValueError):
        return {}, api_error(request, "invalid_request_body", "A valid JSON request body is required.", status=400)


def _organization(request, actor):
    return Organization.objects.filter(pk=actor.organization_id).first()


def _write(request, operation):
    """Shared shape for every administrative write.

    Resolve the actor, refuse anything the guards refuse, and translate an
    AdministrationProblem into its own status rather than a generic 500 — the
    console distinguishes "confirm with your authenticator" from "you may not
    do this" from "the provider is down", and each needs its own answer.
    """
    actor, denied = _privileged_actor(request)
    if denied:
        return denied
    payload, invalid = _json_body(request)
    if invalid:
        return invalid
    organization = _organization(request, actor)
    if organization is None:
        return api_error(request, "resource_not_found", "The requested resource was not found.", status=404)
    try:
        return operation(actor, organization, payload)
    except AdministrationProblem as problem:
        log_access(
            actor,
            f"admin_console.{problem.code}",
            resource_type="User",
            result="denied",
        )
        return api_error(request, problem.code, problem.message, status=problem.status)
    except SupabaseAdminError:
        return api_error(
            request,
            "identity_provider_unavailable",
            "The identity provider is temporarily unavailable. No change was made.",
            status=503,
        )


@csrf_exempt
@require_http_methods(["POST"])
def admin_users(request):
    def operation(actor, organization, payload):
        change = provision_account(
            actor=actor,
            organization=organization,
            email=payload.get("email", ""),
            name=payload.get("name", ""),
            role=payload.get("role", ""),
            department=payload.get("department", ""),
            reason=payload.get("reason", ""),
        )
        # The only time this password is ever transmitted. It is not stored
        # here, not written to the audit entry, and cannot be retrieved again.
        return JsonResponse(
            {"user": account_payload(change.profile), "password": change.password},
            status=201,
        )

    return _write(request, operation)


@csrf_exempt
@require_http_methods(["POST"])
def admin_user_password(request, user_id: int):
    def operation(actor, organization, payload):
        change = replace_password(
            actor=actor,
            organization=organization,
            user_id=user_id,
            reason=payload.get("reason", ""),
        )
        return JsonResponse({"user": account_payload(change.profile), "password": change.password})

    return _write(request, operation)


@csrf_exempt
@require_http_methods(["DELETE"])
def admin_user_factors(request, user_id: int):
    def operation(actor, organization, payload):
        profile = clear_authenticator(
            actor=actor,
            organization=organization,
            user_id=user_id,
            reason=payload.get("reason", ""),
        )
        return JsonResponse({"user": account_payload(profile)})

    return _write(request, operation)


@csrf_exempt
@require_http_methods(["POST"])
def admin_user_status(request, user_id: int):
    def operation(actor, organization, payload):
        profile = set_account_active(
            actor=actor,
            organization=organization,
            user_id=user_id,
            active=bool(payload.get("active")),
            reason=payload.get("reason", ""),
        )
        return JsonResponse({"user": account_payload(profile)})

    return _write(request, operation)


@csrf_exempt
@require_http_methods(["POST"])
def admin_user_sessions_revoke(request, user_id: int):
    def operation(actor, organization, payload):
        profile = end_sessions(
            actor=actor,
            organization=organization,
            user_id=user_id,
            reason=payload.get("reason", ""),
        )
        return JsonResponse({"user": account_payload(profile)})

    return _write(request, operation)


@csrf_exempt
@require_http_methods(["PATCH"])
def admin_user_role(request, user_id: int):
    def operation(actor, organization, payload):
        profile = change_role(
            actor=actor,
            organization=organization,
            user_id=user_id,
            role=payload.get("role", ""),
            reason=payload.get("reason", ""),
        )
        return JsonResponse({"user": account_payload(profile)})

    return _write(request, operation)
