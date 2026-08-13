"""Authentication, organization-user, and administrator HTTP endpoints.

This module deliberately keeps identity verification separate from Netra's
organization and role authorization.  Supabase user metadata is never used as
an authorization source.
"""

from __future__ import annotations

import json

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.db.models import Max
from django.http import Http404, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AccessLog, OperationalEvent, UserProfile
from apps.forensics.services.administration import (
    AdministrationProblem,
    ensure_admin_mutation_allowed,
    transfer_administrator,
)
from common.audit import actor_from_request, can, require_permission, sync_supabase_actor
from common.capabilities import public_capabilities
from common.case_metadata import server_case_identity
from common.supabase_admin import (
    SupabaseAdminConflict,
    SupabaseAdminError,
    find_user_by_email,
    invite_user,
    list_users as list_auth_users,
)


def _json_body(request) -> dict:
    if not request.body:
        return {}
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _administration_problem_response(problem: AdministrationProblem) -> JsonResponse:
    return JsonResponse(
        {"error": {"code": problem.code, "message": problem.message}},
        status=problem.status,
    )


@csrf_exempt
@require_http_methods(["POST"])
def auth_login(request):
    payload = _json_body(request)
    email = payload.get("email") or payload.get("username")
    password = payload.get("password")
    if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase":
        from common.supabase_auth import supabase_password_login, verify_supabase_token

        session = supabase_password_login(email, password)
        if not session or not session.get("access_token"):
            return JsonResponse({"error": "Invalid Supabase credentials"}, status=401)
        supabase_user = verify_supabase_token(session["access_token"])
        if supabase_user is None:
            return JsonResponse({"error": "Invalid Supabase credentials"}, status=401)
        actor = sync_supabase_actor(supabase_user) if supabase_user else None
        if actor and not actor.organization_id:
            return JsonResponse(
                {
                    "error": "A Netra profile has not been provisioned for this identity.",
                    "code": "profile_not_provisioned",
                },
                status=403,
            )
        return JsonResponse(
            {
                "access": session["access_token"],
                "refresh": session.get("refresh_token", ""),
                "expiresIn": session.get("expires_in"),
                "user": {
                    "id": supabase_user.id if supabase_user else "",
                    "email": supabase_user.email if supabase_user else email,
                    "name": actor.user if actor else (supabase_user.display_name if supabase_user else email),
                    "role": actor.role if actor else "Viewer",
                },
            }
        )
    user = authenticate(request, username=email, password=password)
    if not user:
        return JsonResponse({"error": "Invalid credentials"}, status=401)
    profile = UserProfile.objects.filter(user=user).first()
    if profile is None:
        return JsonResponse(
            {
                "error": "A Netra profile has not been provisioned for this identity.",
                "code": "profile_not_provisioned",
            },
            status=403,
        )
    refresh = RefreshToken.for_user(user)
    return JsonResponse(
        {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {
                "id": user.id,
                "email": user.username,
                "name": profile.display_name or user.get_full_name() or user.username,
                "role": profile.role,
            },
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
def auth_refresh(request):
    payload = _json_body(request)
    if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase":
        from common.supabase_auth import supabase_refresh

        session = supabase_refresh(payload.get("refresh", ""))
        if not session or not session.get("access_token"):
            return JsonResponse({"error": "Invalid refresh token"}, status=401)
        return JsonResponse(
            {
                "access": session["access_token"],
                "refresh": session.get("refresh_token", payload.get("refresh", "")),
                "expiresIn": session.get("expires_in"),
            }
        )
    try:
        refresh = RefreshToken(payload["refresh"])
        return JsonResponse({"access": str(refresh.access_token)})
    except Exception:
        return JsonResponse({"error": "Invalid refresh token"}, status=401)


@csrf_exempt
@require_http_methods(["POST"])
def auth_logout(_request):
    return JsonResponse({"status": "logged-out"})


def auth_me(request):
    actor = actor_from_request(request)
    if not actor.authenticated:
        return JsonResponse({"error": "Authentication required"}, status=401)
    investigator, department = server_case_identity(actor)
    is_admin = actor.role == "Admin"
    operator = can(actor, "operations")
    modules = {
        "lab": {
            "enabled": settings.NETRA_ENABLE_PCAP_REPLAY,
            "visible": operator,
            "reason": "Isolated uploaded-PCAP replay is enabled; it does not transmit packets onto a live network."
            if settings.NETRA_ENABLE_PCAP_REPLAY
            else "Requires an isolated PCAP replay environment.",
        },
        "sensors": {
            "enabled": settings.NETRA_ENABLE_SENSOR_CAPTURE,
            "visible": is_admin,
            "reason": "Native capture runs on an enrolled sensor, never inside the Railway web container.",
        },
        "schedules": {
            "enabled": settings.NETRA_ENABLE_CAPTURE_SCHEDULES,
            "visible": is_admin,
            "reason": "Capture scheduling is disabled in the public hackathon profile.",
        },
        "integrations": {
            "enabled": settings.NETRA_ENABLE_INTEGRATIONS,
            "visible": is_admin,
            "reason": "SIEM and webhook delivery require administrator configuration.",
        },
        "retention": {
            "enabled": settings.NETRA_ENABLE_RETENTION_OPERATIONS,
            "visible": is_admin,
            "reason": "Retention execution is disabled until an administrator verifies policy and backups.",
        },
        "system": {
            "enabled": True,
            "visible": is_admin,
            "reason": "Administrator diagnostics only.",
        },
    }
    return JsonResponse(
        {
            "user": investigator,
            "department": department,
            "role": actor.role,
            "authenticated": True,
            "organization": {
                "id": str(actor.organization_id),
                "name": "Netra" if actor.organization_slug == "netra" else actor.organization_slug,
                "slug": actor.organization_slug,
            },
            "aal": actor.aal,
            "mfaPolicy": settings.NETRA_MFA_POLICY,
            "mfaEnrollmentRequired": is_admin and actor.aal != "aal2",
            "privilegedAdminReady": actor.role == "Admin" and actor.aal == "aal2",
            "capabilities": public_capabilities(),
            "deployment": {
                "profile": settings.NETRA_DEPLOYMENT_PROFILE,
                "hostCaptureEnabled": settings.NETRA_ENABLE_HOST_CAPTURE,
                "replayEnabled": settings.NETRA_ENABLE_PCAP_REPLAY,
                "sensorCaptureEnabled": settings.NETRA_ENABLE_SENSOR_CAPTURE,
                "modules": modules,
            },
        }
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def users(request):
    denied = require_permission(request, "manage_users", resource_type="User")
    if denied:
        return denied
    User = get_user_model()
    actor = actor_from_request(request)
    try:
        ensure_admin_mutation_allowed(actor)
    except AdministrationProblem as problem:
        return _administration_problem_response(problem)
    if request.method == "POST":
        payload = _json_body(request)
        email = str(payload.get("email") or "").strip().lower()
        role = payload.get("role", "Viewer")
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({"error": "email and a valid non-administrator role are required"}, status=400)
        if role not in {"Investigator", "Analyst", "Viewer"}:
            return JsonResponse({"error": "email and a valid non-administrator role are required"}, status=400)
        if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" and "password" in payload:
            return JsonResponse(
                {"error": "Passwords are managed by Supabase Auth.", "code": "password_not_accepted"},
                status=400,
            )
        if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase":
            if not settings.NETRA_AUTH_INVITATIONS_ENABLED:
                return JsonResponse(
                    {
                        "error": {
                            "code": "feature_disabled",
                            "message": "User invitations require an approved custom SMTP domain.",
                            "feature": "user_invitations",
                        }
                    },
                    status=503,
                )
            existing_profile = UserProfile.objects.select_related("user").filter(user__username__iexact=email).first()
            if existing_profile and existing_profile.organization_id != actor.organization_id:
                return JsonResponse(
                    {"error": {"code": "user_provisioning_conflict", "message": "The user cannot be provisioned."}},
                    status=409,
                )
            try:
                try:
                    auth_user = invite_user(email, redirect_to=settings.NETRA_AUTH_INVITE_REDIRECT_URL)
                    invitation_state = "sent"
                except SupabaseAdminConflict:
                    auth_user = find_user_by_email(email)
                    if auth_user is None:
                        raise SupabaseAdminError("Supabase Auth identity reconciliation failed.")
                    invitation_state = "accepted" if auth_user.email_confirmed_at else "pending"
            except SupabaseAdminError:
                return JsonResponse(
                    {
                        "error": {
                            "code": "auth_provider_unavailable",
                            "message": "The identity provider is temporarily unavailable.",
                        }
                    },
                    status=503,
                )

            with transaction.atomic():
                user, created = User.objects.get_or_create(
                    username=email,
                    defaults={"email": email, "first_name": payload.get("name", email), "is_active": True},
                )
                profile = UserProfile.objects.filter(user=user).first()
                if profile and profile.organization_id != actor.organization_id:
                    return JsonResponse(
                        {"error": {"code": "user_provisioning_conflict", "message": "The user cannot be provisioned."}},
                        status=409,
                    )
                if profile and profile.role == UserProfile.Role.ADMIN:
                    # Administrators are changed through the administration
                    # namespace, which seals every change into the audit chain.
                    # The refusal is kept now that several administrators are
                    # permitted, but the old code named a rule that no longer
                    # exists: there is no longer a sole administrator.
                    return JsonResponse(
                        {
                            "error": {
                                "code": "administrator_change_forbidden",
                                "message": "Administrator accounts are managed through the administration console.",
                            }
                        },
                        status=409,
                    )
                user.email = email
                user.first_name = str(payload.get("name") or email).strip()
                user.is_active = True
                user.set_unusable_password()
                user.save()
                profile, _ = UserProfile.objects.update_or_create(
                    user=user,
                    defaults={
                        "organization_id": actor.organization_id,
                        "role": role,
                        "display_name": str(payload.get("name") or email).strip(),
                    },
                )
                AccessLog.objects.create(
                    organization_id=actor.organization_id,
                    user_id=actor.django_user_id,
                    user_label=actor.user,
                    role=actor.role,
                    action="organization.user_invited",
                    resource_type="User",
                    resource_id=str(user.id),
                    result="allowed",
                )
                OperationalEvent.objects.create(
                    organization_id=actor.organization_id,
                    event_type="organization.user_invited",
                    payload_json={
                        "targetUserId": user.id,
                        "targetAuthUserId": auth_user.id,
                        "role": role,
                        "invitationState": invitation_state,
                    },
                )
            return JsonResponse(
                {
                    "id": user.id,
                    "email": user.username,
                    "name": profile.display_name,
                    "role": profile.role,
                    "created": created,
                    "invitationState": invitation_state,
                    "authState": "active" if auth_user.email_confirmed_at else "invited",
                },
                status=201 if created else 200,
            )
        user, created = User.objects.get_or_create(
            username=email,
            defaults={"email": email, "first_name": payload.get("name", email)},
        )
        if payload.get("password"):
            user.set_password(payload["password"])
            user.save()
        profile, _ = UserProfile.objects.update_or_create(
            user=user,
            defaults={
                "organization_id": actor.organization_id,
                "role": role,
                "display_name": payload.get("name", email),
            },
        )
        return JsonResponse(
            {
                "id": user.id,
                "email": user.username,
                "name": profile.display_name,
                "role": profile.role,
                "created": created,
            },
            status=201,
        )
    try:
        limit = max(1, min(100, int(request.GET.get("limit", "50"))))
        cursor = max(0, int(request.GET.get("cursor", "0")))
    except ValueError:
        return JsonResponse(
            {"error": {"code": "invalid_cursor", "message": "The user-list cursor is invalid."}},
            status=400,
        )
    profile_query = (
        UserProfile.objects.filter(organization_id=actor.organization_id)
        .select_related("user", "organization")
        .order_by("user__username")
    )
    total = profile_query.count()
    profiles = list(profile_query[cursor : cursor + limit])
    user_ids = [profile.user_id for profile in profiles]
    last_activity = {
        row["user_id"]: row["latest"]
        for row in AccessLog.objects.filter(organization_id=actor.organization_id, user_id__in=user_ids)
        .values("user_id")
        .annotate(latest=Max("created_at"))
    }
    auth_by_email = {}
    auth_metadata_status = "not_applicable"
    if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase":
        auth_metadata_status = "available"
        try:
            auth_users, _ = list_auth_users(page=1)
            auth_by_email = {row.email: row for row in auth_users}
        except SupabaseAdminError:
            auth_metadata_status = "degraded"
    rows = []
    for profile in profiles:
        user = profile.user
        auth_user = auth_by_email.get(user.username.strip().lower())
        invitation_state = "unknown"
        auth_state = "unknown" if auth_metadata_status == "degraded" else "missing"
        mfa_state = "unknown" if auth_metadata_status == "degraded" else "unenrolled"
        last_sign_in_at = ""
        if auth_user:
            auth_state = "active" if auth_user.email_confirmed_at else "invited"
            invitation_state = "accepted" if auth_user.email_confirmed_at else "pending"
            mfa_state = auth_user.mfa_state
            last_sign_in_at = auth_user.last_sign_in_at
        rows.append({
            "id": user.id,
            "email": user.username,
            "name": profile.display_name,
            "role": profile.role,
            "active": user.is_active,
            "organization": {
                "id": str(profile.organization_id),
                "name": profile.organization.name,
                "slug": profile.organization.slug,
            },
            "authState": auth_state,
            "invitationState": invitation_state,
            "mfaState": mfa_state,
            "lastSignInAt": last_sign_in_at,
            "lastActivityAt": last_activity[user.id].isoformat() if last_activity.get(user.id) else "",
        })
    next_cursor = cursor + limit if cursor + limit < total else None
    return JsonResponse(
        {
            "results": rows,
            "users": rows,
            "nextCursor": next_cursor,
            "authMetadataStatus": auth_metadata_status,
        }
    )


@csrf_exempt
@require_http_methods(["PATCH"])
def user_detail(request, user_id: str):
    denied = require_permission(request, "manage_users", resource_type="User", resource_id=user_id)
    if denied:
        return denied
    payload = _json_body(request)
    actor = actor_from_request(request)
    profile = (
        UserProfile.objects.select_related("user")
        .filter(user_id=user_id, organization_id=actor.organization_id)
        .first()
    )
    if not profile:
        raise Http404("User not found")
    try:
        ensure_admin_mutation_allowed(actor, profile)
    except AdministrationProblem as problem:
        return _administration_problem_response(problem)
    user = profile.user
    if payload.get("role") in {"Investigator", "Analyst", "Viewer"} and profile.role != "Admin":
        profile.role = payload["role"]
    if "active" in payload:
        user.is_active = bool(payload["active"])
    profile.display_name = payload.get("name", profile.display_name)
    profile.save()
    user.save()
    return JsonResponse(
        {
            "id": user.id,
            "email": user.username,
            "name": profile.display_name,
            "role": profile.role,
            "active": user.is_active,
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
def admin_transfer(request, organization_id):
    payload = _json_body(request)
    try:
        target_user_id = int(payload.get("targetUserId"))
    except (TypeError, ValueError):
        return JsonResponse(
            {"error": {"code": "invalid_target_user", "message": "targetUserId is required."}},
            status=400,
        )
    try:
        result = transfer_administrator(
            actor=actor_from_request(request),
            organization_id=organization_id,
            target_user_id=target_user_id,
            reason=str(payload.get("reason") or ""),
        )
    except AdministrationProblem as problem:
        return _administration_problem_response(problem)
    return JsonResponse(result)
