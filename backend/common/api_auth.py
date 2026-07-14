from __future__ import annotations

import re

from django.conf import settings
from django.http import JsonResponse

from common.audit import actor_from_request, can, can_actor_access_case
from common.operations import sensor_key_valid


_SENSOR_AGENT_ROUTES = (
    ("POST", re.compile(r"^/api/sensors/register/?$")),
    ("POST", re.compile(r"^/api/sensors/[^/]+/heartbeat/?$")),
    ("GET", re.compile(r"^/api/sensors/[^/]+/commands/next/?$")),
    ("POST", re.compile(r"^/api/sensors/[^/]+/chunks/?$")),
    ("POST", re.compile(r"^/api/sensors/[^/]+/captures/[^/]+/(?:complete|fail)/?$")),
)


def _is_sensor_agent_route(method: str, path: str) -> bool:
    return any(method == expected_method and pattern.fullmatch(path) for expected_method, pattern in _SENSOR_AGENT_ROUTES)


def _authentication_error() -> JsonResponse:
    return JsonResponse(
        {"error": "Authentication required", "code": "authentication_required"},
        status=401,
    )


def _not_found() -> JsonResponse:
    # Deliberately hide whether the case exists from actors outside its boundary.
    return JsonResponse({"error": "Resource not found", "code": "resource_not_found"}, status=404)


def _permission_error() -> JsonResponse:
    return JsonResponse({"error": "Permission denied", "code": "permission_denied"}, status=403)


def _feature_disabled(feature: str) -> JsonResponse:
    return JsonResponse(
        {
            "error": f"{feature} is not configured for this deployment profile.",
            "code": "feature_disabled",
            "feature": feature,
            "profile": settings.NETRA_DEPLOYMENT_PROFILE,
        },
        status=404,
    )


def _disabled_feature(path: str) -> str | None:
    feature_gates = (
        (("/api/capture/replay",), settings.NETRA_ENABLE_PCAP_REPLAY, "PCAP replay"),
        (
            ("/api/capture/live", "/api/capture/interfaces", "/api/capture/log-import", "/api/sensors", "/api/sensor-groups", "/api/events", "/api/logs/import/zeek"),
            settings.NETRA_ENABLE_SENSOR_CAPTURE,
            "Native sensor capture",
        ),
        (("/api/capture-schedules",), settings.NETRA_ENABLE_CAPTURE_SCHEDULES, "Capture schedules"),
        (("/api/integrations",), settings.NETRA_ENABLE_INTEGRATIONS, "Integrations and webhooks"),
        (("/api/retention",), settings.NETRA_ENABLE_RETENTION_OPERATIONS, "Retention operations"),
    )
    for prefixes, enabled, label in feature_gates:
        if not enabled and any(path == prefix or path.startswith(f"{prefix}/") for prefix in prefixes):
            return label
    return None


def _required_permission(method: str, path: str) -> str | None:
    if path.rstrip("/") == "/api/auth/logout":
        return None
    privileged_prefixes = (
        ("/api/users", "manage_users"),
        ("/api/setup", "manage_users"),
        ("/api/system", "operations"),
        ("/api/capture", "operations"),
        ("/api/sensors", "operations"),
        ("/api/sensor-groups", "operations"),
        ("/api/capture-schedules", "operations"),
        ("/api/events", "operations"),
        ("/api/integrations", "integrations"),
        ("/api/compliance", "compliance"),
        ("/api/retention", "compliance"),
        ("/api/audit", "compliance"),
    )
    for prefix, permission in privileged_prefixes:
        if path == prefix or path.startswith(f"{prefix}/"):
            return permission
    if method == "GET":
        return "view"
    if path.startswith("/api/evidence") or path.startswith("/api/capture") or path == "/api/cases":
        return "upload"
    if path.startswith("/api/reports"):
        return "report"
    if path.startswith("/api/exports"):
        return "export"
    return "review"


class NetraApiAuthMiddleware:
    """Default-deny authentication and case-boundary enforcement for Netra APIs."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith("/api/") or not settings.NETRA_PUBLIC_API_AUTH_REQUIRED:
            return self.get_response(request)
        if request.method == "OPTIONS" or (request.method == "GET" and request.path.rstrip("/") == "/api/health"):
            return self.get_response(request)
        if settings.NETRA_AUTH_PROXY_ENABLED and request.path.rstrip("/") in {"/api/auth/login", "/api/auth/refresh"}:
            return self.get_response(request)
        if _is_sensor_agent_route(request.method, request.path):
            if not sensor_key_valid(request):
                return _authentication_error()
            disabled_feature = _disabled_feature(request.path.rstrip("/"))
            if disabled_feature:
                return _feature_disabled(disabled_feature)
            request.netra_sensor_authenticated = True
            return self.get_response(request)

        actor = actor_from_request(request)
        if not actor.authenticated:
            return _authentication_error()
        request.netra_actor = actor
        return self.get_response(request)

    def process_view(self, request, _view_func, view_args, view_kwargs):
        if not request.path.startswith("/api/") or request.method == "OPTIONS":
            return None
        actor = getattr(request, "netra_actor", None)
        if actor is None:
            return None

        disabled_feature = _disabled_feature(request.path.rstrip("/"))
        if disabled_feature:
            return _feature_disabled(disabled_feature)

        permission = _required_permission(request.method, request.path.rstrip("/"))
        if permission and not can(actor, permission):
            return _permission_error()

        case_ids = []
        if view_kwargs.get("case_id"):
            case_ids.append(str(view_kwargs["case_id"]))
        query_case_id = request.GET.get("caseId") or request.POST.get("caseId")
        if query_case_id:
            case_ids.append(str(query_case_id))
        for case_id in set(case_ids):
            if not can_actor_access_case(actor, case_id) and not self._may_create_case(request, case_id):
                return _not_found()

        resource_case_id = self._resource_case_id(view_kwargs)
        if resource_case_id and not can_actor_access_case(actor, resource_case_id):
            return _not_found()
        return None

    @staticmethod
    def _may_create_case(request, case_id: str) -> bool:
        if request.method != "POST":
            return False
        from apps.forensics.models import Case

        if Case.objects.filter(pk=case_id).exists():
            return False
        path = request.path.rstrip("/")
        return path in {"/api/evidence/upload", "/api/evidence/upload-sessions"} or path.startswith("/api/capture/")

    @staticmethod
    def _resource_case_id(view_kwargs) -> str | None:
        # Direct-ID downloads/status routes must inherit the parent case boundary.
        from apps.forensics.models import CaptureJob, EvidenceFile, EvidenceUploadSession, Export, ProcessingJob, Report

        lookups = (
            ("evidence_id", EvidenceFile, "case_id"),
            ("report_id", Report, "case_id"),
            ("export_id", Export, "case_id"),
            ("upload_session_id", EvidenceUploadSession, "case_id"),
        )
        for kwarg, model, field in lookups:
            value = view_kwargs.get(kwarg)
            if value:
                return model.objects.filter(pk=value).values_list(field, flat=True).first()
        job_id = view_kwargs.get("job_id")
        if job_id:
            case_id = ProcessingJob.objects.filter(pk=job_id).values_list("case_id", flat=True).first()
            return case_id or CaptureJob.objects.filter(pk=job_id).values_list("case_id", flat=True).first()
        return None
