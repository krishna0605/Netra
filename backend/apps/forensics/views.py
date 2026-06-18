import json
import os
import hmac
import hashlib
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.cache import cache
from django.db import connection
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AccessLog, CaptureJob, CaptureSchedule, Case, CaseLink, CaseMembership, ComplianceControl, CustodyLedgerEvent, DeadLetterEvent, EvidenceFile, EvidenceManifest, Export, IntegrationConnection, IntegrationCredential, IntegrationDelivery, OperationalEvent, ProcessingJob, Report, RetentionPolicy, RetentionRun, Sensor, SensorCommand, SensorGroup, SensorHealthSnapshot, UserProfile, WorkerHeartbeat
from common.audit import access_log_dict, actor_from_request, add_history, log_access, require_permission, sync_supabase_actor
from common.analysis import analyze_pcap, empty_analysis
from common.artifacts import generate_export_artifact, generate_pdf_report_artifact, generate_report_artifact
from common.async_pipeline import queue_uploaded_evidence
from common.case_workspace import bump_case_list_cache_version, case_list_cache_version, workspace_for_case
from common.custody import custody_event_dict, record_custody_event, verify_case_ledger
from common.detection import classify_detection, load_rules
from common.evidence_normalization import normalize_evidence_upload
from common.indexing import search_index
from common.jobs import job_status_payload
from common.kafka import probe_supabase_queue, publish_event
from common.pcap import available_packet_tools
from common.persistence import VALIDATOR_CASE_PREFIXES, analysis_for_case, latest_job_for_case, persist_analysis, record_export, update_analysis_alert_status
from common.readiness import audit_export_payload, deployment_readiness_payload, incident_readiness_payload, legal_review_checklist, ml_model_status_payload, status_matrix_payload
from common.hashing import sha256_file, sha256_text
from common.fleet import backpressure_allows_new_capture, capacity_payload, ensure_default_retention_policy, execute_safe_retention, kafka_lag_payload, queue_schedule_run, retention_policy_payload, retention_preview, retention_run_payload, schedule_payload, sensor_group_payload
from common.operations import capture_job_payload, create_capture_job, emit_operational_event, ensure_capture_case, expire_stale_replay, finalize_capture, heartbeat_state, ingest_capture_chunk, mark_capture_running, sensor_key_valid, sensor_payload, start_replay, stop_capture, validate_capture_bounds, worker_payload
from common.storage_provider import storage_provider
from common.storage import save_uploaded_file, write_text_artifact
from common.vault import fernet, read_encrypted_or_plain


def _json_body(request) -> dict:
    if not request.body:
        return {}
    return json.loads(request.body.decode("utf-8"))


def _filter_rows(rows: list[dict], params, field_map: dict[str, str]) -> list[dict]:
    filtered = rows
    for query_key, row_key in field_map.items():
        value = params.get(query_key)
        if not value or value == "all":
            continue
        filtered = [row for row in filtered if value.lower() in str(row.get(row_key, "")).lower()]
    return filtered


def _paged(rows: list[dict], request) -> dict:
    try:
        limit = max(1, min(500, int(request.GET.get("limit", "100"))))
        offset = max(0, int(request.GET.get("offset", "0")))
    except ValueError:
        limit, offset = 100, 0
    sliced = rows[offset : offset + limit]
    next_offset = offset + limit if offset + limit < len(rows) else None
    return {"count": len(rows), "limit": limit, "offset": offset, "nextOffset": next_offset, "results": sliced}


def _analysis(request=None, case_id: str | None = None) -> dict:
    selected_case = case_id or (request.GET.get("caseId") if request is not None else None)
    return analysis_for_case(selected_case) or empty_analysis()


def _results(key: str, request=None) -> list[dict]:
    return _analysis(request).get(key, [])


def _is_probable_validator_case(case: Case) -> bool:
    if case.is_test or case.origin in {Case.Origin.VALIDATOR, Case.Origin.SYSTEM_TEST}:
        return True
    if any(case.id.startswith(prefix) for prefix in VALIDATOR_CASE_PREFIXES):
        return True
    investigator = (case.investigator or "").lower()
    return "validator" in investigator or "readiness" in investigator


def _visible_cases_queryset(request):
    rows = Case.objects.order_by("-updated_at")
    include_test = request.GET.get("includeTest") in {"1", "true", "yes"}
    if not include_test:
        test_query = Q(is_test=True) | Q(origin__in=[Case.Origin.VALIDATOR, Case.Origin.SYSTEM_TEST])
        for prefix in VALIDATOR_CASE_PREFIXES:
            test_query |= Q(id__startswith=prefix)
        rows = rows.exclude(test_query)
    status = request.GET.get("status")
    if status and status != "all":
        rows = rows.filter(status=status)
    priority = request.GET.get("priority")
    if priority and priority != "all":
        rows = rows.filter(priority=priority)
    query_text = (request.GET.get("q") or "").strip()
    if query_text:
        rows = rows.filter(Q(id__icontains=query_text) | Q(title__icontains=query_text) | Q(investigator__icontains=query_text) | Q(source_location__icontains=query_text))
    return rows


def _report_dict(report: Report) -> dict:
    filename = report.id.removesuffix(".enc")
    return {
        "id": report.id,
        "caseId": report.case_id,
        "caseTitle": report.case.title if report.case_id else "",
        "caseStatus": report.case.status if report.case_id else "",
        "openedAt": report.case.opened_at.isoformat() if report.case_id and report.case.opened_at else report.case.created_at.isoformat() if report.case_id else "",
        "closedAt": report.case.closed_at.isoformat() if report.case_id and report.case.closed_at else "",
        "title": f"{report.case_id} forensic report" if report.case_id else filename,
        "language": report.language,
        "format": "PDF" if filename.lower().endswith(".pdf") else "HTML",
        "status": report.status,
        "generatedBy": report.generated_by,
        "generatedAt": report.created_at.isoformat(),
        "sha256": report.sha256,
        "filename": filename,
        "downloadUrl": f"/api/reports/{report.id}/download",
    }


def _case_dict(case: Case) -> dict:
    snapshot = getattr(case, "analysis_snapshot", None)
    snapshot_json = snapshot.snapshot_json if snapshot and isinstance(snapshot.snapshot_json, dict) else {}
    snapshot_case = snapshot_json.get("case", {}) if isinstance(snapshot_json.get("case"), dict) else {}
    snapshot_summary = snapshot_json.get("summary", {}) if isinstance(snapshot_json.get("summary"), dict) else {}
    latest_job = None if snapshot_json else latest_job_for_case(case.id)
    analysis = latest_job.stats.get("analysis", {}) if latest_job else {}
    latest_report = case.reports.order_by("-created_at").first()
    evidence = case.evidence_files.order_by("-created_at").first()
    packets = analysis.get("packets", [])
    sessions = analysis.get("sessions", [])
    links = [
        {
            "id": link.id,
            "caseId": link.target_case_id,
            "caseTitle": link.target_case.title,
            "relationType": link.relation_type,
            "notes": link.notes,
        }
        for link in case.outgoing_links.select_related("target_case").order_by("-created_at")[:20]
    ]
    return {
        "id": case.id,
        "title": case.title,
        "investigator": case.investigator,
        "department": case.department,
        "status": case.status,
        "priority": case.priority,
        "origin": case.origin,
        "isTest": _is_probable_validator_case(case),
        "openedAt": case.opened_at.isoformat() if case.opened_at else case.created_at.isoformat(),
        "closedAt": case.closed_at.isoformat() if case.closed_at else "",
        "sourceLocation": case.source_location,
        "remarks": case.remarks,
        "flags": case.flags_json if isinstance(case.flags_json, list) else [],
        "linkedCases": links,
        "evidenceFileId": (latest_job.evidence_file_id if latest_job else ""),
        "evidenceFilename": evidence.filename if evidence else "",
        "alertIds": [alert.get("id") for alert in analysis.get("alerts", [])],
        "notes": [event.details for event in case.history.order_by("-created_at")[:8]],
        "history": [
            {"id": f"hist-{event.id}", "timestamp": event.created_at.isoformat(), "actor": event.actor_name, "action": event.action, "details": event.details}
            for event in case.history.order_by("-created_at")[:20]
        ],
        "createdAt": case.created_at.isoformat(),
        "reportStatus": case.report_status,
        "riskLevel": snapshot_summary.get("riskLevel") or snapshot_case.get("riskLevel") or analysis.get("riskLevel", "low"),
        "topAttackClass": snapshot_summary.get("topAttackClass") or snapshot_case.get("topAttackClass") or analysis.get("topAttackClass", "Normal Baseline"),
        "alertCount": snapshot_summary.get("alerts", len(analysis.get("alerts", []))),
        "packetCount": snapshot_summary.get("packets", analysis.get("summary", {}).get("packets", len(packets))),
        "sessionCount": snapshot_summary.get("sessions", analysis.get("summary", {}).get("sessions", len(sessions))),
        "latestReportId": snapshot_case.get("latestReportId") or (latest_report.id if latest_report else ""),
        "latestReportDownloadUrl": snapshot_case.get("latestReportDownloadUrl") or (f"/api/reports/{latest_report.id}/download" if latest_report else ""),
        "updatedAt": case.updated_at.isoformat(),
    }


def _case_list_dict(case: Case) -> dict:
    snapshot = getattr(case, "analysis_snapshot", None)
    snapshot_json = snapshot.snapshot_json if snapshot and isinstance(snapshot.snapshot_json, dict) else {}
    snapshot_case = snapshot_json.get("case", {}) if isinstance(snapshot_json.get("case"), dict) else {}
    snapshot_summary = snapshot_json.get("summary", {}) if isinstance(snapshot_json.get("summary"), dict) else {}
    latest_report = snapshot_case.get("latestReportId") or ""
    return {
        "id": case.id,
        "title": case.title,
        "investigator": case.investigator,
        "department": case.department,
        "status": case.status,
        "priority": case.priority,
        "origin": case.origin,
        "isTest": _is_probable_validator_case(case),
        "openedAt": case.opened_at.isoformat() if case.opened_at else case.created_at.isoformat(),
        "closedAt": case.closed_at.isoformat() if case.closed_at else "",
        "sourceLocation": case.source_location,
        "remarks": case.remarks,
        "flags": case.flags_json if isinstance(case.flags_json, list) else [],
        "linkedCases": [],
        "evidenceFileId": snapshot_case.get("evidenceFileId", ""),
        "evidenceFilename": snapshot_case.get("evidenceFilename", ""),
        "alertIds": snapshot_case.get("alertIds", []),
        "notes": [],
        "history": [],
        "createdAt": case.created_at.isoformat(),
        "reportStatus": case.report_status,
        "riskLevel": snapshot_summary.get("riskLevel") or snapshot_case.get("riskLevel") or "low",
        "topAttackClass": snapshot_summary.get("topAttackClass") or snapshot_case.get("topAttackClass") or "Normal Baseline",
        "alertCount": snapshot_summary.get("alerts", 0),
        "packetCount": snapshot_summary.get("packets", 0),
        "sessionCount": snapshot_summary.get("sessions", 0),
        "latestReportId": latest_report,
        "latestReportDownloadUrl": snapshot_case.get("latestReportDownloadUrl", ""),
        "updatedAt": case.updated_at.isoformat(),
    }


def health(_request):
    return JsonResponse(
        {
            "status": "ok",
            "service": "netra-backend",
            "allowedStack": settings.NETRA_ALLOWED_STACK,
            "packetTools": available_packet_tools(),
        }
    )


def _admin_count() -> int:
    User = get_user_model()
    admin_profile_ids = set(UserProfile.objects.filter(role="Admin").values_list("user_id", flat=True))
    superuser_ids = set(User.objects.filter(is_superuser=True).values_list("id", flat=True))
    return len(admin_profile_ids | superuser_ids)


def setup_status(_request):
    admin_count = _admin_count()
    return JsonResponse({"requiresSetup": admin_count == 0, "adminCount": admin_count})


@csrf_exempt
@require_http_methods(["POST"])
def setup_admin(request):
    if _admin_count() > 0:
        return JsonResponse({"error": "First-run setup is already complete."}, status=409)
    payload = _json_body(request)
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    name = (payload.get("name") or "Netra Admin").strip()
    if not email or "@" not in email:
        return JsonResponse({"error": "A valid admin email is required."}, status=400)
    if len(password) < 8:
        return JsonResponse({"error": "Password must be at least 8 characters."}, status=400)
    User = get_user_model()
    user = User.objects.create_user(username=email, email=email, password=password, first_name=name, is_staff=True, is_superuser=True)
    profile = UserProfile.objects.create(user=user, role="Admin", display_name=name)
    refresh = RefreshToken.for_user(user)
    return JsonResponse(
        {
            "status": "created",
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {"id": user.id, "email": user.username, "name": profile.display_name, "role": profile.role},
        },
        status=201,
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
        actor = sync_supabase_actor(supabase_user) if supabase_user else None
        return JsonResponse(
            {
                "access": session["access_token"],
                "refresh": session.get("refresh_token", ""),
                "expiresIn": session.get("expires_in"),
                "user": {
                    "id": supabase_user.id if supabase_user else "",
                    "email": supabase_user.email if supabase_user else email,
                    "name": actor.user if actor else (supabase_user.display_name if supabase_user else email),
                    "role": actor.role if actor else "Investigator",
                },
            }
        )
    user = authenticate(request, username=email, password=password)
    if not user:
        return JsonResponse({"error": "Invalid credentials"}, status=401)
    profile, _ = UserProfile.objects.get_or_create(user=user, defaults={"role": "Investigator", "display_name": user.get_full_name() or user.username})
    refresh = RefreshToken.for_user(user)
    return JsonResponse(
        {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {"id": user.id, "email": user.username, "name": profile.display_name or user.get_full_name() or user.username, "role": profile.role},
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
        return JsonResponse({"access": session["access_token"], "refresh": session.get("refresh_token", payload.get("refresh", "")), "expiresIn": session.get("expires_in")})
    try:
        refresh = RefreshToken(payload["refresh"])
        return JsonResponse({"access": str(refresh.access_token)})
    except Exception:
        return JsonResponse({"error": "Invalid refresh token"}, status=401)


@csrf_exempt
@require_http_methods(["POST"])
def auth_logout(request):
    return JsonResponse({"status": "logged-out"})


def auth_me(request):
    actor = actor_from_request(request)
    if not actor.authenticated:
        return JsonResponse({"error": "Authentication required"}, status=401)
    return JsonResponse({"user": actor.user, "role": actor.role, "authenticated": True})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def users(request):
    denied = require_permission(request, "manage_users", resource_type="User")
    if denied:
        return denied
    User = get_user_model()
    if request.method == "POST":
        payload = _json_body(request)
        email = payload.get("email")
        role = payload.get("role", "Viewer")
        if not email or role not in {"Admin", "Investigator", "Analyst", "Viewer"}:
            return JsonResponse({"error": "email and valid role are required"}, status=400)
        user, created = User.objects.get_or_create(username=email, defaults={"email": email, "first_name": payload.get("name", email)})
        if payload.get("password"):
            user.set_password(payload["password"])
            user.save()
        profile, _ = UserProfile.objects.update_or_create(user=user, defaults={"role": role, "display_name": payload.get("name", email)})
        return JsonResponse({"id": user.id, "email": user.username, "name": profile.display_name, "role": profile.role, "created": created}, status=201)
    rows = []
    for user in User.objects.order_by("username"):
        profile, _ = UserProfile.objects.get_or_create(user=user, defaults={"role": "Viewer", "display_name": user.get_full_name() or user.username})
        rows.append({"id": user.id, "email": user.username, "name": profile.display_name, "role": profile.role, "active": user.is_active})
    return JsonResponse({"results": rows})


@csrf_exempt
@require_http_methods(["PATCH"])
def user_detail(request, user_id: str):
    denied = require_permission(request, "manage_users", resource_type="User", resource_id=user_id)
    if denied:
        return denied
    payload = _json_body(request)
    User = get_user_model()
    user = User.objects.filter(id=user_id).first()
    if not user:
        raise Http404("User not found")
    profile, _ = UserProfile.objects.get_or_create(user=user)
    if payload.get("role") in {"Admin", "Investigator", "Analyst", "Viewer"}:
        profile.role = payload["role"]
    if "active" in payload:
        user.is_active = bool(payload["active"])
    profile.display_name = payload.get("name", profile.display_name)
    profile.save()
    user.save()
    return JsonResponse({"id": user.id, "email": user.username, "name": profile.display_name, "role": profile.role, "active": user.is_active})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def cases(request):
    actor = actor_from_request(request)
    if request.method == "POST":
        denied = require_permission(request, "upload", resource_type="Case")
        if denied:
            return denied
        payload = _json_body(request)
        case_id = payload.get("caseNumber") or f"CYB-GJ-{datetime.now().year}-{uuid4().hex[:4].upper()}"
        case, _ = Case.objects.update_or_create(
            id=case_id,
            defaults={
                "title": payload.get("title") or f"Investigation {case_id}",
                "investigator": payload.get("investigator") or actor.user,
                "department": payload.get("department") or "",
                "priority": payload.get("priority") or "Standard",
                "origin": payload.get("origin") if payload.get("origin") in {choice[0] for choice in Case.Origin.choices} else Case.Origin.OFFICER_UPLOAD,
                "is_test": bool(payload.get("isTest", False)),
                "opened_at": parse_datetime(payload.get("openedAt")) if payload.get("openedAt") else datetime.now(timezone.utc),
                "closed_at": parse_datetime(payload.get("closedAt")) if payload.get("closedAt") else None,
                "source_location": payload.get("sourceLocation", ""),
                "remarks": payload.get("remarks", ""),
                "flags_json": payload.get("flags", []),
            },
        )
        add_history(case, actor, "Case created", "Investigation case created from API.")
        bump_case_list_cache_version()
        publish_event("netra.case.events", {"type": "case.created", "caseId": case_id, "payload": payload})
        return JsonResponse(_case_dict(case), status=201)
    cache_key = f"netra:cases:list:{case_list_cache_version()}:{request.GET.urlencode() or 'default'}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return JsonResponse(cached)
    rows = _visible_cases_queryset(request).select_related("analysis_snapshot")[:250]
    payload = _paged([_case_list_dict(case) for case in rows], request)
    payload["testHidden"] = request.GET.get("includeTest") not in {"1", "true", "yes"}
    cache.set(cache_key, payload, timeout=45)
    return JsonResponse(payload)


@csrf_exempt
@require_http_methods(["GET", "PATCH"])
def case_detail(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if request.method == "PATCH":
        if not case:
            raise Http404("Case not found")
        denied = require_permission(request, "review", case=case, resource_type="Case", resource_id=case_id)
        if denied:
            return denied
        payload = _json_body(request)
        for field, attr in {
            "title": "title",
            "investigator": "investigator",
            "department": "department",
            "status": "status",
            "priority": "priority",
            "sourceLocation": "source_location",
            "remarks": "remarks",
        }.items():
            if field in payload:
                setattr(case, attr, payload[field] or "")
        if "flags" in payload and isinstance(payload["flags"], list):
            case.flags_json = payload["flags"]
        if "closedAt" in payload:
            case.closed_at = parse_datetime(payload["closedAt"]) if payload["closedAt"] else None
        case.save()
        add_history(case, actor_from_request(request), "Case metadata updated", "Case details, flags, or status were updated.")
        return JsonResponse(_case_dict(case))
    if case:
        return JsonResponse(_case_dict(case))
    analysis = _analysis(case_id=case_id)
    if analysis.get("case"):
        return JsonResponse(analysis["case"])
    raise Http404("Case not found")


@csrf_exempt
@require_http_methods(["POST"])
def case_notes(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    denied = require_permission(request, "review", case=case, resource_type="Case", resource_id=case_id)
    if denied:
        return denied
    payload = _json_body(request)
    if case:
        add_history(case, actor_from_request(request), "Investigator note added", payload.get("note", ""))
    publish_event("netra.case.events", {"type": "case.note_added", "caseId": case_id, "note": payload.get("note", "")})
    return JsonResponse({"caseId": case_id, "note": payload.get("note", ""), "status": "saved"}, status=201)


def case_history(_request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if case:
        return JsonResponse({"caseId": case_id, "results": _case_dict(case)["history"]})
    case_data = _analysis(case_id=case_id).get("case") or {}
    return JsonResponse({"caseId": case_id, "results": case_data.get("history", [])})


def case_light_summary(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    summary = dashboard_summary_payload(case_id)
    return JsonResponse({"case": _case_dict(case), "summary": summary})


def case_workspace(_request, case_id: str):
    cache_key = f"netra:case-workspace-response:{case_id}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return JsonResponse(cached)
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    payload = workspace_for_case(case)
    cache.set(cache_key, payload, timeout=60)
    return JsonResponse(payload)


def dashboard_summary_payload(case_id: str) -> dict:
    analysis = _analysis(case_id=case_id)
    return analysis["summary"] | {
        "topAttackClass": analysis.get("topAttackClass", analysis["summary"].get("topAttackClass", "Normal Baseline")),
        "riskLevel": analysis.get("riskLevel", analysis["summary"].get("riskLevel", "low")),
        "toolStatus": analysis.get("toolStatus", analysis["summary"].get("toolStatus", available_packet_tools())),
    }


def case_charts(_request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if case and getattr(case, "analysis_snapshot", None):
        charts = case.analysis_snapshot.snapshot_json.get("charts", {})
        return JsonResponse(
            {
                "caseId": case_id,
                "severity": charts.get("severity", []),
                "attackClasses": charts.get("attackClasses", []),
                "protocols": charts.get("protocols", []),
                "topSources": charts.get("topSources", []),
                "topDestinations": charts.get("topDestinations", []),
                "timeline": charts.get("timeline", []),
                "packetSessionSummary": charts.get("packetSessionSummary", {"packets": 0, "sessions": 0, "alerts": 0, "anomalies": 0}),
                "evidenceVerified": charts.get("evidenceVerified", False),
                "dataQuality": charts.get("dataQuality", "No data found in this evidence file."),
            }
        )
    analysis = _analysis(case_id=case_id)
    alerts = analysis.get("alerts", [])
    packets = analysis.get("packets", [])
    sessions = analysis.get("sessions", [])
    anomalies = analysis.get("anomalies", [])

    if not alerts:
        alerts = [
            {
                "severity": row.severity,
                "attackClass": row.attack_class,
                "timestamp": row.event_timestamp.isoformat() if row.event_timestamp else row.created_at.isoformat(),
            }
            for row in Alert.objects.filter(case_id=case_id).order_by("-created_at")[:500]
        ]
    if not sessions:
        sessions = [
            {
                "source": row.source,
                "destination": row.destination,
                "protocol": row.protocol,
                "packetCount": row.packet_count,
                "riskScore": row.risk_score,
            }
            for row in SessionSummary.objects.filter(case_id=case_id).order_by("-risk_score", "-packet_count")[:500]
        ]
    if not anomalies:
        anomalies = [{"id": row.id} for row in AnomalyRecord.objects.filter(case_id=case_id)[:500]]

    def counts(rows: list[dict], key: str, limit: int = 8):
        values: dict[str, int] = {}
        for row in rows:
            value = str(row.get(key) or "unknown")
            values[value] = values.get(value, 0) + 1
        return [{"name": name, "value": count} for name, count in sorted(values.items(), key=lambda item: item[1], reverse=True)[:limit]]

    return JsonResponse(
        {
            "caseId": case_id,
            "severity": counts(alerts, "severity"),
            "attackClasses": counts(alerts, "attackClass"),
            "protocols": analysis.get("protocolChartData") or counts(packets, "protocol") or counts(sessions, "protocol"),
            "topSources": counts(packets, "sourceIp") or counts(sessions, "source"),
            "topDestinations": counts(packets, "destinationIp") or counts(sessions, "destination"),
            "timeline": analysis.get("trafficTimeline", []) or _alert_timeline(alerts),
            "packetSessionSummary": {"packets": len(packets), "sessions": len(sessions), "alerts": len(alerts), "anomalies": len(anomalies)},
            "evidenceVerified": bool((analysis.get("evidence") or {}).get("manifestHash")),
        }
    )


def _alert_timeline(alerts: list[dict]) -> list[dict]:
    buckets: dict[str, dict] = {}
    for row in alerts:
        raw_time = str(row.get("timestamp") or "")
        label = raw_time[11:16] if "T" in raw_time else raw_time[:5] or "time"
        bucket = buckets.setdefault(label, {"time": label, "alerts": 0, "mb": 0, "packets": 0})
        bucket["alerts"] += 1
    return list(buckets.values())[:24]


def case_tab(request, case_id: str, tab_name: str):
    mapping = {
        "packets": lambda: packets(request),
        "sessions": lambda: sessions(request),
        "alerts": lambda: alerts(request),
        "protocols": lambda: decoder_summary(request),
        "payloads": lambda: payloads(request),
        "graph": lambda: graph(request),
        "timeline": lambda: JsonResponse({"results": _analysis(case_id=case_id).get("trafficTimeline", [])}),
    }
    if tab_name not in mapping:
        raise Http404("Unknown case tab")
    request.GET._mutable = True
    request.GET["caseId"] = case_id
    request.GET._mutable = False
    return mapping[tab_name]()


@csrf_exempt
@require_http_methods(["POST"])
def case_flags(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "review", case=case, resource_type="Case", resource_id=case_id)
    if denied:
        return denied
    payload = _json_body(request)
    incoming = payload.get("flags", [])
    if not isinstance(incoming, list):
        incoming = [payload.get("flag", "")]
    flags = list(dict.fromkeys([str(flag).strip() for flag in [*(case.flags_json or []), *incoming] if str(flag).strip()]))
    case.flags_json = flags
    case.save(update_fields=["flags_json", "updated_at"])
    add_history(case, actor_from_request(request), "Case flags updated", ", ".join(flags) or "Flags cleared.")
    return JsonResponse({"caseId": case.id, "flags": flags})


@csrf_exempt
@require_http_methods(["DELETE"])
def case_flag_detail(request, case_id: str, flag: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "review", case=case, resource_type="Case", resource_id=case_id)
    if denied:
        return denied
    case.flags_json = [item for item in (case.flags_json or []) if item != flag]
    case.save(update_fields=["flags_json", "updated_at"])
    add_history(case, actor_from_request(request), "Case flag removed", flag)
    return JsonResponse({"caseId": case.id, "flags": case.flags_json})


@csrf_exempt
@require_http_methods(["POST"])
def case_links(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "review", case=case, resource_type="Case", resource_id=case_id)
    if denied:
        return denied
    payload = _json_body(request)
    target = Case.objects.filter(id=payload.get("targetCaseId")).first()
    if not target:
        return JsonResponse({"error": "Related case not found."}, status=404)
    if target.id == case.id:
        return JsonResponse({"error": "A case cannot be linked to itself."}, status=400)
    relation_type = payload.get("relationType") or "manual_link"
    link, _ = CaseLink.objects.update_or_create(
        source_case=case,
        target_case=target,
        relation_type=relation_type,
        defaults={"notes": payload.get("notes", ""), "created_by": actor_from_request(request).user},
    )
    add_history(case, actor_from_request(request), "Related case linked", f"{target.id} ({relation_type})")
    return JsonResponse({"id": link.id, "caseId": target.id, "caseTitle": target.title, "relationType": link.relation_type, "notes": link.notes}, status=201)


@csrf_exempt
@require_http_methods(["DELETE"])
def case_link_detail(request, case_id: str, link_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "review", case=case, resource_type="Case", resource_id=case_id)
    if denied:
        return denied
    CaseLink.objects.filter(id=link_id, source_case=case).delete()
    add_history(case, actor_from_request(request), "Related case unlinked", str(link_id))
    return JsonResponse({"caseId": case.id, "removed": link_id})


def custody_ledger(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "compliance", case=case, resource_type="CustodyLedger", resource_id=case_id)
    if denied:
        return denied
    rows = [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("-created_at", "-id")]
    payload = _paged(rows, request)
    payload["caseId"] = case_id
    payload["verification"] = verify_case_ledger(case)
    return JsonResponse(payload)


@csrf_exempt
@require_http_methods(["POST"])
def custody_verify(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "compliance", case=case, resource_type="CustodyLedger", resource_id=case_id)
    if denied:
        return denied
    result = verify_case_ledger(case)
    record_custody_event(case, actor_from_request(request), "Custody ledger verified", result, resource_type="Case", resource_id=case_id)
    return JsonResponse(result)


def custody_export(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "compliance", case=case, resource_type="CustodyLedger", resource_id=case_id)
    if denied:
        return denied
    payload = {"caseId": case_id, "verification": verify_case_ledger(case), "events": [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("created_at", "id")]}
    return JsonResponse(payload)


def case_linked_evidence(_request, case_id: str):
    analysis = _analysis(case_id=case_id)
    exports = [{"id": row.id, "type": row.export_type, "caseId": case_id, "requestedBy": row.requested_by, "timestamp": row.created_at.isoformat(), "hash": row.sha256, "status": row.status} for row in Export.objects.filter(case_id=case_id).order_by("-created_at")]
    return JsonResponse({"caseId": case_id, "packets": analysis.get("packets", [])[:20], "sessions": analysis.get("sessions", []), "payloads": analysis.get("payloadFindings", []), "exports": exports})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def case_members(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    if request.method == "POST":
        denied = require_permission(request, "manage_users", case=case, resource_type="CaseMembership", resource_id=case_id)
        if denied:
            return denied
        payload = _json_body(request)
        User = get_user_model()
        user = User.objects.filter(username=payload.get("email")).first()
        if not user:
            return JsonResponse({"error": "User not found"}, status=404)
        role = payload.get("role", "Viewer")
        membership, _ = CaseMembership.objects.update_or_create(case=case, user=user, defaults={"role": role, "added_by": actor_from_request(request).user})
        return JsonResponse({"id": membership.id, "caseId": case.id, "email": user.username, "role": membership.role}, status=201)
    rows = []
    for membership in CaseMembership.objects.filter(case=case).select_related("user"):
        rows.append({"id": membership.id, "caseId": case.id, "email": membership.user.username, "role": membership.role})
    return JsonResponse({"results": rows})


@csrf_exempt
@require_http_methods(["PATCH"])
def case_member_detail(request, case_id: str, member_id: str):
    case = Case.objects.filter(id=case_id).first()
    denied = require_permission(request, "manage_users", case=case, resource_type="CaseMembership", resource_id=member_id)
    if denied:
        return denied
    membership = CaseMembership.objects.filter(case_id=case_id, id=member_id).select_related("user").first()
    if not membership:
        raise Http404("Membership not found")
    payload = _json_body(request)
    if payload.get("role") in {"Admin", "Investigator", "Analyst", "Viewer"}:
        membership.role = payload["role"]
        membership.save(update_fields=["role", "updated_at"])
    return JsonResponse({"id": membership.id, "caseId": case_id, "email": membership.user.username, "role": membership.role})


@csrf_exempt
@require_http_methods(["POST"])
def link_stub(request, case_id: str):
    payload = _json_body(request)
    publish_event("netra.case.events", {"type": "case.linked_evidence", "caseId": case_id, "payload": payload})
    return JsonResponse({"caseId": case_id, "linked": payload}, status=201)


def _storage_configuration_response() -> JsonResponse:
    return JsonResponse(
        {
            "error": "Evidence storage is not configured.",
            "detail": "Ask the operator to update the Supabase service-role key and bootstrap the private evidence buckets from Technical Status.",
        },
        status=503,
    )


def _storage_failure_response() -> JsonResponse:
    return JsonResponse(
        {
            "error": "Evidence storage failed.",
            "detail": "Ask the operator to check Supabase Storage on the Technical Status page before trying again.",
        },
        status=503,
    )


def _normalization_error_response(normalization: dict) -> JsonResponse:
    code = normalization.get("code", "")
    detected = normalization.get("detectedType", "Unknown")
    selected = normalization.get("selectedType", "Auto-detect")
    if code == "unsupported_evidence_extension":
        return JsonResponse(
            {
                "error": "Unsupported evidence file type.",
                **normalization,
            },
            status=400,
        )
    if code == "invalid_pcap" or (detected == "Unknown" and normalization.get("features", {}).get("magicType") == "invalid-pcap"):
        return JsonResponse(
            {
                "error": "File does not look like a valid PCAP/PCAPNG capture.",
                "code": "invalid_pcap",
                **normalization,
            },
            status=422,
        )
    if code == "evidence_type_mismatch" or (detected != "Unknown" and selected != "Auto-detect" and selected != detected):
        return JsonResponse(
            {
                "error": "Invalid evidence type for selected file.",
                "code": "evidence_type_mismatch",
                **normalization,
            },
            status=422,
        )
    return JsonResponse(
        {
            "error": "Unsupported or unrecognized evidence file.",
            "code": "evidence_type_unrecognized",
            **normalization,
        },
        status=422,
    )


@csrf_exempt
@require_http_methods(["POST"])
def evidence_normalize_preview(request):
    denied = require_permission(request, "upload", resource_type="EvidenceFile")
    if denied:
        return denied
    upload = request.FILES.get("file")
    if not upload:
        return JsonResponse({"error": "file is required"}, status=400)
    normalization = normalize_evidence_upload(upload, request.POST.get("evidenceType")).to_dict()
    return JsonResponse(normalization)


@csrf_exempt
@require_http_methods(["POST"])
def evidence_upload(request):
    denied = require_permission(request, "upload", resource_type="EvidenceFile")
    if denied:
        return denied
    actor = actor_from_request(request)
    upload = request.FILES.get("file")
    case_id = request.POST.get("caseId") or f"CYB-GJ-{datetime.now().year}-{uuid4().hex[:4].upper()}"
    if not upload:
        return JsonResponse({"error": "file is required"}, status=400)
    normalization_result = normalize_evidence_upload(upload, request.POST.get("evidenceType"))
    normalization = normalization_result.to_dict()
    if not normalization_result.valid:
        return _normalization_error_response(normalization)
    if normalization_result.normalized_type != EvidenceFile.EvidenceType.PCAP:
        return JsonResponse(
            {
                "error": f"{normalization_result.normalized_type} normalization is available, but analysis for this evidence type is not enabled in the officer upload flow yet.",
                "code": "evidence_type_not_analyzable",
                **normalization,
            },
            status=422,
        )
    try:
        saved = save_uploaded_file(upload, "pcap")
    except OverflowError as exc:
        return JsonResponse({"error": str(exc)}, status=413)
    except ValueError as exc:
        message = str(exc)
        status = 422 if "valid PCAP" in message else 400
        return JsonResponse({"error": message}, status=status)
    except RuntimeError as exc:
        if "Evidence storage is not configured" in str(exc) or "Supabase Storage" in str(exc):
            return _storage_configuration_response()
        return _storage_failure_response()
    try:
        intake_flags = json.loads(request.POST.get("flags") or "[]")
        if not isinstance(intake_flags, list):
            intake_flags = []
    except json.JSONDecodeError:
        intake_flags = []
    saved["intake"] = {
        "investigator": (request.POST.get("investigator") or actor.user).strip(),
        "department": (request.POST.get("department") or "").strip(),
        "selectedEvidenceType": normalization_result.selected_type,
        "evidenceType": normalization_result.normalized_type,
        "sourceLocation": (request.POST.get("sourceLocation") or "").strip(),
        "priority": (request.POST.get("priority") or "Standard").strip(),
        "remarks": (request.POST.get("remarks") or "").strip(),
        "flags": [str(flag).strip() for flag in intake_flags if str(flag).strip()],
        "origin": Case.Origin.OFFICER_UPLOAD,
        "sourceIp": (request.POST.get("sourceIp") or "").strip(),
        "destinationIp": (request.POST.get("destinationIp") or "").strip(),
        "protocol": (request.POST.get("protocol") or "").strip().upper(),
        "port": (request.POST.get("port") or "").strip(),
        "durationSeconds": (request.POST.get("durationSeconds") or "").strip(),
        "packetLimit": (request.POST.get("packetLimit") or "").strip(),
        "bpfFilter": (request.POST.get("bpfFilter") or "").strip(),
    }
    saved["normalization"] = normalization
    evidence_id = f"ev-{uuid4().hex[:8]}"
    job_id = f"job-{uuid4().hex[:8]}"
    public_saved = {key: value for key, value in saved.items() if key != "analysis_path"}
    if settings.NETRA_PROCESSING_MODE == "async-primary":
        job = queue_uploaded_evidence(saved, case_id, evidence_id, job_id, actor)
        event = {"type": "pcap.uploaded", "caseId": case_id, "evidenceId": evidence_id, "jobId": job_id, "processingMode": settings.NETRA_PROCESSING_MODE, "saved": public_saved, "intake": saved["intake"]}
        if publish_event("netra.pcap.uploaded", event, key=job_id):
            Path(saved["analysis_path"]).unlink(missing_ok=True)
            return JsonResponse({"id": evidence_id, "caseId": case_id, "jobId": job_id, "status": "queued", "processingPath": "async-workers", "job": job_status_payload(job), **public_saved}, status=202)
    try:
        analysis = analyze_pcap(saved["analysis_path"], case_id, evidence_id, job_id, saved)
        analysis["processingPath"] = "sync-fallback"
        if settings.NETRA_PROCESSING_MODE == "async-primary":
            analysis["fallbackReason"] = "kafka-publish-failed"
        job = persist_analysis(analysis, saved, actor)
    except Exception as exc:
        return JsonResponse({"error": f"PCAP analysis failed: {exc}", "id": evidence_id, "caseId": case_id, "jobId": job_id, **saved}, status=422)
    finally:
        if saved.get("analysis_path"):
            Path(saved["analysis_path"]).unlink(missing_ok=True)
    event = {"type": "pcap.uploaded", "caseId": case_id, "evidenceId": evidence_id, "jobId": job_id, "summary": analysis["summary"], "processingMode": settings.NETRA_PROCESSING_MODE, **public_saved}
    publish_event("netra.pcap.uploaded", event)
    return JsonResponse(
        {
            "id": evidence_id,
            "caseId": case_id,
            "jobId": job_id,
            "status": "verified",
            "analysis": analysis["summary"],
            "job": job_status_payload(job),
            "detectedAttackClasses": analysis.get("detectedAttackClasses", []),
            "topAlerts": analysis.get("alerts", [])[:3],
            "riskLevel": analysis.get("riskLevel", "low"),
            "toolStatus": analysis.get("toolStatus", available_packet_tools()),
            **public_saved,
        },
        status=201,
    )


def evidence_manifest(_request, evidence_id: str):
    manifest = EvidenceManifest.objects.filter(evidence_file_id=evidence_id).first()
    if not manifest:
        raise Http404("Evidence manifest not found")
    return JsonResponse({"manifest": manifest.manifest_json, "manifestHash": manifest.manifest_hash})


@csrf_exempt
@require_http_methods(["POST"])
def evidence_verify_integrity(request, evidence_id: str):
    evidence = EvidenceFile.objects.filter(id=evidence_id).select_related("case").first()
    if not evidence:
        raise Http404("Evidence not found")
    denied = require_permission(request, "view", case=evidence.case, resource_type="EvidenceFile", resource_id=evidence_id)
    if denied:
        return denied
    manifest = getattr(evidence, "manifest", None)
    if not manifest:
        return JsonResponse({"verified": False, "error": "manifest missing"}, status=404)
    stat = storage_provider.stat(evidence.stored_path)
    encrypted_hash = stat.sha256
    encrypted_verified = bool(encrypted_hash and encrypted_hash == manifest.encrypted_sha256)
    canonical_manifest = {key: value for key, value in manifest.manifest_json.items() if key != "manifestHash"}
    calculated_manifest_hash = sha256_text(json.dumps(canonical_manifest, sort_keys=True))
    manifest_verified = calculated_manifest_hash == manifest.manifest_hash == manifest.manifest_json.get("manifestHash")
    verified = encrypted_verified and manifest_verified
    checked_at = datetime.now(timezone.utc).isoformat()
    details = {"verified": verified, "encryptedArtifactVerified": encrypted_verified, "manifestVerified": manifest_verified, "manifestHash": manifest.manifest_hash, "checkedAt": checked_at}
    record_custody_event(evidence.case, actor_from_request(request), "Integrity verified", details, evidence, "EvidenceFile", evidence.id)
    return JsonResponse(details | {"plaintextIdentityHash": manifest.plaintext_sha256, "encryptedStorageHash": encrypted_hash})


def evidence_download(request, evidence_id: str):
    evidence = EvidenceFile.objects.filter(id=evidence_id).select_related("case").first()
    if not evidence:
        raise Http404("Evidence not found")
    denied = require_permission(request, "export", case=evidence.case, resource_type="EvidenceFile", resource_id=evidence_id)
    if denied:
        return denied
    record_custody_event(evidence.case, actor_from_request(request), "Evidence downloaded", {"filename": evidence.filename, "sha256": evidence.sha256}, evidence, "EvidenceFile", evidence.id)
    return HttpResponse(read_encrypted_or_plain(evidence.stored_path), headers={"Content-Disposition": f'attachment; filename="{evidence.filename}"'}, content_type="application/vnd.tcpdump.pcap")


@csrf_exempt
@require_http_methods(["POST"])
def capture_live_start(request):
    denied = require_permission(request, "upload", resource_type="CaptureJob")
    if denied:
        return denied
    payload = _json_body(request)
    sensor = Sensor.objects.filter(id=payload.get("sensorId")).first()
    allowed, capacity = backpressure_allows_new_capture()
    if not allowed:
        return JsonResponse({"error": "New capture rejected while fleet capacity is critical.", "capacity": capacity}, status=503)
    if not sensor or not sensor.enabled or heartbeat_state(sensor.last_heartbeat_at) != "healthy":
        return JsonResponse({"error": "A healthy registered sensor is required for native capture."}, status=409)
    try:
        duration = int(payload.get("durationSeconds", 0))
        packet_limit = int(payload.get("packetLimit", 0))
        chunk_interval = int(payload.get("chunkIntervalSeconds", 5))
        validate_capture_bounds(duration, packet_limit, chunk_interval, payload.get("bpfFilter", ""))
    except (TypeError, ValueError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    case = ensure_capture_case(payload.get("caseId") or f"CYB-GJ-LIVE-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    job = create_capture_job(case=case, mode=CaptureJob.Mode.LIVE_CAPTURE, sensor=sensor, interface_name=payload.get("interfaceName", ""), duration_seconds=duration, packet_limit=packet_limit, chunk_interval_seconds=chunk_interval, bpf_filter=payload.get("bpfFilter", ""), source_label=sensor.name)
    SensorCommand.objects.create(sensor=sensor, capture_job=job, command_type="capture.start", payload_json=capture_job_payload(job))
    return JsonResponse(capture_job_payload(job), status=201)


def capture_interfaces(request):
    sensor = Sensor.objects.filter(id=request.GET.get("sensorId")).first()
    if not sensor:
        return JsonResponse({"enabled": False, "results": [], "message": "Select a healthy registered sensor."})
    return JsonResponse({"enabled": heartbeat_state(sensor.last_heartbeat_at) == "healthy", "sensorId": sensor.id, "results": sensor.interfaces_json})


@csrf_exempt
@require_http_methods(["POST"])
def capture_live_stop(request, job_id: str | None = None):
    payload = _json_body(request)
    job = CaptureJob.objects.filter(id=job_id or payload.get("jobId")).first()
    if not job:
        raise Http404("Capture job not found")
    return JsonResponse(stop_capture(job))


def capture_live_status(_request, job_id: str):
    job = CaptureJob.objects.filter(id=job_id).first()
    if not job:
        raise Http404("Capture job not found")
    return JsonResponse(capture_job_payload(job))


@csrf_exempt
@require_http_methods(["POST"])
def capture_log_import(request):
    denied = require_permission(request, "upload", resource_type="LogImport")
    if denied:
        return denied
    payload = _json_body(request)
    job_id = f"log-{uuid4().hex[:8]}"
    publish_event("netra.pcap.processing", {"type": "log.imported", "jobId": job_id, "payload": payload})
    return JsonResponse({"jobId": job_id, "status": "queued", "mode": "log_import"}, status=201)


@csrf_exempt
@require_http_methods(["POST"])
def capture_replay_start(request):
    denied = require_permission(request, "upload", resource_type="CaptureReplay")
    if denied:
        return denied
    upload = request.FILES.get("file")
    if not upload:
        return JsonResponse({"error": "A PCAP or PCAPNG file is required for replay."}, status=400)
    allowed, capacity = backpressure_allows_new_capture()
    if not allowed:
        return JsonResponse({"error": "Replay rejected while fleet capacity is critical.", "capacity": capacity}, status=503)
    try:
        packet_limit = int(request.POST.get("packetLimit", "10000"))
        chunk_interval = int(request.POST.get("chunkIntervalSeconds", "5"))
        duration = int(request.POST.get("durationSeconds", "900"))
        validate_capture_bounds(duration, packet_limit, chunk_interval)
        saved = save_uploaded_file(upload, "capture_chunk")
        Path(saved["analysis_path"]).unlink(missing_ok=True)
    except (OverflowError, TypeError, ValueError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except RuntimeError as exc:
        if "Evidence storage is not configured" in str(exc) or "Supabase Storage" in str(exc):
            return _storage_configuration_response()
        return _storage_failure_response()
    case_id = request.POST.get("caseId") or f"CYB-GJ-REPLAY-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    case = ensure_capture_case(case_id)
    job = create_capture_job(case=case, mode=CaptureJob.Mode.REPLAY, duration_seconds=duration, packet_limit=packet_limit, chunk_interval_seconds=chunk_interval, source_label=f"Replay: {upload.name}")
    start_replay(job, saved["stored_path"], request.POST.get("speed", "max"))
    return JsonResponse(capture_job_payload(job), status=201)


@csrf_exempt
@require_http_methods(["POST"])
def capture_replay_stop(request, job_id: str | None = None):
    payload = _json_body(request)
    job = CaptureJob.objects.filter(id=job_id or payload.get("jobId")).first()
    if not job:
        raise Http404("Replay job not found")
    return JsonResponse(stop_capture(job))


def capture_replay_status(_request, job_id: str):
    job = CaptureJob.objects.filter(id=job_id).first()
    if not job:
        raise Http404("Replay job not found")
    if expire_stale_replay(job):
        job.refresh_from_db()
    return JsonResponse(capture_job_payload(job))


@csrf_exempt
@require_http_methods(["GET", "POST"])
def sensors(request):
    if request.method == "POST":
        return sensor_register(request)
    rows = Sensor.objects.select_related("group").order_by("name")
    if request.GET.get("groupId"):
        rows = rows.filter(group_id=request.GET["groupId"])
    if request.GET.get("location"):
        rows = rows.filter(location__icontains=request.GET["location"])
    results = [sensor_payload(row) for row in rows]
    if request.GET.get("status"):
        results = [row for row in results if row["status"] == request.GET["status"]]
    if request.GET.get("q"):
        query = request.GET["q"].lower()
        results = [row for row in results if query in json.dumps(row).lower()]
    return JsonResponse({"results": results})


@csrf_exempt
@require_http_methods(["POST"])
def sensor_register(request):
    if not sensor_key_valid(request):
        return JsonResponse({"error": "Invalid sensor key."}, status=403)
    payload = _json_body(request)
    sensor_id = payload.get("id") or f"sensor-{uuid4().hex[:10]}"
    sensor, _ = Sensor.objects.update_or_create(
        id=sensor_id,
        defaults={
            "name": payload.get("name", sensor_id),
            "hostname": payload.get("hostname", "unknown"),
            "platform": payload.get("platform", "unknown"),
            "agent_version": payload.get("agentVersion", "phase5-v1"),
            "capture_engine": payload.get("captureEngine", "dumpcap"),
            "capture_engine_version": payload.get("captureEngineVersion", ""),
            "status": Sensor.Status.ONLINE,
            "last_heartbeat_at": datetime.now(timezone.utc),
            "interfaces_json": payload.get("interfaces", []),
            "metadata_json": payload.get("metadata", {}),
        },
    )
    emit_operational_event("sensor.connected", sensor_payload(sensor))
    return JsonResponse(sensor_payload(sensor), status=201)


@csrf_exempt
@require_http_methods(["GET", "PATCH"])
def sensor_detail(request, sensor_id: str):
    sensor = Sensor.objects.select_related("group").filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
    if request.method == "PATCH":
        payload = _json_body(request)
        if "groupId" in payload:
            sensor.group = SensorGroup.objects.filter(id=payload["groupId"]).first() if payload["groupId"] else None
        sensor.location = payload.get("location", sensor.location)
        sensor.tags_json = payload.get("tags", sensor.tags_json)
        sensor.notes = payload.get("notes", sensor.notes)
        sensor.enabled = payload.get("enabled", sensor.enabled)
        sensor.save(update_fields=["group", "location", "tags_json", "notes", "enabled", "updated_at"])
    return JsonResponse(sensor_payload(sensor))


@csrf_exempt
@require_http_methods(["POST"])
def sensor_heartbeat(request, sensor_id: str):
    if not sensor_key_valid(request):
        return JsonResponse({"error": "Invalid sensor key."}, status=403)
    sensor = Sensor.objects.filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
    payload = _json_body(request)
    sensor.last_heartbeat_at = datetime.now(timezone.utc)
    sensor.status = Sensor.Status.ONLINE if sensor.enabled else Sensor.Status.DISABLED
    sensor.interfaces_json = payload.get("interfaces", sensor.interfaces_json)
    sensor.metadata_json = sensor.metadata_json | payload.get("metadata", {})
    sensor.save(update_fields=["last_heartbeat_at", "status", "interfaces_json", "metadata_json", "updated_at"])
    SensorHealthSnapshot.objects.create(
        sensor=sensor,
        status=sensor.status,
        heartbeat_age_seconds=0,
        capture_engine=sensor.capture_engine,
        interface_count=len(sensor.interfaces_json),
        current_job_id=sensor.current_capture_job_id or "",
        metadata_json=sensor.metadata_json,
    )
    emit_operational_event("sensor.heartbeat", sensor_payload(sensor))
    return JsonResponse(sensor_payload(sensor))


def sensor_next_command(request, sensor_id: str):
    if not sensor_key_valid(request):
        return JsonResponse({"error": "Invalid sensor key."}, status=403)
    sensor = Sensor.objects.filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
    command = SensorCommand.objects.filter(sensor=sensor, status=SensorCommand.Status.QUEUED).select_related("capture_job").order_by("issued_at").first()
    job = command.capture_job if command else CaptureJob.objects.filter(sensor=sensor, mode=CaptureJob.Mode.LIVE_CAPTURE, status=CaptureJob.Status.QUEUED).order_by("created_at").first()
    if job and sensor.enabled:
        mark_capture_running(job)
        sensor.last_command_at = datetime.now(timezone.utc)
        sensor.save(update_fields=["last_command_at", "updated_at"])
        if command:
            command.status = SensorCommand.Status.CLAIMED
            command.claimed_at = datetime.now(timezone.utc)
            command.save(update_fields=["status", "claimed_at", "updated_at"])
    return JsonResponse({"command": capture_job_payload(job) if job else None})


@csrf_exempt
@require_http_methods(["POST"])
def sensor_chunk_upload(request, sensor_id: str):
    if not sensor_key_valid(request):
        return JsonResponse({"error": "Invalid sensor key."}, status=403)
    sensor = Sensor.objects.filter(id=sensor_id).first()
    job = CaptureJob.objects.filter(id=request.POST.get("jobId"), sensor=sensor).first()
    upload = request.FILES.get("file")
    if not sensor or not job or not upload:
        return JsonResponse({"error": "sensor, jobId, and PCAP chunk file are required."}, status=400)
    try:
        sequence = int(request.POST.get("sequence", "0"))
        chunk = ingest_capture_chunk(job, upload, sequence, sensor=sensor)
    except (OverflowError, TypeError, ValueError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except RuntimeError as exc:
        if "Evidence storage is not configured" in str(exc) or "Supabase Storage" in str(exc):
            return _storage_configuration_response()
        return _storage_failure_response()
    return JsonResponse({"chunkId": chunk.id, **capture_job_payload(job)}, status=201)


@csrf_exempt
@require_http_methods(["POST"])
def sensor_capture_complete(request, sensor_id: str, job_id: str):
    if not sensor_key_valid(request):
        return JsonResponse({"error": "Invalid sensor key."}, status=403)
    job = CaptureJob.objects.filter(id=job_id, sensor_id=sensor_id).first()
    if not job:
        raise Http404("Capture job not found")
    try:
        response = finalize_capture(job)
        SensorCommand.objects.filter(sensor_id=sensor_id, capture_job_id=job_id).update(status=SensorCommand.Status.COMPLETED, completed_at=datetime.now(timezone.utc))
        return JsonResponse(response)
    except ValueError as exc:
        SensorCommand.objects.filter(sensor_id=sensor_id, capture_job_id=job_id).update(status=SensorCommand.Status.FAILED, completed_at=datetime.now(timezone.utc), error_message=str(exc))
        return JsonResponse({"error": str(exc)}, status=422)
    except RuntimeError as exc:
        SensorCommand.objects.filter(sensor_id=sensor_id, capture_job_id=job_id).update(status=SensorCommand.Status.FAILED, completed_at=datetime.now(timezone.utc), error_message=str(exc))
        if "Evidence storage is not configured" in str(exc) or "Supabase Storage" in str(exc):
            return _storage_configuration_response()
        return _storage_failure_response()
    except Exception as exc:
        SensorCommand.objects.filter(sensor_id=sensor_id, capture_job_id=job_id).update(status=SensorCommand.Status.FAILED, completed_at=datetime.now(timezone.utc), error_message=str(exc))
        return JsonResponse({"error": "Capture finalization failed.", "detail": str(exc)}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def sensor_capture_fail(request, sensor_id: str, job_id: str):
    if not sensor_key_valid(request):
        return JsonResponse({"error": "Invalid sensor key."}, status=403)
    job = CaptureJob.objects.filter(id=job_id, sensor_id=sensor_id).first()
    if not job:
        raise Http404("Capture job not found")
    payload = _json_body(request)
    job.status = CaptureJob.Status.FAILED
    job.error_message = payload.get("error", "Sensor capture failed.")
    job.completed_at = datetime.now(timezone.utc)
    job.save(update_fields=["status", "error_message", "completed_at", "updated_at"])
    SensorCommand.objects.filter(sensor_id=sensor_id, capture_job_id=job_id).update(status=SensorCommand.Status.FAILED, completed_at=datetime.now(timezone.utc), error_message=job.error_message)
    emit_operational_event("capture.failed", capture_job_payload(job), capture_job=job)
    return JsonResponse(capture_job_payload(job))


@csrf_exempt
@require_http_methods(["POST"])
def sensor_enable(_request, sensor_id: str):
    sensor = Sensor.objects.filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
    sensor.enabled = True
    sensor.status = Sensor.Status.ONLINE if heartbeat_state(sensor.last_heartbeat_at) == "healthy" else Sensor.Status.OFFLINE
    sensor.save(update_fields=["enabled", "status", "updated_at"])
    return JsonResponse(sensor_payload(sensor))


@csrf_exempt
@require_http_methods(["POST"])
def sensor_disable(_request, sensor_id: str):
    sensor = Sensor.objects.filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
    if CaptureJob.objects.filter(sensor=sensor, status=CaptureJob.Status.RUNNING).exists():
        return JsonResponse({"error": "Stop the active capture before disabling this sensor."}, status=409)
    sensor.enabled = False
    sensor.status = Sensor.Status.DISABLED
    sensor.save(update_fields=["enabled", "status", "updated_at"])
    return JsonResponse(sensor_payload(sensor))


def sensor_history(_request, sensor_id: str):
    sensor = Sensor.objects.filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
    rows = sensor.commands.order_by("-issued_at")[:100]
    return JsonResponse({"results": [{"id": row.id, "type": row.command_type, "status": row.status, "jobId": row.capture_job_id or "", "issuedAt": row.issued_at.isoformat(), "completedAt": row.completed_at.isoformat() if row.completed_at else None, "error": row.error_message} for row in rows]})


def sensor_captures(_request, sensor_id: str):
    rows = CaptureJob.objects.filter(sensor_id=sensor_id).order_by("-created_at")[:100]
    return JsonResponse({"results": [capture_job_payload(row) for row in rows]})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def sensor_groups(request):
    if request.method == "POST":
        payload = _json_body(request)
        name = (payload.get("name") or "").strip()
        if not name:
            return JsonResponse({"error": "Group name is required."}, status=400)
        group = SensorGroup.objects.create(name=name, description=payload.get("description", ""), color=payload.get("color", "#2563eb"))
        return JsonResponse(sensor_group_payload(group), status=201)
    return JsonResponse({"results": [sensor_group_payload(row) for row in SensorGroup.objects.order_by("name")]})


@csrf_exempt
@require_http_methods(["PATCH", "DELETE"])
def sensor_group_detail(request, group_id: str):
    group = SensorGroup.objects.filter(id=group_id).first()
    if not group:
        raise Http404("Sensor group not found")
    if request.method == "DELETE":
        group.delete()
        return JsonResponse({"status": "deleted"})
    payload = _json_body(request)
    group.name = payload.get("name", group.name)
    group.description = payload.get("description", group.description)
    group.color = payload.get("color", group.color)
    group.save(update_fields=["name", "description", "color", "updated_at"])
    return JsonResponse(sensor_group_payload(group))


def _schedule_values(payload: dict, schedule: CaptureSchedule | None = None) -> dict:
    sensor = Sensor.objects.filter(id=payload.get("sensorId") or (schedule.sensor_id if schedule else "")).first()
    if not sensor:
        raise ValueError("A registered sensor is required.")
    duration = int(payload.get("durationSeconds", schedule.duration_seconds if schedule else 60))
    packet_limit = int(payload.get("packetLimit", schedule.packet_limit if schedule else 10000))
    chunk_interval = int(payload.get("chunkIntervalSeconds", schedule.chunk_interval_seconds if schedule else 5))
    bpf_filter = payload.get("bpfFilter", schedule.bpf_filter if schedule else "")
    validate_capture_bounds(duration, packet_limit, chunk_interval, bpf_filter)
    start_at = parse_datetime(payload.get("startAt", "")) or (schedule.start_at if schedule else None)
    if not start_at:
        raise ValueError("startAt must be an ISO timestamp.")
    schedule_type = payload.get("scheduleType", schedule.schedule_type if schedule else "one-time")
    if schedule_type not in CaptureSchedule.ScheduleType.values:
        raise ValueError("scheduleType must be one-time, daily, or weekly.")
    return {
        "name": payload.get("name", schedule.name if schedule else "Bounded capture schedule"),
        "sensor": sensor,
        "enabled": payload.get("enabled", schedule.enabled if schedule else True),
        "schedule_type": schedule_type,
        "start_at": start_at,
        "timezone": payload.get("timezone", schedule.timezone if schedule else "Asia/Kolkata"),
        "weekdays_json": payload.get("weekdays", schedule.weekdays_json if schedule else []),
        "duration_seconds": duration,
        "packet_limit": packet_limit,
        "chunk_interval_seconds": chunk_interval,
        "interface_name": payload.get("interfaceName", schedule.interface_name if schedule else ""),
        "bpf_filter": bpf_filter,
        "case_id_prefix": payload.get("caseIdPrefix", schedule.case_id_prefix if schedule else "CYB-GJ-SCHEDULED"),
    }


@csrf_exempt
@require_http_methods(["GET", "POST"])
def capture_schedules(request):
    if request.method == "POST":
        try:
            schedule = CaptureSchedule.objects.create(**_schedule_values(_json_body(request)))
            from common.fleet import calculate_next_run
            schedule.next_run_at = calculate_next_run(schedule)
            schedule.save(update_fields=["next_run_at", "updated_at"])
            return JsonResponse(schedule_payload(schedule), status=201)
        except (TypeError, ValueError) as exc:
            return JsonResponse({"error": str(exc)}, status=400)
    rows = CaptureSchedule.objects.select_related("sensor").order_by("name")
    if request.GET.get("sensorId"):
        rows = rows.filter(sensor_id=request.GET["sensorId"])
    if request.GET.get("enabled") in {"true", "false"}:
        rows = rows.filter(enabled=request.GET["enabled"] == "true")
    return JsonResponse({"results": [schedule_payload(row) for row in rows]})


@csrf_exempt
@require_http_methods(["GET", "PATCH", "DELETE"])
def capture_schedule_detail(request, schedule_id: str):
    schedule = CaptureSchedule.objects.select_related("sensor").filter(id=schedule_id).first()
    if not schedule:
        raise Http404("Capture schedule not found")
    if request.method == "DELETE":
        schedule.delete()
        return JsonResponse({"status": "deleted"})
    if request.method == "PATCH":
        try:
            for key, value in _schedule_values(_json_body(request), schedule).items():
                setattr(schedule, key, value)
            from common.fleet import calculate_next_run
            schedule.next_run_at = calculate_next_run(schedule)
            schedule.save()
        except (TypeError, ValueError) as exc:
            return JsonResponse({"error": str(exc)}, status=400)
    return JsonResponse(schedule_payload(schedule))


@csrf_exempt
@require_http_methods(["POST"])
def capture_schedule_run_now(_request, schedule_id: str):
    schedule = CaptureSchedule.objects.filter(id=schedule_id).first()
    if not schedule:
        raise Http404("Capture schedule not found")
    job = queue_schedule_run(schedule)
    return JsonResponse({"status": "queued" if job else "skipped", "job": capture_job_payload(job) if job else None}, status=201 if job else 409)


def capture_schedule_history(_request, schedule_id: str):
    rows = CaptureJob.objects.filter(schedule_runs__id=schedule_id).order_by("-created_at")[:100]
    return JsonResponse({"results": [capture_job_payload(row) for row in rows]})


@csrf_exempt
@require_http_methods(["GET", "PATCH"])
def retention_policy(request):
    policy = ensure_default_retention_policy()
    if request.method == "PATCH":
        payload = _json_body(request)
        policy.high_volume_search_days = int(payload.get("highVolumeSearchDays", policy.high_volume_search_days))
        policy.evidence_days = int(payload.get("evidenceDays", policy.evidence_days))
        policy.capture_chunk_days = int(payload.get("captureChunkDays", policy.capture_chunk_days))
        policy.enabled = payload.get("enabled", policy.enabled)
        policy.save()
    return JsonResponse(retention_policy_payload(policy))


@csrf_exempt
@require_http_methods(["POST"])
def retention_preview_view(_request):
    return JsonResponse(retention_run_payload(retention_preview()), status=201)


@csrf_exempt
@require_http_methods(["POST"])
def retention_execute(_request):
    return JsonResponse(retention_run_payload(execute_safe_retention()), status=201)


def retention_runs(_request):
    return JsonResponse({"results": [retention_run_payload(row) for row in RetentionRun.objects.order_by("-started_at")[:100]]})


@csrf_exempt
@require_http_methods(["POST", "DELETE"])
def case_legal_hold(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "compliance", case=case, resource_type="Case", resource_id=case.id)
    if denied:
        return denied
    actor = actor_from_request(request)
    case.legal_hold = request.method == "POST"
    case.legal_hold_reason = _json_body(request).get("reason", "") if request.method == "POST" else ""
    case.save(update_fields=["legal_hold", "legal_hold_reason", "updated_at"])
    action = "Legal hold enabled" if case.legal_hold else "Legal hold removed"
    add_history(case, actor, action, case.legal_hold_reason or "No reason supplied.")
    record_custody_event(case, actor, action, {"legalHold": case.legal_hold, "reason": case.legal_hold_reason}, resource_type="Case", resource_id=case.id)
    log_access(actor, "case.legal_hold" if case.legal_hold else "case.legal_hold.remove", case=case, resource_type="Case", resource_id=case.id)
    return JsonResponse({"caseId": case.id, "legalHold": case.legal_hold, "reason": case.legal_hold_reason})


def case_legal_review_checklist(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "compliance", case=case, resource_type="Case", resource_id=case.id)
    if denied:
        return denied
    actor = actor_from_request(request)
    log_access(actor, "case.legal_review.checklist", case=case, resource_type="Case", resource_id=case.id)
    return JsonResponse(legal_review_checklist(case))


def operational_events(request):
    rows = OperationalEvent.objects.order_by("-id")
    if request.GET.get("caseId"):
        rows = rows.filter(case_id=request.GET["caseId"])
    if request.GET.get("captureJobId"):
        rows = rows.filter(capture_job_id=request.GET["captureJobId"])
    try:
        limit = min(500, max(1, int(request.GET.get("limit", "100"))))
    except ValueError:
        limit = 100
    results = [_operational_event_dict(row) for row in reversed(list(rows[:limit]))]
    return JsonResponse({"results": results})


def operational_event_stream(request):
    case_id = request.GET.get("caseId")
    capture_job_id = request.GET.get("captureJobId")
    try:
        cursor = int(request.GET.get("after") or request.headers.get("Last-Event-ID") or 0)
    except ValueError:
        cursor = 0

    def generate():
        nonlocal cursor
        last_heartbeat = time.monotonic()
        while True:
            rows = OperationalEvent.objects.filter(id__gt=cursor).order_by("id")
            if case_id:
                rows = rows.filter(case_id=case_id)
            if capture_job_id:
                rows = rows.filter(capture_job_id=capture_job_id)
            emitted = False
            for row in rows[:100]:
                emitted = True
                cursor = row.id
                yield f"id: {row.id}\nevent: {row.event_type}\ndata: {json.dumps(_operational_event_dict(row))}\n\n"
            if not emitted and time.monotonic() - last_heartbeat >= 15:
                last_heartbeat = time.monotonic()
                yield ": heartbeat\n\n"
            time.sleep(1)

    response = StreamingHttpResponse(generate(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


def _operational_event_dict(row: OperationalEvent) -> dict:
    timestamp = row.created_at.isoformat()
    return {"id": row.id, "type": row.event_type, "eventType": row.event_type, "caseId": row.case_id or "", "captureJobId": row.capture_job_id or "", "timestamp": timestamp, "createdAt": timestamp, "payload": row.payload_json}


@csrf_exempt
@require_http_methods(["POST"])
def zeek_log_import(request):
    denied = require_permission(request, "upload", resource_type="ZeekLog")
    if denied:
        return denied
    payload = _json_body(request)
    job_id = f"zeek-log-{uuid4().hex[:8]}"
    publish_event("netra.protocol.decoded", {"type": "zeek.log.imported", "jobId": job_id, "payload": payload})
    return JsonResponse({"jobId": job_id, "status": "queued", "mode": "zeek_log_import"}, status=201)


def job_status(_request, job_id: str):
    job = ProcessingJob.objects.filter(id=job_id).first()
    if job:
        return JsonResponse(job_status_payload(job))
    analysis = _analysis()
    return JsonResponse({"jobId": job_id, "status": "completed", "progress": 100, "step": "completed", "steps": [], "stats": {"packetsParsed": analysis["summary"]["packets"], "alertsGenerated": analysis["summary"]["alerts"]}})


def job_events(_request, job_id: str):
    job = ProcessingJob.objects.filter(id=job_id).first()
    return JsonResponse({"jobId": job_id, "results": (job.events if job else [])})


def system_workers(_request):
    expected = ["capture", "pcap-ingestion", "parser", "decoder", "session", "detection", "anomaly", "analysis-finalizer", "report-export", "scheduler", "retention"]
    worker_mode = "enabled" if getattr(settings, "NETRA_SUPABASE_START_WORKERS", False) else "disabled"
    latest = {}
    by_worker = {}
    for row in WorkerHeartbeat.objects.order_by("worker_name", "-last_seen_at"):
        latest.setdefault(row.worker_name, row)
        by_worker.setdefault(row.worker_name, []).append(row)
    results = []
    for worker in expected:
        row = latest.get(worker)
        if worker_mode == "disabled" and getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
            results.append({
                "name": worker,
                "status": "disabled",
                "lastSeen": row.last_seen_at.isoformat() if row else None,
                "currentJobId": "",
                "details": (row.details_json if row else {}) | {"reason": "Supabase worker containers are disabled for lightweight synchronous demo mode."},
                "replicaCount": 0,
                "replicas": [],
            })
            continue
        if not row:
            results.append({"name": worker, "status": "offline", "lastSeen": None, "currentJobId": "", "details": {}, "replicaCount": 0, "replicas": []})
            continue
        replicas = [
            {"instanceId": instance.instance_id, "status": heartbeat_state(instance.last_seen_at), "lastSeen": instance.last_seen_at.isoformat()}
            for instance in by_worker.get(worker, [])
            if heartbeat_state(instance.last_seen_at) in {"healthy", "stale"}
        ]
        results.append(worker_payload(row, worker) | {"replicaCount": sum(1 for instance in replicas if instance["status"] == "healthy"), "replicas": replicas})
    return JsonResponse({"processingMode": settings.NETRA_PROCESSING_MODE, "queueProvider": getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka"), "workerMode": worker_mode, "results": results})


def system_health_deep(_request):
    checks = {
        "postgres": _probe_postgres(),
        "elasticsearch": _probe_elasticsearch(),
        "kafka": _probe_kafka(),
        "storage": _probe_storage(),
        "realtime": _probe_realtime(),
        "encryption": _probe_encryption(),
        "security": _probe_security(),
        "evidenceNormalization": _probe_evidence_normalization(),
        "packetTools": _probe_packet_tools(),
        "workers": _probe_workers(),
    }
    status = "ok" if all(value["status"] == "ok" for value in checks.values()) else "degraded"
    db = {
        "mode": getattr(settings, "NETRA_DATABASE_MODE", "docker-postgres"),
        "provider": getattr(settings, "NETRA_DATABASE_PROVIDER", "postgres"),
        "host": settings.DATABASES["default"]["HOST"],
        "port": settings.DATABASES["default"]["PORT"],
        "name": settings.DATABASES["default"]["NAME"],
        "tables": len(connection.introspection.table_names()),
    }
    access = {
        "mode": getattr(settings, "NETRA_ACCESS_MODE", "role-headers"),
        "label": "Supabase Auth" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else ("Trusted LAN" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "Development"),
        "authentication": "supabase-auth" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else ("disabled" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "development headers or JWT"),
        "authorization": "role-based" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else ("disabled" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "development"),
        "publicInternet": "not-supported" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "not-configured",
        "actor": getattr(settings, "NETRA_TRUSTED_LAN_ACTOR", "Local Investigator"),
        "role": getattr(settings, "NETRA_TRUSTED_LAN_ROLE", "LAN Operator"),
    }
    return JsonResponse({"status": status, "checkedAt": datetime.now(timezone.utc).isoformat(), "checks": checks, "database": db, "access": access, "incidentReadiness": incident_readiness_payload()})


def system_incident_readiness(request):
    actor = actor_from_request(request)
    log_access(actor, "system.incident_readiness", resource_type="System", resource_id="incident-readiness")
    return JsonResponse(incident_readiness_payload())


def system_deployment_readiness(request):
    actor = actor_from_request(request)
    log_access(actor, "system.deployment_readiness", resource_type="System", resource_id="deployment-readiness")
    return JsonResponse(deployment_readiness_payload())


def system_status_matrix(request):
    actor = actor_from_request(request)
    log_access(actor, "system.status_matrix", resource_type="System", resource_id="status-matrix")
    return JsonResponse(status_matrix_payload())


def ml_model_status(request):
    actor = actor_from_request(request)
    log_access(actor, "ml.model_status", resource_type="Model", resource_id="anomaly")
    return JsonResponse(ml_model_status_payload())


def system_metrics(_request):
    return JsonResponse(
        {
            "cases": Case.objects.count(),
            "evidenceFiles": EvidenceFile.objects.count(),
            "alerts": sum(len((job.stats.get("analysis") or {}).get("alerts", [])) for job in ProcessingJob.objects.all()),
            "criticalAlerts": sum(1 for job in ProcessingJob.objects.all() for alert in (job.stats.get("analysis") or {}).get("alerts", []) if alert.get("severity") == "critical"),
            "queuedJobs": ProcessingJob.objects.filter(status=ProcessingJob.Status.QUEUED).count(),
            "failedJobs": ProcessingJob.objects.filter(status=ProcessingJob.Status.FAILED).count(),
            "deadLetterEvents": DeadLetterEvent.objects.exclude(status=DeadLetterEvent.Status.RESOLVED).count(),
            "indexedPackets": sum((job.stats.get("indexed") or {}).get("packets", 0) for job in ProcessingJob.objects.all()),
            "storageBytes": sum(path.stat().st_size for path in settings.NETRA_STORAGE_ROOT.rglob("*") if path.is_file()) if settings.NETRA_STORAGE_ROOT.exists() else 0,
        }
    )


def system_storage(_request):
    rows = []
    if settings.NETRA_STORAGE_ROOT.exists():
        for path in settings.NETRA_STORAGE_ROOT.iterdir():
            if path.is_dir():
                rows.append({"folder": path.name, "bytes": sum(item.stat().st_size for item in path.rglob("*") if item.is_file())})
    return JsonResponse({"root": str(settings.NETRA_STORAGE_ROOT), "results": rows})


def system_indexes(_request):
    if getattr(settings, "NETRA_SEARCH_PROVIDER", "elasticsearch") == "postgres" or getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
        return JsonResponse({"status": "ok", "provider": "postgres", "results": ["forensics_processingjob.stats", "forensics_sessionsummary", "forensics_alert"], "detail": "Elasticsearch disabled in Supabase mode."})
    try:
        from common.search import get_elasticsearch_client
        rows = sorted(get_elasticsearch_client().indices.get_alias(index="netra-*").keys())
        return JsonResponse({"status": "ok", "results": rows})
    except Exception as exc:
        return JsonResponse({"status": "failed", "results": [], "detail": str(exc)}, status=503)


def system_kafka(_request):
    probe = _probe_kafka()
    queue_topics = ["pcap-uploaded", "capture-chunk-received", "analysis-finalize", "report-export", "dead-letter"] if getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka") == "supabase-pgmq" else ["netra.pcap.uploaded", "netra.capture.chunk.received", "netra.packets.normalized", "netra.operational.events", "netra.dead_letter"]
    return JsonResponse({"provider": getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka"), "bootstrap": "" if getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka") == "supabase-pgmq" else settings.NETRA_KAFKA_BOOTSTRAP, **probe, "topics": queue_topics}, status=200 if probe["status"] in {"ok", "configured"} else 503)


def system_realtime(_request):
    expected = [
        "forensics_operationalevent",
        "forensics_processingjob",
        "forensics_alert",
        "forensics_anomalyrecord",
        "forensics_capturejob",
        "forensics_workerheartbeat",
    ]
    if getattr(settings, "NETRA_REALTIME_PROVIDER", "") != "supabase":
        return JsonResponse({"status": "disabled", "provider": getattr(settings, "NETRA_REALTIME_PROVIDER", "none"), "tables": []})
    try:
        with connection.cursor() as cursor:
            cursor.execute("select exists(select 1 from pg_publication where pubname = 'supabase_realtime')")
            publication = bool(cursor.fetchone()[0])
            cursor.execute(
                """
                select tablename
                from pg_publication_tables
                where pubname = 'supabase_realtime' and schemaname = 'public'
                order by tablename
                """
            )
            tables = [row[0] for row in cursor.fetchall()]
        missing = [table for table in expected if table not in tables]
        return JsonResponse(
            {
                "status": "ok" if publication and not missing else "degraded",
                "provider": "supabase-realtime",
                "publication": "supabase_realtime" if publication else "",
                "tables": tables,
                "expectedTables": expected,
                "missingTables": missing,
                "detail": "Browser subscriptions use these low-volume operational tables only.",
            },
            status=200 if publication else 503,
        )
    except Exception as exc:
        return JsonResponse({"status": "failed", "provider": "supabase-realtime", "detail": str(exc)}, status=503)


def system_capacity(_request):
    return JsonResponse(capacity_payload())


def system_kafka_lag(_request):
    return JsonResponse(kafka_lag_payload())


def system_throughput(_request):
    cutoff = datetime.now(timezone.utc).timestamp() - 60
    recent_chunks = [row for row in OperationalEvent.objects.filter(event_type="capture.chunk_received").order_by("-created_at")[:500] if row.created_at.timestamp() >= cutoff]
    packets = sum(int(row.payload_json.get("chunkPackets", 0)) for row in recent_chunks)
    return JsonResponse({"windowSeconds": 60, "chunksPerMinute": len(recent_chunks), "packetsIndexedPerMinute": packets})


def system_index_retention(_request):
    policy = ensure_default_retention_policy()
    return JsonResponse({"status": "configured", "policy": retention_policy_payload(policy), "aliases": ["netra-packets", "netra-sessions", "netra-protocols", "netra-payloads", "netra-alerts", "netra-zeek", "netra-live-packets"]})


def _probe_postgres() -> dict:
    started = time.perf_counter()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return {"status": "ok", "latencyMs": round((time.perf_counter() - started) * 1000, 2)}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def _probe_elasticsearch() -> dict:
    if getattr(settings, "NETRA_SEARCH_PROVIDER", "elasticsearch") == "postgres" or getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
        return {"status": "ok", "provider": "postgres", "detail": "Elasticsearch disabled in Supabase mode."}
    started = time.perf_counter()
    try:
        from common.search import get_elasticsearch_client
        ok = bool(get_elasticsearch_client().ping())
        return {"status": "ok" if ok else "failed", "latencyMs": round((time.perf_counter() - started) * 1000, 2)}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def _probe_kafka() -> dict:
    if getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka") == "supabase-pgmq":
        return probe_supabase_queue()
    started = time.perf_counter()
    try:
        from kafka.admin import KafkaAdminClient
        admin = KafkaAdminClient(bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP, request_timeout_ms=2500, api_version_auto_timeout_ms=2500)
        topics = sorted(admin.list_topics())
        admin.close()
        return {"status": "ok", "latencyMs": round((time.perf_counter() - started) * 1000, 2), "topicCount": len(topics)}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def _probe_realtime() -> dict:
    if getattr(settings, "NETRA_REALTIME_PROVIDER", "") != "supabase":
        return {"status": "configured", "provider": getattr(settings, "NETRA_REALTIME_PROVIDER", "none"), "detail": "Supabase Realtime is not selected."}
    expected = {"forensics_operationalevent", "forensics_processingjob", "forensics_alert", "forensics_anomalyrecord", "forensics_capturejob", "forensics_workerheartbeat"}
    try:
        with connection.cursor() as cursor:
            cursor.execute("select tablename from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public'")
            tables = {row[0] for row in cursor.fetchall()}
        missing = sorted(expected - tables)
        return {"status": "ok" if not missing else "degraded", "provider": "supabase-realtime", "missingTables": missing}
    except Exception as exc:
        return {"status": "failed", "provider": "supabase-realtime", "detail": str(exc)}


def _probe_storage() -> dict:
    if getattr(settings, "NETRA_STORAGE_PROVIDER", "local") == "supabase":
        try:
            result = storage_provider.health_check()
            return {**result, "bucket": settings.SUPABASE_STORAGE_BUCKET_EVIDENCE}
        except Exception as exc:
            return {"status": "failed", "provider": "supabase-storage", "detail": str(exc)}
    try:
        settings.NETRA_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
        probe = settings.NETRA_STORAGE_ROOT / ".netra-health-probe"
        probe.write_text("ok", encoding="utf-8")
        ok = probe.read_text(encoding="utf-8") == "ok"
        probe.unlink(missing_ok=True)
        return {"status": "ok" if ok else "failed"}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def _probe_encryption() -> dict:
    try:
        token = fernet().encrypt(b"netra-health")
        return {"status": "ok" if fernet().decrypt(token) == b"netra-health" else "failed", "keyId": settings.NETRA_EVIDENCE_KEY_ID}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def _probe_security() -> dict:
    details = []
    status = "ok"
    if getattr(settings, "NETRA_AUTH_PROVIDER", "") != "supabase":
        details.append("Supabase Auth is not the active auth provider.")
        status = "degraded"
    if getattr(settings, "NETRA_DEV_ROLE_HEADERS", False):
        details.append("Development role headers are enabled.")
        status = "degraded"
    if not getattr(settings, "SUPABASE_SERVICE_ROLE_KEY", ""):
        details.append("Backend Supabase service-role key is missing.")
        status = "failed"
    if getattr(settings, "NETRA_STORAGE_PROVIDER", "") == "supabase" and not getattr(settings, "SUPABASE_SERVICE_ROLE_KEY", ""):
        details.append("Supabase Storage cannot use private buckets without backend service-role key.")
        status = "failed"
    if getattr(settings, "NETRA_EVIDENCE_KEY", "") == "netra-phase3-development-evidence-key":
        details.append("Evidence encryption key is still the development default.")
        if status == "ok":
            status = "degraded"
    admin_count = _admin_count()
    if admin_count < 1:
        details.append("No Netra Admin profile exists yet; the next authenticated Supabase user will bootstrap Admin.")
        if status == "ok":
            status = "degraded"
    return {
        "status": status,
        "authProvider": getattr(settings, "NETRA_AUTH_PROVIDER", "django"),
        "rbac": "enabled" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else "development",
        "devRoleHeaders": bool(getattr(settings, "NETRA_DEV_ROLE_HEADERS", False)),
        "serviceRoleBackendOnly": True,
        "serviceRoleConfigured": bool(getattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "")),
        "adminProfiles": admin_count,
        "detail": "; ".join(details) if details else "Supabase Auth, RBAC, private Storage credentials, and audit logging are configured.",
    }


def _probe_evidence_normalization() -> dict:
    return {
        "status": "ok",
        "detail": "Evidence normalization and unsupported extension blocking are enabled. PCAP is fully analyzable; firewall, DNS, TLS, and mixed evidence are validation-only until their parsers are connected.",
        "supportedTypes": ["PCAP", "Firewall Logs", "DNS Logs", "TLS Metadata", "Mixed Evidence"],
        "fullyAnalyzable": ["PCAP"],
        "unsupportedExtensionBlocking": "enabled",
        "logEvidence": "validation-only",
    }


def _probe_packet_tools() -> dict:
    tools = available_packet_tools()
    return {"status": "ok" if tools.get("tshark") and tools.get("zeek") else "degraded", **tools}


def _probe_workers() -> dict:
    if getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase" and not getattr(settings, "NETRA_SUPABASE_START_WORKERS", False):
        return {"status": "ok", "mode": "disabled", "detail": "Supabase worker containers are disabled for lightweight synchronous demo mode."}
    rows = system_workers(None).content
    payload = json.loads(rows)
    offline = [row["name"] for row in payload["results"] if row["status"] == "offline"]
    stale = [row["name"] for row in payload["results"] if row["status"] == "stale"]
    return {"status": "ok" if not offline and not stale else "degraded", "mode": payload.get("workerMode", "enabled"), "offline": offline, "stale": stale}


def system_database(_request):
    tables = connection.introspection.table_names()
    access = {
        "mode": getattr(settings, "NETRA_ACCESS_MODE", "role-headers"),
        "label": "Supabase Auth" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else ("Trusted LAN" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "Development"),
        "authentication": "supabase-auth" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else ("disabled" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "development headers or JWT"),
        "publicInternet": "not-supported" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "not-configured",
    }
    return JsonResponse(
        {
            "mode": getattr(settings, "NETRA_DATABASE_MODE", "docker-postgres"),
            "provider": getattr(settings, "NETRA_DATABASE_PROVIDER", "postgres"),
            "engine": settings.DATABASES["default"]["ENGINE"],
            "host": settings.DATABASES["default"]["HOST"],
            "port": settings.DATABASES["default"]["PORT"],
            "name": settings.DATABASES["default"]["NAME"],
            "user": settings.DATABASES["default"]["USER"],
            "tables": len(tables),
            "forensicsTables": sorted([table for table in tables if table.startswith("forensics_")]),
            "access": access,
        }
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def dead_letter(request):
    if request.method == "POST":
        payload = _json_body(request)
        event = DeadLetterEvent.objects.create(
            id=f"dlq-{uuid4().hex[:8]}",
            topic=payload.get("topic", "netra.dead_letter"),
            worker_name=payload.get("workerName", "manual"),
            job_id=payload.get("jobId", ""),
            case_id=payload.get("caseId", ""),
            evidence_id=payload.get("evidenceId", ""),
            payload_json=payload.get("payload", {}),
            error_message=payload.get("error", "Manual dead-letter test event"),
        )
        return JsonResponse({"id": event.id, "status": event.status}, status=201)
    rows = DeadLetterEvent.objects.order_by("-created_at")[:50]
    return JsonResponse({"results": [_dead_letter_dict(row) for row in rows]})


@csrf_exempt
@require_http_methods(["POST"])
def dead_letter_retry(_request, event_id: str):
    event = DeadLetterEvent.objects.filter(id=event_id).first()
    if not event:
        raise Http404("Dead-letter event not found")
    event.status = DeadLetterEvent.Status.RETRYING
    event.retry_count += 1
    event.save(update_fields=["status", "retry_count", "updated_at"])
    publish_event(event.topic, event.payload_json | {"retryOf": event.id})
    return JsonResponse(_dead_letter_dict(event))


@csrf_exempt
@require_http_methods(["POST"])
def dead_letter_ignore(_request, event_id: str):
    event = DeadLetterEvent.objects.filter(id=event_id).first()
    if not event:
        raise Http404("Dead-letter event not found")
    event.status = DeadLetterEvent.Status.IGNORED
    event.save(update_fields=["status", "updated_at"])
    return JsonResponse(_dead_letter_dict(event))


@csrf_exempt
@require_http_methods(["POST"])
def job_reprocess(_request, job_id: str):
    job = ProcessingJob.objects.filter(id=job_id).first()
    if not job:
        raise Http404("Job not found")
    job.events = (job.events or []) + [{"timestamp": datetime.now(timezone.utc).isoformat(), "event": "reprocess.requested", "detail": "Manual Phase 3 reprocess requested."}]
    job.save(update_fields=["events", "updated_at"])
    publish_event("netra.pcap.uploaded", {"type": "job.reprocess", "jobId": job.id, "caseId": job.case_id})
    return JsonResponse(job_status_payload(job))


def _dead_letter_dict(row: DeadLetterEvent) -> dict:
    return {"id": row.id, "topic": row.topic, "workerName": row.worker_name, "jobId": row.job_id, "caseId": row.case_id, "error": row.error_message, "retryCount": row.retry_count, "status": row.status, "timestamp": row.created_at.isoformat()}


def dashboard_summary(request):
    analysis = _analysis(request)
    return JsonResponse(
        dashboard_summary_payload(request.GET.get("caseId") or analysis.get("caseId", ""))
        | {
            "case": analysis.get("case"),
            "evidence": analysis.get("evidence"),
            "zeek": analysis.get("zeek", analysis["summary"].get("zeek")),
        }
    )


def traffic_timeline(request):
    return JsonResponse({"results": _analysis(request).get("trafficTimeline", [])})


def protocol_distribution(request):
    return JsonResponse({"results": _analysis(request).get("protocolChartData", [])})


def alerts(request):
    rows = _filter_rows(_results("alerts", request), request.GET, {"severity": "severity", "attackClass": "attackClass", "status": "status"})
    return JsonResponse({"results": rows})


def packets(request):
    fallback = _filter_rows(_results("packets", request), request.GET, {"sourceIp": "sourceIp", "destinationIp": "destinationIp", "protocol": "protocol", "sessionId": "sessionId", "severity": "severity"})
    rows, backend = search_index("packets", request.GET.get("caseId", ""), request.GET.get("q", ""), fallback)
    rows = _filter_rows(rows, request.GET, {"sourceIp": "sourceIp", "destinationIp": "destinationIp", "protocol": "protocol", "sessionId": "sessionId", "severity": "severity"})
    port = request.GET.get("port")
    if port:
        rows = [row for row in rows if str(row["sourcePort"]) == port or str(row["destinationPort"]) == port]
    payload = _paged(rows, request)
    payload["searchBackend"] = backend
    return JsonResponse(payload)


def packet_detail(_request, packet_id: str):
    packet = next((row for row in _results("packets") if row["id"] == packet_id), None)
    if not packet:
        raise Http404("Packet not found")
    return JsonResponse(packet)


def sessions(request):
    fallback = _results("sessions", request)
    rows, backend = search_index("sessions", request.GET.get("caseId", ""), request.GET.get("q", ""), fallback)
    rows = _filter_rows(rows, request.GET, {"source": "source", "destination": "destination", "protocol": "protocol"})
    min_risk = request.GET.get("minRisk")
    if min_risk:
        rows = [row for row in rows if int(row.get("riskScore", row.get("risk_score", 0)) or 0) >= int(min_risk)]
    payload = _paged(rows, request)
    payload["searchBackend"] = backend
    return JsonResponse(payload)


def session_detail(_request, session_id: str):
    session = next((row for row in _results("sessions") if row["id"] == session_id), None)
    if not session:
        raise Http404("Session not found")
    return JsonResponse(session | {"reconstruction": f"{session['packetCount']} packet(s) reconstructed from uploaded PCAP metadata."})


def session_timeline(_request, session_id: str):
    session = next((row for row in _results("sessions") if row["id"] == session_id), None)
    if not session:
        return JsonResponse({"sessionId": session_id, "results": []})
    return JsonResponse({"sessionId": session_id, "results": [{"time": session["startTime"], "event": "Session started"}, {"time": session["endTime"], "event": "Session ended"}]})


def decoder_summary(request):
    analysis = _analysis(request)
    return JsonResponse(
        {
            "encryptedTrafficPolicy": "Encrypted content is not decrypted; metadata patterns are analyzed.",
            "results": analysis.get("decodedProtocols", []),
            "zeek": analysis.get("zeek", {}),
        }
    )


def decoder_protocol(_request, protocol: str):
    rows = [row for row in _results("decodedProtocols") if protocol.lower() in row["protocol"].lower()]
    return JsonResponse({"protocol": protocol, "results": rows})


def payloads(request):
    fallback = _filter_rows(_results("payloadFindings", request), request.GET, {"protocol": "protocol", "risk": "risk"})
    rows, backend = search_index("payloads", request.GET.get("caseId", ""), request.GET.get("q", ""), fallback)
    rows = _filter_rows(rows, request.GET, {"protocol": "protocol", "risk": "risk"})
    return JsonResponse({"results": rows, "searchBackend": backend})


def payload_detail(_request, finding_id: str):
    finding = next((row for row in _results("payloadFindings") if row["id"] == finding_id), None)
    if not finding:
        raise Http404("Payload finding not found")
    return JsonResponse(finding)


def detection_rules(_request):
    return JsonResponse({"results": load_rules()})


def detection_matches(request):
    category = request.GET.get("category")
    rows = _results("detectionMatches", request)
    if category and category != "all":
        rows = [row for row in rows if category.lower() in row["category"].lower() or category.lower() in row["ruleName"].lower()]
    return JsonResponse({"results": rows})


@csrf_exempt
@require_http_methods(["PATCH", "POST"])
def detection_match_status(request, match_id: str):
    payload = _json_body(request)
    case_id = request.GET.get("caseId") or payload.get("caseId")
    case = Case.objects.filter(id=case_id).first() if case_id else None
    permission = "confirm" if payload.get("status") in {"confirmed", "dismissed"} else "review"
    denied = require_permission(request, permission, case=case, resource_type="DetectionMatch", resource_id=match_id)
    if denied:
        return denied
    updated = update_analysis_alert_status(match_id, payload.get("status", "reviewing"), actor_from_request(request))
    publish_event("netra.detection.matches", {"type": "detection.status_changed", "matchId": match_id, "status": payload.get("status", "reviewing")})
    return JsonResponse(updated or {"id": match_id, "status": payload.get("status", "reviewing")})


@csrf_exempt
@require_http_methods(["PATCH", "POST"])
def alert_status(request, alert_id: str):
    payload = _json_body(request)
    case_id = request.GET.get("caseId") or payload.get("caseId")
    case = Case.objects.filter(id=case_id).first() if case_id else None
    permission = "confirm" if payload.get("status") in {"confirmed", "dismissed"} else "review"
    denied = require_permission(request, permission, case=case, resource_type="Alert", resource_id=alert_id)
    if denied:
        return denied
    updated = update_analysis_alert_status(alert_id, payload.get("status", "reviewing"), actor_from_request(request))
    publish_event("netra.alerts.created", {"type": "alert.status_changed", "alertId": alert_id, "status": payload.get("status", "reviewing")})
    return JsonResponse(updated or {"id": alert_id, "status": payload.get("status", "reviewing")})


def anomalies(request):
    return JsonResponse({"results": _results("anomalies", request)})


def case_anomaly_explanation(request, case_id: str):
    model = ml_model_status_payload()
    rows = _analysis(case_id=case_id).get("anomalies", [])
    top_features: list[str] = []
    explanations = []
    for row in rows[:8]:
        features = row.get("topFeatures") or []
        top_features.extend([str(item) for item in features])
        explanations.append(
            {
                "id": row.get("id"),
                "entity": row.get("entity"),
                "behaviour": row.get("behaviour"),
                "confidence": row.get("confidence", 0),
                "topFeatures": features,
                "recommendedAction": row.get("recommendedAction") or "Review related packets, sessions, and alerts before making an investigative conclusion.",
                "modelVersion": row.get("modelVersion") or model.get("version", "fallback-scoring"),
                "mlAnomalyScore": row.get("mlAnomalyScore"),
            }
        )
    unique_features = list(dict.fromkeys(top_features))[:10]
    return JsonResponse(
        {
            "caseId": case_id,
            "mode": "trained-model-with-explainable-fallback" if model.get("modelAvailable") else "explainable-fallback",
            "modelVersion": model.get("version") or "fallback-scoring",
            "modelType": model.get("modelType") or "heuristic-statistical",
            "fallbackUsed": not bool(model.get("modelAvailable")),
            "topFeatures": unique_features,
            "explanations": explanations,
            "limitations": [
                "PCAP-only anomaly scoring indicates unusual network behavior, not proof of compromise.",
                "Encrypted payload contents are not decrypted.",
                "Model quality depends on the available benchmark corpus and should be reviewed before public production use.",
            ],
        }
    )


def anomaly_baseline(request):
    return JsonResponse({"results": [{"metric": row["behaviour"], "baseline": row["baseline"], "observed": row["observed"], "confidence": row["confidence"]} for row in _results("anomalies", request)]})


def anomaly_risk_timeline(request):
    return JsonResponse({"results": [{"time": row["time"], "risk": min(100, row.get("alerts", 0) * 20)} for row in _analysis(request).get("trafficTimeline", [])]})


def graph(request):
    return JsonResponse(_analysis(request).get("graph", {"nodes": [], "edges": []}))


def graph_node(_request, node_id: str):
    node = next((row for row in _analysis().get("graph", {}).get("nodes", []) if row["id"] == node_id), None)
    analysis = _analysis()
    related_alerts = [alert for alert in analysis.get("alerts", []) if alert["id"] in (node or {}).get("alertIds", [])]
    return JsonResponse({"id": node_id, "riskScore": node.get("risk", 0) if node else 0, "node": node, "relatedAlerts": related_alerts})


def graph_attack_path(_request):
    graph_data = _analysis().get("graph", {"edges": []})
    path = [graph_data["edges"][0]["source"], graph_data["edges"][0]["target"]] if graph_data.get("edges") else []
    return JsonResponse({"path": path})


def search(request):
    kind = request.GET.get("type", "packets")
    case_id = request.GET.get("caseId", "")
    query_text = request.GET.get("q", "")
    fallback_key = {"packets": "packets", "sessions": "sessions", "alerts": "alerts", "zeek": "decodedProtocols"}.get(kind, "packets")
    rows, backend = search_index(kind if kind in {"packets", "sessions", "alerts", "zeek", "payloads"} else "packets", case_id, query_text, _analysis(request, case_id=case_id).get(fallback_key, []))
    payload = _paged(rows, request)
    payload["searchBackend"] = backend
    return JsonResponse(payload)


def report_preview(request, case_id: str):
    language = request.GET.get("language", "en")
    analysis = _analysis(case_id=case_id)
    case = Case.objects.filter(id=case_id).first()
    custody = verify_case_ledger(case) if case else {"verified": False, "eventCount": 0}
    summary = f"Netra parsed {analysis['summary']['packets']} packets, reconstructed {analysis['summary']['sessions']} sessions, and generated {analysis['summary']['alerts']} alert(s). Top class: {analysis.get('topAttackClass', 'Normal Baseline')}."
    return JsonResponse(
        {
            "caseId": case_id,
            "language": language,
            "summary": summary,
            "riskLevel": analysis.get("riskLevel", "low"),
            "topAttackClass": analysis.get("topAttackClass", "Normal Baseline"),
            "alerts": analysis.get("alerts", []),
            "anomalies": analysis.get("anomalies", []),
            "evidence": analysis.get("evidence"),
            "zeek": analysis.get("zeek", {}),
            "toolStatus": analysis.get("toolStatus", available_packet_tools()),
            "chainOfCustody": analysis.get("chainOfCustody", []),
            "custodyLedger": custody,
            "legalReview": legal_review_checklist(case) if case else {},
            "timeline": analysis.get("trafficTimeline", []),
            "graph": analysis.get("graph", {}),
        }
    )


def reports(request):
    rows = Report.objects.select_related("case").order_by("-created_at")
    case_id = request.GET.get("caseId")
    if case_id:
        rows = rows.filter(case_id=case_id)
    status = request.GET.get("status")
    if status and status != "all":
        rows = rows.filter(status=status)
    language = request.GET.get("language")
    if language and language != "all":
        rows = rows.filter(language=language)
    if request.GET.get("includeTest") not in {"1", "true", "yes"}:
        test_query = Q(case__is_test=True) | Q(case__origin__in=[Case.Origin.VALIDATOR, Case.Origin.SYSTEM_TEST])
        for prefix in VALIDATOR_CASE_PREFIXES:
            test_query |= Q(case_id__startswith=prefix)
        rows = rows.exclude(test_query)
    return JsonResponse(_paged([_report_dict(row) for row in rows[:250]], request))


def case_reports(request, case_id: str):
    request.GET._mutable = True
    request.GET["caseId"] = case_id
    request.GET._mutable = False
    return reports(request)


@csrf_exempt
@require_http_methods(["POST"])
def report_generate(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "report", case=case, resource_type="Report", resource_id=case_id)
    if denied:
        return denied
    actor = actor_from_request(request)
    payload = _json_body(request)
    language = payload.get("language", "en")
    report_format = (payload.get("format") or "html").lower()
    analysis = _analysis(case_id=case_id)
    if getattr(settings, "NETRA_SUPABASE_START_WORKERS", False) and payload.get("queued"):
        extension = "pdf" if report_format == "pdf" else "html"
        report_id = f"{case_id}-{language}-{uuid4().hex[:6]}.{extension}"
        if case:
            Report.objects.update_or_create(
                id=report_id,
                defaults={"case": case, "language": language, "generated_by": actor.user, "status": "queued", "stored_path": "", "sha256": ""},
            )
        publish_event("netra.export.requests", {"type": "report.generate", "caseId": case_id, "language": language, "reportId": report_id, "actor": actor.user})
        return JsonResponse({"caseId": case_id, "language": language, "status": "queued", "reportId": report_id}, status=202)
    artifact = generate_pdf_report_artifact(case_id, language, analysis, actor) if report_format == "pdf" else generate_report_artifact(case_id, language, analysis, actor)
    publish_event("netra.export.completed", {"type": "report.generated", "format": report_format, "caseId": case_id, **artifact})
    return JsonResponse({"caseId": case_id, "language": language, "status": "ready", "reportId": artifact["id"], "downloadUrl": f"/api/reports/{artifact['id']}/download", **artifact}, status=201)


def report_download(request, report_id: str):
    report = Report.objects.filter(id=report_id).first()
    if not report:
        raise Http404("Report not found")
    denied = require_permission(request, "report", case=report.case, resource_type="Report", resource_id=report.id)
    if denied:
        return denied
    actor = actor_from_request(request)
    record_custody_event(report.case, actor, "Report downloaded", {"reportId": report.id, "sha256": report.sha256}, resource_type="Report", resource_id=report.id)
    log_access(actor, "report.download", case=report.case, resource_type="Report", resource_id=report.id)
    filename = report.id.removesuffix(".enc")
    content_type = "application/pdf" if filename.lower().endswith(".pdf") else "text/html"
    return HttpResponse(read_encrypted_or_plain(report.stored_path), headers={"Content-Disposition": f'attachment; filename="{filename}"'}, content_type=content_type)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def exports(request):
    if request.method == "POST":
        denied = require_permission(request, "export", resource_type="Export")
        if denied:
            return denied
        actor = actor_from_request(request)
        payload = _json_body(request)
        case_id = payload.get("caseId") or request.GET.get("caseId") or _analysis().get("caseId", "")
        case = Case.objects.filter(id=case_id).first()
        if not case:
            raise Http404("Case not found")
        analysis = _analysis(case_id=case_id)
        export_type = (payload.get("type") or "json").lower()
        if getattr(settings, "NETRA_SUPABASE_START_WORKERS", False) and payload.get("queued"):
            export_id = f"exp-{uuid4().hex[:8]}"
            Export.objects.update_or_create(
                id=export_id,
                defaults={"case": case, "export_type": export_type, "requested_by": actor.user, "status": "queued", "stored_path": "", "sha256": ""},
            )
            publish_event("netra.export.requests", {"type": "export.generate", "caseId": case_id, "exportType": export_type, "exportId": export_id, "actor": actor.user})
            return JsonResponse({"id": export_id, "status": "queued", "type": export_type}, status=202)
        artifact = generate_export_artifact(case_id, export_type, analysis, actor)
        publish_event("netra.export.requests", {"type": "export.created", "exportId": artifact["id"], **payload})
        return JsonResponse({"id": artifact["id"], "status": "ready", "type": export_type, "downloadUrl": f"/api/exports/{artifact['id']}/download", **artifact}, status=201)
    denied = require_permission(request, "view", resource_type="Export")
    if denied:
        return denied
    case_id = request.GET.get("caseId")
    queryset = Export.objects.select_related("case").order_by("-created_at")
    if case_id:
        queryset = queryset.filter(case_id=case_id)
    if request.GET.get("includeTest") not in {"1", "true", "yes"}:
        test_query = Q(case__is_test=True) | Q(case__origin__in=[Case.Origin.VALIDATOR, Case.Origin.SYSTEM_TEST])
        for prefix in VALIDATOR_CASE_PREFIXES:
            test_query |= Q(case_id__startswith=prefix)
        queryset = queryset.exclude(test_query)
    generated = [
        {"id": row.id, "type": row.export_type, "caseId": row.case_id, "requestedBy": row.requested_by, "timestamp": row.created_at.isoformat(), "hash": row.sha256 or row.stored_path, "status": row.status, "downloadUrl": f"/api/exports/{row.id}/download"}
        for row in queryset[:50]
    ]
    return JsonResponse({"results": generated})


def export_detail(request, export_id: str):
    export = Export.objects.filter(id=export_id).first()
    if not export:
        raise Http404("Export not found")
    denied = require_permission(request, "view", case=export.case, resource_type="Export", resource_id=export.id)
    if denied:
        return denied
    return JsonResponse({"id": export.id, "type": export.export_type, "caseId": export.case_id, "requestedBy": export.requested_by, "timestamp": export.created_at.isoformat(), "hash": export.sha256 or export.stored_path, "status": export.status, "downloadUrl": f"/api/exports/{export.id}/download"})


def export_download(request, export_id: str):
    export = Export.objects.filter(id=export_id).first()
    if not export:
        raise Http404("Export not found")
    denied = require_permission(request, "export", case=export.case, resource_type="Export", resource_id=export.id)
    if denied:
        return denied
    actor = actor_from_request(request)
    record_custody_event(export.case, actor, "Evidence export downloaded", {"exportId": export.id, "type": export.export_type, "sha256": export.sha256}, resource_type="Export", resource_id=export.id)
    log_access(actor, "export.download", case=export.case, resource_type="Export", resource_id=export.id)
    extension = "cef" if "cef" in export.export_type else ("csv" if "csv" in export.export_type or "alert" in export.export_type else "json")
    filename = f"{export.id}.{extension}"
    return HttpResponse(read_encrypted_or_plain(export.stored_path), headers={"Content-Disposition": f'attachment; filename="{filename}"'}, content_type="application/octet-stream")


@csrf_exempt
@require_http_methods(["GET", "POST"])
def integrations(request):
    if request.method == "POST":
        denied = require_permission(request, "integrations", resource_type="IntegrationConnection")
        if denied:
            return denied
        payload = _json_body(request)
        connection, _ = IntegrationConnection.objects.update_or_create(
            system_name=payload.get("systemName", "Local webhook"),
            defaults={
                "status": "pending",
                "api_mode": payload.get("mode", "webhook-json"),
                "config": {key: value for key, value in payload.items() if key != "secret"},
            },
        )
        if payload.get("secret"):
            IntegrationCredential.objects.update_or_create(integration=connection, defaults={"secret_label": "webhook-hmac", "secret_value": payload["secret"]})
        return JsonResponse(_integration_dict(connection), status=201)
    rows = [_integration_dict(row) for row in IntegrationConnection.objects.order_by("system_name")]
    return JsonResponse({"results": rows})


def _integration_dict(row: IntegrationConnection) -> dict:
    latest = row.deliveries.order_by("-created_at").first()
    return {
        "id": row.id,
        "system": row.system_name,
        "systemName": row.system_name,
        "status": row.status,
        "lastSync": latest.created_at.isoformat() if latest else (row.last_sync_at.isoformat() if row.last_sync_at else "Not connected"),
        "linkedCases": row.linked_cases_count,
        "apiMode": row.api_mode,
        "config": row.config,
    }


@csrf_exempt
@require_http_methods(["POST"])
def integration_sync(_request, integration_id: str):
    publish_event("netra.case.events", {"type": "integration.sync", "integrationId": integration_id})
    return JsonResponse({"integrationId": integration_id, "status": "sync-requested"})


@csrf_exempt
@require_http_methods(["PATCH"])
def integration_detail(request, integration_id: str):
    denied = require_permission(request, "integrations", resource_type="IntegrationConnection", resource_id=integration_id)
    if denied:
        return denied
    connection = IntegrationConnection.objects.filter(id=integration_id).first()
    if not connection:
        raise Http404("Integration not found")
    payload = _json_body(request)
    connection.status = payload.get("status", connection.status)
    connection.api_mode = payload.get("mode", connection.api_mode)
    connection.config = connection.config | payload
    connection.save()
    return JsonResponse(_integration_dict(connection))


@csrf_exempt
@require_http_methods(["POST"])
def integration_test(request, integration_id: str):
    denied = require_permission(request, "integrations", resource_type="IntegrationConnection", resource_id=integration_id)
    if denied:
        return denied
    connection = IntegrationConnection.objects.filter(id=integration_id).first()
    if not connection:
        raise Http404("Integration not found")
    delivery = _deliver_webhook(connection, {"source": "netra", "type": "integration.test", "timestamp": datetime.now(timezone.utc).isoformat()}, "test")
    connection.status = "connected" if delivery.result == "success" else "failed"
    connection.last_sync_at = datetime.now(timezone.utc)
    connection.save(update_fields=["status", "last_sync_at", "updated_at"])
    return JsonResponse({"deliveryId": delivery.id, "result": delivery.result, "response": delivery.response_summary}, status=200 if delivery.result == "success" else 502)


@csrf_exempt
@require_http_methods(["POST"])
def integration_send_alerts(request, integration_id: str):
    denied = require_permission(request, "integrations", resource_type="IntegrationConnection", resource_id=integration_id)
    if denied:
        return denied
    connection = IntegrationConnection.objects.filter(id=integration_id).first()
    if not connection:
        raise Http404("Integration not found")
    payload = _json_body(request)
    case_id = payload.get("caseId") or _analysis().get("caseId", "")
    analysis = _analysis(case_id=case_id)
    case = Case.objects.filter(id=case_id).first()
    deliveries = []
    for alert in analysis.get("alerts", [])[:20]:
        event = {"source": "netra", "caseId": case_id, "alertId": alert.get("id"), "attackClass": alert.get("attackClass"), "severity": alert.get("severity"), "confidence": alert.get("confidence"), "sourceIp": alert.get("sourceIp"), "destination": alert.get("destination"), "timestamp": alert.get("timestamp"), "evidenceHash": (analysis.get("evidence") or {}).get("sha256", "")}
        delivery = _deliver_webhook(connection, event, "alert", case=case)
        deliveries.append(delivery)
        if case:
            record_custody_event(case, actor_from_request(request), "Integration delivery sent", event, resource_type="IntegrationConnection", resource_id=str(connection.id))
    succeeded = [delivery for delivery in deliveries if delivery.result == "success"]
    failed = [delivery for delivery in deliveries if delivery.result != "success"]
    if deliveries:
        connection.status = "connected" if succeeded and not failed else ("degraded" if succeeded else "failed")
        connection.last_sync_at = datetime.now(timezone.utc)
        connection.save(update_fields=["status", "last_sync_at", "updated_at"])
    return JsonResponse({"integrationId": integration_id, "caseId": case_id, "attempted": len(deliveries), "delivered": len(succeeded), "failed": len(failed), "deliveryIds": [delivery.id for delivery in deliveries]})


def integration_deliveries(_request, integration_id: str):
    rows = IntegrationDelivery.objects.filter(integration_id=integration_id).order_by("-created_at")[:50]
    return JsonResponse({"results": [{"id": row.id, "timestamp": row.created_at.isoformat(), "caseId": row.case_id or "", "type": row.delivery_type, "result": row.result, "response": row.response_summary} for row in rows]})


@csrf_exempt
@require_http_methods(["POST"])
def integration_delivery_retry(request, integration_id: str, delivery_id: str):
    denied = require_permission(request, "integrations", resource_type="IntegrationDelivery", resource_id=delivery_id)
    if denied:
        return denied
    connection = IntegrationConnection.objects.filter(id=integration_id).first()
    delivery = IntegrationDelivery.objects.filter(id=delivery_id, integration=connection).first()
    if not connection or not delivery:
        raise Http404("Integration delivery not found")
    retried = _deliver_webhook(connection, delivery.payload_json, delivery.delivery_type, case=delivery.case)
    return JsonResponse({"deliveryId": retried.id, "result": retried.result, "response": retried.response_summary}, status=200 if retried.result == "success" else 502)


def _deliver_webhook(connection: IntegrationConnection, payload: dict, delivery_type: str, case: Case | None = None) -> IntegrationDelivery:
    url = str(connection.config.get("url", "")).strip()
    if not url:
        return IntegrationDelivery.objects.create(integration=connection, case=case, delivery_type=delivery_type, payload_json=payload, result="failed", response_summary="Webhook URL is not configured.")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    credential = getattr(connection, "credential", None)
    secret = credential.secret_value if credential else ""
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest() if secret else ""
    headers = {"Content-Type": "application/json", "User-Agent": "Netra/phase5"}
    if signature:
        headers["X-Netra-Signature"] = signature
    summary = ""
    result = "failed"
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method="POST"), timeout=5) as response:
                preview = response.read(200).decode("utf-8", errors="replace").strip()
                summary = f"HTTP {response.status}" + (f" {preview}" if preview else "")
                result = "success" if 200 <= response.status < 300 else "failed"
            if result == "success":
                break
        except urllib.error.HTTPError as exc:
            summary = f"HTTP {exc.code}"
        except Exception as exc:
            summary = f"{type(exc).__name__}: {exc}"
        if attempt < 3:
            time.sleep(0.25 * attempt)
    return IntegrationDelivery.objects.create(integration=connection, case=case, delivery_type=delivery_type, payload_json=payload, result=result, response_summary=summary)


@csrf_exempt
@require_http_methods(["POST"])
def siem_export(request):
    denied = require_permission(request, "export", resource_type="SIEMExport")
    if denied:
        return denied
    actor = actor_from_request(request)
    payload = _json_body(request)
    case_id = payload.get("caseId") or _analysis().get("caseId", "")
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    analysis = _analysis(case_id=case_id)
    lines = [
        f"CEF:0|Netra|Network Forensics|3|{alert.get('ruleId','netra-alert')}|{alert.get('attackClass')}|{alert.get('confidence')}|src={alert.get('sourceIp')} dst={alert.get('destination')} cs1={case_id} cs1Label=caseId"
        for alert in analysis.get("alerts", [])
    ]
    export_id = f"siem-{uuid4().hex[:8]}"
    artifact = write_text_artifact("\n".join(lines) or "CEF:0|Netra|Network Forensics|3|baseline|No critical alerts|0|", "export", f"{export_id}.cef")
    record_export(case_id, export_id, "cef", artifact, actor)
    record_custody_event(case, actor, "SIEM CEF export generated", {"exportId": export_id, "filename": artifact["filename"], "sha256": artifact["sha256"]}, resource_type="Export", resource_id=export_id)
    return JsonResponse({"id": export_id, "caseId": case_id, "status": "ready", "downloadUrl": f"/api/exports/{export_id}/download", **artifact}, status=201)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def integration_case_link(request):
    if request.method == "POST":
        payload = _json_body(request)
        publish_event("netra.case.events", {"type": "case.integration_linked", "payload": payload})
        return JsonResponse({"status": "linked", **payload}, status=201)
    return JsonResponse({"results": [], "syncStatus": "not-linked"})


def integration_case_link_detail(_request, case_id: str):
    return JsonResponse({"caseId": case_id, "reportedCaseId": "", "syncStatus": "not-linked"})


def compliance_checklist(_request):
    rows = list(ComplianceControl.objects.order_by("item"))
    if rows:
        return JsonResponse({"results": [{"item": row.item, "status": row.status, "detail": row.detail} for row in rows]})
    return JsonResponse({"results": []})


def compliance_roles(_request):
    return JsonResponse(
        {
            "status": "enabled" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else "development",
            "detail": "Supabase Auth identities are mapped to Netra server-side roles. Roles are enforced on protected backend actions.",
            "results": [
                {"role": "Admin", "permissions": ["upload", "review", "confirm", "report", "export", "view", "compliance", "manage_users", "integrations", "operations"]},
                {"role": "Investigator", "permissions": ["upload", "review", "confirm", "report", "export", "view", "compliance"]},
                {"role": "Analyst", "permissions": ["upload", "review", "view"]},
                {"role": "Viewer", "permissions": ["view"]},
            ],
        }
    )


def security_posture(_request):
    security = _probe_security()
    return JsonResponse(
        {
            "encryptionAtRest": "ready" if security["status"] in {"ok", "degraded"} else "blocked",
            "rbac": security["rbac"],
            "authentication": "supabase-auth" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else "development",
            "accessMode": getattr(settings, "NETRA_ACCESS_MODE", "role-headers"),
            "publicInternet": "not-configured",
            "sensorSecurity": "installation-shared-key",
            "auditLogs": "enabled",
            "serviceRoleBackendOnly": True,
            "serviceRoleConfigured": security["serviceRoleConfigured"],
            "devRoleHeaders": security["devRoleHeaders"],
            "adminProfiles": security["adminProfiles"],
            "status": security["status"],
            "detail": security["detail"],
            "standardsAlignment": "digital evidence workflow",
        }
    )


def access_logs(_request):
    rows = AccessLog.objects.order_by("-created_at")[:100]
    if rows:
        return JsonResponse({"results": [access_log_dict(row) for row in rows]})
    return JsonResponse({"results": []})


def audit_export(request):
    case_id = request.GET.get("caseId", "")
    case = Case.objects.filter(id=case_id).first() if case_id else None
    denied = require_permission(request, "compliance", case=case, resource_type="AuditExport", resource_id=case_id or "system")
    if denied:
        return denied
    actor = actor_from_request(request)
    if case:
        record_custody_event(case, actor, "Audit export generated", {"scope": "case", "caseId": case.id}, resource_type="AuditExport", resource_id=case.id)
    log_access(actor, "audit.export", case=case, resource_type="AuditExport", resource_id=case_id or "system")
    return JsonResponse(audit_export_payload(case))
