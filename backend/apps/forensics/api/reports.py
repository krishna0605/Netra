"""Report and export endpoints."""

import json
import logging
import os
import hashlib
import ipaddress
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection, transaction
from django.db.models import Exists, F, OuterRef, Prefetch, Q, Sum
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AccessLog, Alert, CaptureJob, CaptureSchedule, Case, CaseAnalysisSnapshot, CaseLink, CaseMembership, ComplianceControl, CustodyLedgerEvent, DeadLetterEvent, EvidenceFile, EvidenceManifest, EvidenceUploadSession, Export, IntegrationConnection, IntegrationCredential, IntegrationDelivery, OperationalEvent, ProcessingJob, Report, RetentionPolicy, RetentionRun, Sensor, SensorCommand, SensorGroup, SensorHealthSnapshot, SessionSummary, UserProfile, WorkerHeartbeat
from apps.forensics.services.webhook_delivery import queue_delivery
from common.audit import access_log_dict, actor_from_request, add_history, can_actor_access_case, log_access, require_permission, visible_cases_for_actor
from common.case_metadata import ALLOWED_CASE_FLAGS, InvalidCaseFlags, server_case_identity, validated_case_flags
from common.analysis_contract import empty_analysis
from common.bpf import validate_bpf_syntax
from common.artifacts import generate_export_artifact, generate_pdf_report_artifact, generate_report_artifact, report_analysis_from_snapshot
from common.job_admission import queue_uploaded_evidence
from common.case_workspace import analysis_status_for_case, bump_case_list_cache_version, case_list_cache_version, workspace_for_case, workspace_status_payload
from common.custody import custody_event_dict, record_custody_event, verify_case_ledger
from common.detection import classify_detection, load_rules
from common.evidence_normalization import NORMALIZATION_PREVIEW_BYTES, normalize_evidence_upload
from common.capabilities import public_capabilities
from apps.forensics.api.errors import api_error
from common.jobs import job_status_payload
from common.kafka import probe_supabase_queue, publish_event
from common.queue_limits import OrganizationQueueLimit
from common.rate_limit_middleware import rate_limit_response
from common.rate_limits import RateLimitSpec, consume_rate_limits, request_byte_count
from common.persistence import VALIDATOR_CASE_PREFIXES, analysis_for_case, latest_job_for_case, record_export
from common.postgres_jobs import request_job_cancellation, retry_job
from common.readiness import audit_export_payload, deployment_readiness_payload, incident_readiness_payload, legal_review_checklist, ml_model_status_payload, status_matrix_payload, storage_cache_status_payload
from common.hashing import sha256_file, sha256_text
from common.identifiers import InvalidCaseId, generate_case_id, validate_case_id
from common.fleet import backpressure_allows_new_capture, capacity_payload, ensure_default_retention_policy, execute_safe_retention, kafka_lag_payload, queue_schedule_run, retention_policy_payload, retention_preview, retention_run_payload, schedule_payload, sensor_group_payload
from common.operations import capture_job_payload, create_capture_job, emit_operational_event, ensure_capture_case, expire_stale_replay, finalize_capture, heartbeat_state, ingest_capture_chunk, mark_capture_running, sensor_key_valid, sensor_payload, start_replay, stop_capture, validate_capture_bounds, worker_payload
from common.storage_provider import storage_provider
from common.storage import save_uploaded_file, write_text_artifact
from common.safe_paths import generated_artifact_filename
from common.tenancy import netra_organization
from common.upload_sessions import UploadSessionProblem, create_upload_session, finalize_upload_session, get_upload_session, upload_session_payload
from common.vault import fernet, open_decrypted_artifact, temporary_decrypted_copy
from common.vault_v2 import verify_evidence_v2
from common.worker_capacity import analysis_admission_available, compatible_analysis_worker_available


logger = logging.getLogger(__name__)

from apps.forensics.api.legacy_support import (
    _case_scoped_analysis,
    _json_body,
    _paged,
    _report_dict,
    _specialized_rate_limit,
)


def report_preview(request, case_id: str):
    language = request.GET.get("language", "en")
    analysis = _case_scoped_analysis(case_id=case_id)
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
            "toolStatus": analysis.get("toolStatus", {}),
            "chainOfCustody": analysis.get("chainOfCustody", []),
            "custodyLedger": custody,
            "legalReview": legal_review_checklist(case) if case else {},
            "timeline": analysis.get("trafficTimeline", []),
            "graph": analysis.get("graph", {}),
        }
    )


def reports(request):
    actor = actor_from_request(request)
    rows = Report.objects.filter(case__in=visible_cases_for_actor(actor)).select_related("case").order_by("-created_at")
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
            test_query |= Q(case__id__startswith=prefix)
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
    case = Case.objects.select_related("analysis_snapshot").filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "report", case=case, resource_type="Report", resource_id=case_id)
    if denied:
        return denied
    limited = _specialized_rate_limit(request, "report-generate", settings.NETRA_RATE_LIMIT_REPORT_USER_PER_HOUR)
    if limited:
        return limited
    analysis_status = analysis_status_for_case(case)
    if not analysis_status["reportEligible"]:
        return JsonResponse(
            {
                "error": analysis_status["reportBlockedReason"],
                "code": "analysis_not_complete",
                "analysisStatus": analysis_status,
            },
            status=409,
        )
    actor = actor_from_request(request)
    payload = _json_body(request)
    language = payload.get("language", "en")
    report_format = (payload.get("format") or "html").lower()
    analysis = report_analysis_from_snapshot(case) or _case_scoped_analysis(case_id=case_id)
    if getattr(settings, "NETRA_SUPABASE_START_WORKERS", False) and payload.get("queued"):
        extension = "pdf" if report_format == "pdf" else "html"
        report_id = generated_artifact_filename("rpt", f".{extension}")
        if case:
            Report.objects.update_or_create(
                id=report_id,
                defaults={"case": case, "language": language, "generated_by": actor.user, "status": "queued", "stored_path": "", "sha256": ""},
            )
        publish_event(
            "netra.export.requests",
            {
                "type": "report.generate",
                "caseId": case_id,
                "language": language,
                "format": report_format,
                "reportId": report_id,
                "actor": actor.user,
            },
        )
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
    return FileResponse(
        open_decrypted_artifact(report.stored_path),
        as_attachment=True,
        filename=filename,
        content_type=content_type,
    )


@csrf_exempt
@require_http_methods(["GET", "POST"])
def exports(request):
    if request.method == "POST":
        denied = require_permission(request, "export", resource_type="Export")
        if denied:
            return denied
        limited = _specialized_rate_limit(request, "export-generate", settings.NETRA_RATE_LIMIT_EXPORT_USER_PER_HOUR)
        if limited:
            return limited
        actor = actor_from_request(request)
        payload = _json_body(request)
        case_id = str(payload.get("caseId") or request.GET.get("caseId") or "").strip()
        if not case_id:
            return JsonResponse({"error": "caseId is required.", "code": "analysis_scope_required"}, status=400)
        case = Case.objects.filter(id=case_id).first()
        if not case:
            raise Http404("Case not found")
        denied = require_permission(request, "export", case=case, resource_type="Export", resource_id=case_id)
        if denied:
            return denied
        analysis = _case_scoped_analysis(case_id=case_id)
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
    queryset = Export.objects.filter(case__in=visible_cases_for_actor(actor_from_request(request))).select_related("case").order_by("-created_at")
    if case_id:
        queryset = queryset.filter(case_id=case_id)
    if request.GET.get("includeTest") not in {"1", "true", "yes"}:
        test_query = Q(case__is_test=True) | Q(case__origin__in=[Case.Origin.VALIDATOR, Case.Origin.SYSTEM_TEST])
        for prefix in VALIDATOR_CASE_PREFIXES:
            test_query |= Q(case__id__startswith=prefix)
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
    return FileResponse(
        open_decrypted_artifact(export.stored_path),
        as_attachment=True,
        filename=filename,
        content_type="application/octet-stream",
    )


@csrf_exempt
@require_http_methods(["POST"])
def siem_export(request):
    denied = require_permission(request, "export", resource_type="SIEMExport")
    if denied:
        return denied
    actor = actor_from_request(request)
    payload = _json_body(request)
    case_id = str(payload.get("caseId") or "").strip()
    if not case_id:
        return JsonResponse({"error": "caseId is required.", "code": "analysis_scope_required"}, status=400)
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    analysis = _case_scoped_analysis(case_id=case_id)
    lines = [
        f"CEF:0|Netra|Network Forensics|3|{alert.get('ruleId','netra-alert')}|{alert.get('attackClass')}|{alert.get('confidence')}|src={alert.get('sourceIp')} dst={alert.get('destination')} cs1={case_id} cs1Label=caseId"
        for alert in analysis.get("alerts", [])
    ]
    export_id = f"siem-{uuid4().hex[:8]}"
    artifact = write_text_artifact(
        "\n".join(lines) or "CEF:0|Netra|Network Forensics|3|baseline|No critical alerts|0|",
        "export",
        f"{export_id}.cef",
        case_id=case.id,
        artifact_id=export_id,
    )
    record_export(case_id, export_id, "cef", artifact, actor)
    record_custody_event(case, actor, "SIEM CEF export generated", {"exportId": export_id, "filename": artifact["filename"], "sha256": artifact["sha256"]}, resource_type="Export", resource_id=export_id)
    return JsonResponse({"id": export_id, "caseId": case_id, "status": "ready", "downloadUrl": f"/api/exports/{export_id}/download", **artifact}, status=201)
