"""Compliance, custody, access-log, and audit endpoints."""

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
    _json_body,
    _paged,
    _probe_security,
)


def custody_ledger(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    denied = require_permission(request, "compliance", case=case, resource_type="CustodyLedger", resource_id=case_id)
    if denied:
        return denied
    rows = [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("-chain_index")]
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
    payload = {"caseId": case_id, "verification": verify_case_ledger(case), "events": [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("chain_index")]}
    return JsonResponse(payload)


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


def access_logs(request):
    actor = actor_from_request(request)
    rows = AccessLog.objects.filter(organization_id=actor.organization_id)
    if actor.role != "Admin":
        visible_case_ids = visible_cases_for_actor(actor).values_list("id", flat=True)
        rows = rows.filter(Q(case_id__in=visible_case_ids) | Q(case__isnull=True, user_id=actor.django_user_id))
    rows = rows.order_by("-created_at")[:100]
    if rows:
        return JsonResponse({"results": [access_log_dict(row) for row in rows]})
    return JsonResponse({"results": []})


def audit_export(request):
    case_id = request.GET.get("caseId", "")
    actor = actor_from_request(request)
    case = visible_cases_for_actor(actor).filter(id=case_id).first() if case_id else None
    if case_id and not case:
        raise Http404("Resource not found")
    if not case_id and actor.role != "Admin":
        return JsonResponse({"error": "A visible case is required.", "code": "case_scope_required"}, status=400)
    denied = require_permission(request, "compliance", case=case, resource_type="AuditExport", resource_id=case_id or "system")
    if denied:
        return denied
    if case:
        record_custody_event(case, actor, "Audit export generated", {"scope": "case", "caseId": case.id}, resource_type="AuditExport", resource_id=case.id)
    log_access(actor, "audit.export", case=case, resource_type="AuditExport", resource_id=case_id or "system")
    return JsonResponse(audit_export_payload(case, organization_id=actor.organization_id))
