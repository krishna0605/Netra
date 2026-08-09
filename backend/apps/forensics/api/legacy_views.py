"""Deprecated compatibility adapters pending telemetry-based Phase 11 removal."""

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

from apps.forensics.models import AccessLog, Alert, CaptureJob, CaptureSchedule, Case, CaseAnalysisSnapshot, CaseLink, CaseMembership, ComplianceControl, CustodyLedgerEvent, DeadLetterEvent, EvidenceFile, EvidenceManifest, EvidenceUploadSession, Export, IntegrationConnection, IntegrationDelivery, OperationalEvent, ProcessingJob, Report, RetentionPolicy, RetentionRun, Sensor, SensorCommand, SensorGroup, SensorHealthSnapshot, SessionSummary, UserProfile, WorkerHeartbeat
from apps.forensics.services.administration import AdministrationProblem, require_privileged_admin
from apps.forensics.services.integration_credentials import store_integration_secret
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
    _deliver_webhook,
    _integration_dict,
    _json_body,
    _specialized_rate_limit,
)


def operational_event_stream(request):
    from apps.forensics.api.events import event_stream

    return event_stream(request)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def integrations(request):
    actor = actor_from_request(request)
    if request.method == "POST":
        denied = require_permission(request, "integrations", resource_type="IntegrationConnection")
        if denied:
            return denied
        try:
            require_privileged_admin(actor, actor.organization_id)
        except AdministrationProblem as problem:
            return api_error(request, problem.code, problem.message, status=problem.status)
        payload = _json_body(request)
        connection, _ = IntegrationConnection.objects.update_or_create(
            organization_id=actor.organization_id,
            system_name=payload.get("systemName", "Local webhook"),
            defaults={
                "status": "pending",
                "api_mode": payload.get("mode", "webhook-json"),
                "config": {key: value for key, value in payload.items() if key != "secret"},
            },
        )
        if payload.get("secret"):
            store_integration_secret(connection, str(payload["secret"]), label="webhook-hmac")
        return JsonResponse(_integration_dict(connection), status=201)
    rows = [
        _integration_dict(row)
        for row in IntegrationConnection.objects.filter(organization_id=actor.organization_id).order_by("system_name")
    ]
    return JsonResponse({"results": rows})


@csrf_exempt
@require_http_methods(["POST"])
def integration_sync(request, integration_id: str):
    return api_error(request, "feature_not_implemented", "No reviewed external synchronization adapter is installed.", status=501)


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
    limited = _specialized_rate_limit(request, "webhook-test", settings.NETRA_RATE_LIMIT_WEBHOOK_TEST_ADMIN_PER_HOUR)
    if limited:
        return limited
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
    case_id = str(payload.get("caseId") or "").strip()
    if not case_id:
        return JsonResponse({"error": "caseId is required.", "code": "analysis_scope_required"}, status=400)
    analysis = _case_scoped_analysis(case_id=case_id)
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


@csrf_exempt
@require_http_methods(["GET", "POST"])
def integration_case_link(request):
    return api_error(request, "feature_not_implemented", "Durable integration case links are not installed.", status=501)


def integration_case_link_detail(request, case_id: str):
    return api_error(request, "feature_not_implemented", "Durable integration case links are not installed.", status=501)
