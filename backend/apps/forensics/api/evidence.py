"""Evidence intake, manifest, integrity, and download endpoints."""

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
    _analysis_filter_error,
    _case_scoped_analysis,
    _normalization_error_response,
    _specialized_rate_limit,
    _storage_configuration_response,
    _storage_failure_response,
    _upload_session_problem_response,
)
from apps.forensics.api.reports import (
    exports,
)


def case_linked_evidence(_request, case_id: str):
    analysis = _case_scoped_analysis(case_id=case_id)
    exports = [{"id": row.id, "type": row.export_type, "caseId": case_id, "requestedBy": row.requested_by, "timestamp": row.created_at.isoformat(), "hash": row.sha256, "status": row.status} for row in Export.objects.filter(case_id=case_id).order_by("-created_at")]
    return JsonResponse({"caseId": case_id, "packets": analysis.get("packets", [])[:20], "sessions": analysis.get("sessions", []), "payloads": analysis.get("payloadFindings", []), "exports": exports})


@csrf_exempt
@require_http_methods(["POST"])
def evidence_normalize_preview(request):
    denied = require_permission(request, "upload", resource_type="EvidenceFile")
    if denied:
        return denied
    upload = request.FILES.get("file")
    if not upload:
        return JsonResponse({"error": "file is required"}, status=400)
    if upload.size > NORMALIZATION_PREVIEW_BYTES:
        return JsonResponse(
            {
                "error": "Normalization preview is limited to the first 64 KiB.",
                "code": "normalization_preview_too_large",
                "maximumBytes": NORMALIZATION_PREVIEW_BYTES,
            },
            status=413,
        )
    normalization = normalize_evidence_upload(upload, request.POST.get("evidenceType")).to_dict()
    return JsonResponse(normalization)


@csrf_exempt
@require_http_methods(["POST"])
def evidence_upload_sessions(request):
    denied = require_permission(request, "upload", resource_type="EvidenceUploadSession")
    if denied:
        return denied
    limited = _specialized_rate_limit(
        request,
        "upload-session",
        settings.NETRA_RATE_LIMIT_UPLOAD_USER_PER_HOUR,
        organization_limit=settings.NETRA_RATE_LIMIT_UPLOAD_ORG_PER_HOUR,
    )


@require_http_methods(["GET"])
def evidence_upload_session_detail(request, upload_session_id):
    denied = require_permission(request, "view", resource_type="EvidenceUploadSession", resource_id=str(upload_session_id))
    if denied:
        return denied
    try:
        return JsonResponse(upload_session_payload(get_upload_session(actor_from_request(request), upload_session_id)))
    except UploadSessionProblem as problem:
        return _upload_session_problem_response(problem)


@csrf_exempt
@require_http_methods(["POST"])
def evidence_upload_session_finalize(request, upload_session_id):
    denied = require_permission(request, "upload", resource_type="EvidenceUploadSession", resource_id=str(upload_session_id))
    if denied:
        return denied
    try:
        session = finalize_upload_session(actor_from_request(request), upload_session_id)
        return JsonResponse(upload_session_payload(session))
    except UploadSessionProblem as problem:
        return _upload_session_problem_response(problem)


@csrf_exempt
@require_http_methods(["POST"])
def evidence_upload(request):
    denied = require_permission(request, "upload", resource_type="EvidenceFile")
    if denied:
        return denied
    actor = actor_from_request(request)
    upload = request.FILES.get("file")
    if not upload:
        return JsonResponse({"error": "file is required"}, status=400)
    try:
        case_id = validate_case_id(request.POST["caseId"]) if request.POST.get("caseId") is not None else generate_case_id()
    except InvalidCaseId as exc:
        return JsonResponse({"error": str(exc), "code": "invalid_case_id"}, status=400)
    raw_idempotency_key = (request.headers.get("Idempotency-Key") or request.POST.get("idempotencyKey") or "").strip()
    if len(raw_idempotency_key) > 128:
        return JsonResponse({"error": "Idempotency key is too long.", "code": "invalid_idempotency_key"}, status=400)
    actor_scope = actor.external_id or str(actor.django_user_id or actor.user)
    idempotency_key = sha256_text(f"{actor_scope}:{raw_idempotency_key}") if raw_idempotency_key else None
    if idempotency_key:
        existing_job = ProcessingJob.objects.select_related("case", "evidence_file").filter(idempotency_key=idempotency_key).first()
        if existing_job:
            if existing_job.case_id != case_id:
                return JsonResponse({"error": "Idempotency key was already used for another case.", "code": "idempotency_conflict"}, status=409)
            if not can_actor_access_case(actor, existing_job.case):
                raise Http404("Job not found")
            evidence = existing_job.evidence_file
            manifest = getattr(evidence, "manifest", None) if evidence else None
            completed = existing_job.status == ProcessingJob.Status.COMPLETED
            return JsonResponse(
                {
                    "id": evidence.id if evidence else "",
                    "caseId": existing_job.case_id,
                    "routeRef": str(existing_job.case.route_ref),
                    "jobId": existing_job.id,
                    "status": "verified" if completed else "queued",
                    "processingPath": existing_job.processing_path,
                    "job": job_status_payload(existing_job),
                    "analysis": (existing_job.stats or {}).get("summary", {}),
                    "sha256": evidence.sha256 if evidence else "",
                    "encrypted_sha256": manifest.encrypted_sha256 if manifest else "",
                    "keyId": manifest.key_id if manifest else settings.NETRA_EVIDENCE_KEY_ID,
                    "idempotentReplay": True,
                },
                status=200 if completed else 202,
            )
    requested_bpf = (request.POST.get("bpfFilter") or "").strip()
    if requested_bpf and not settings.NETRA_BPF_FILTER_ENABLED:
        return JsonResponse(
            {
                "error": "Expert BPF filtering is not enabled in this deployment.",
                "code": "bpf_filter_unavailable",
                "detail": "Use the source, destination, protocol, port, duration, and packet-limit filters, or leave BPF blank.",
            },
            status=400,
        )
    normalization_result = normalize_evidence_upload(upload, request.POST.get("evidenceType"))
    normalization = normalization_result.to_dict()
    if not normalization_result.valid:
        return _normalization_error_response(normalization)
    filter_error = _analysis_filter_error(request, normalization_result.normalized_type, requested_bpf)
    if filter_error:
        return filter_error
    if not analysis_admission_available():
        return JsonResponse(
            {"error": "Analysis capacity is temporarily unavailable.", "code": "analysis_capacity_unavailable"},
            status=503,
        )
    try:
        intake_flags = json.loads(request.POST.get("flags") or "[]")
        approved_flags = validated_case_flags(intake_flags)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Case flags must be a valid JSON array.", "code": "invalid_case_flags", "allowedFlags": list(ALLOWED_CASE_FLAGS)}, status=400)
    except InvalidCaseFlags as exc:
        return JsonResponse({"error": str(exc), "code": "invalid_case_flags", "allowedFlags": list(ALLOWED_CASE_FLAGS)}, status=400)
    evidence_id = f"ev-{uuid4().hex[:8]}"
    job_id = f"job-{uuid4().hex[:8]}"
    try:
        saved = save_uploaded_file(
            upload,
            "pcap" if normalization_result.normalized_type == EvidenceFile.EvidenceType.PCAP else "structured",
            evidence_id=evidence_id,
            case_id=case_id,
        )
    except OverflowError as exc:
        return JsonResponse({"error": str(exc)}, status=413)
    except ValueError as exc:
        message = str(exc)
        status = 422 if "valid PCAP" in message or "Mixed-evidence" in message else 400
        return JsonResponse({"error": message}, status=status)
    except RuntimeError as exc:
        if "Evidence storage is not configured" in str(exc) or "Supabase Storage" in str(exc):
            return _storage_configuration_response()
        return _storage_failure_response()
    investigator, department = server_case_identity(actor)
    saved["intake"] = {
        "investigator": investigator,
        "department": department,
        "selectedEvidenceType": normalization_result.selected_type,
        "evidenceType": normalization_result.normalized_type,
        "sourceLocation": (request.POST.get("sourceLocation") or "").strip(),
        "priority": (request.POST.get("priority") or "Standard").strip(),
        "remarks": (request.POST.get("remarks") or "").strip(),
        "flags": approved_flags,
        "origin": Case.Origin.OFFICER_UPLOAD,
        "sourceIp": (request.POST.get("sourceIp") or "").strip(),
        "destinationIp": (request.POST.get("destinationIp") or "").strip(),
        "protocol": (request.POST.get("protocol") or "").strip().upper(),
        "port": (request.POST.get("port") or "").strip(),
        "durationSeconds": (request.POST.get("durationSeconds") or "").strip(),
        "packetLimit": (request.POST.get("packetLimit") or "").strip(),
        "bpfFilter": requested_bpf,
    }
    saved["normalization"] = normalization
    public_saved = {key: value for key, value in saved.items() if key not in {"analysis_path", "v2_manifest"}}
    client_saved = {
        key: public_saved[key]
        for key in ("filename", "size_bytes", "sha256", "plaintext_sha256", "encrypted_sha256", "normalization")
        if key in public_saved
    } | {"keyId": settings.NETRA_EVIDENCE_KEY_ID}
    try:
        job = queue_uploaded_evidence(saved, case_id, evidence_id, job_id, actor, idempotency_key=idempotency_key)
    except OrganizationQueueLimit:
        response = JsonResponse(
            {"error": "The organization analysis queue is full.", "code": "organization_queue_limit"},
            status=429,
        )
        response["Retry-After"] = "60"
        return response
    finally:
        if saved.get("analysis_path"):
            Path(saved["analysis_path"]).unlink(missing_ok=True)
    return JsonResponse({"id": evidence_id, "caseId": case_id, "routeRef": str(job.case.route_ref), "jobId": job_id, "status": "queued", "processingPath": "postgres-worker", "job": job_status_payload(job), **client_saved}, status=202)


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
    if evidence.stored_path.endswith("/manifest.v2.json"):
        v2_verification = verify_evidence_v2(evidence.stored_path)
        encrypted_hash = v2_verification.get("encryptedStorageHash", "")
        encrypted_verified = bool(v2_verification.get("verified") and encrypted_hash == manifest.encrypted_sha256)
    else:
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
    temporary = Path(temporary_decrypted_copy(evidence.stored_path))
    response = FileResponse(
        temporary.open("rb"),
        as_attachment=True,
        filename=Path(evidence.filename).name,
        content_type="application/vnd.tcpdump.pcap" if evidence.evidence_type == EvidenceFile.EvidenceType.PCAP else "application/octet-stream",
    )
    original_close = response.close

    def close_and_remove() -> None:
        try:
            original_close()
        finally:
            temporary.unlink(missing_ok=True)

    response.close = close_and_remove
    return response
