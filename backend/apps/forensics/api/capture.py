"""Capture, sensor, schedule, and retention endpoints."""

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
    _schedule_values,
    _storage_configuration_response,
    _storage_failure_response,
)


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
    try:
        case_id = validate_case_id(payload["caseId"]) if payload.get("caseId") is not None else validate_case_id(f"CYB-GJ-LIVE-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    except InvalidCaseId as exc:
        return JsonResponse({"error": str(exc), "code": "invalid_case_id"}, status=400)
    case = ensure_capture_case(case_id)
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
    if not job_id:
        return api_error(
            request,
            "scope_required",
            "Use the workspace-scoped capture stop URL.",
            status=400,
        )
    job = CaptureJob.objects.filter(id=job_id).first()
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
    return api_error(request, "feature_not_implemented", "Durable capture-log import is not installed.", status=501)


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
        case_id = validate_case_id(request.POST["caseId"]) if request.POST.get("caseId") is not None else validate_case_id(f"CYB-GJ-REPLAY-{datetime.now().strftime('%Y%m%d%H%M%S')}")
        saved = save_uploaded_file(upload, "capture_chunk")
        Path(saved["analysis_path"]).unlink(missing_ok=True)
    except (OverflowError, TypeError, ValueError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except RuntimeError as exc:
        if "Evidence storage is not configured" in str(exc) or "Supabase Storage" in str(exc):
            return _storage_configuration_response()
        return _storage_failure_response()
    case = ensure_capture_case(case_id)
    job = create_capture_job(case=case, mode=CaptureJob.Mode.REPLAY, duration_seconds=duration, packet_limit=packet_limit, chunk_interval_seconds=chunk_interval, source_label=f"Replay: {upload.name}")
    start_replay(job, saved["stored_path"], request.POST.get("speed", "max"))
    return JsonResponse(capture_job_payload(job), status=201)


@csrf_exempt
@require_http_methods(["POST"])
def capture_replay_stop(request, job_id: str | None = None):
    if not job_id:
        return api_error(
            request,
            "scope_required",
            "Use the workspace-scoped capture stop URL.",
            status=400,
        )
    job = CaptureJob.objects.filter(id=job_id).first()
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
@require_http_methods(["POST"])
def zeek_log_import(request):
    return api_error(request, "feature_not_implemented", "Durable Zeek-log import is not installed.", status=501)
