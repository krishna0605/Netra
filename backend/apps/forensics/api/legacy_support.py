"""Private helpers shared by feature-owned compatibility endpoints."""

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


def _json_body(request) -> dict:
    if not request.body:
        return {}
    return json.loads(request.body.decode("utf-8"))


def _specialized_rate_limit(request, route_key: str, user_limit: int, *, organization_limit: int | None = None):
    if not settings.NETRA_RATE_LIMITS_ENABLED:
        return None
    actor = actor_from_request(request)
    specs = [RateLimitSpec(route_key, user_limit, 3600)]
    if organization_limit:
        specs.append(RateLimitSpec(route_key, organization_limit, 3600, scope="organization"))
    result = consume_rate_limits(actor, specs, byte_count=request_byte_count(request))
    return None if result.allowed else rate_limit_response(result)


def _paged(rows: list[dict], request) -> dict:
    try:
        limit = max(1, min(500, int(request.GET.get("limit", "100"))))
        offset = max(0, int(request.GET.get("offset", "0")))
    except ValueError:
        limit, offset = 100, 0
    sliced = rows[offset : offset + limit]
    next_offset = offset + limit if offset + limit < len(rows) else None
    return {"count": len(rows), "limit": limit, "offset": offset, "nextOffset": next_offset, "results": sliced}


def _case_scoped_analysis(*, case_id: str) -> dict:
    """Load analysis for one already-authorized case.

    The case identifier is keyword-only and mandatory. A blank identifier used
    to make this helper scan whichever case happened to be most recently
    updated, which would reintroduce cross-case disclosure.
    """
    resolved = (case_id or "").strip()
    if not resolved:
        raise Http404("An analysis case is required.")
    return analysis_for_case(resolved) or empty_analysis()


def _is_probable_validator_case(case: Case) -> bool:
    if case.is_test or case.origin in {Case.Origin.VALIDATOR, Case.Origin.SYSTEM_TEST}:
        return True
    if any(case.id.startswith(prefix) for prefix in VALIDATOR_CASE_PREFIXES):
        return True
    investigator = (case.investigator or "").lower()
    return "validator" in investigator or "readiness" in investigator


def _visible_cases_queryset(request):
    rows = visible_cases_for_actor(actor_from_request(request)).order_by("-updated_at")
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
    analysis_status = analysis_status_for_case(case)
    return {
        "id": case.id,
        "displayReference": case.display_reference,
        "organizationId": str(case.organization_id),
        "routeRef": str(case.route_ref),
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
        "analysisStatus": analysis_status,
        "reportEligible": analysis_status["reportEligible"],
        "reportBlockedReason": analysis_status["reportBlockedReason"],
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
    snapshot_case = {
        "evidenceFileId": getattr(case, "_snapshot_evidence_file_id", "") or "",
        "evidenceFilename": getattr(case, "_snapshot_evidence_filename", "") or "",
        "alertIds": getattr(case, "_snapshot_alert_ids", []) or [],
        "latestReportId": getattr(case, "_snapshot_latest_report_id", "") or "",
        "latestReportDownloadUrl": getattr(case, "_snapshot_latest_report_url", "") or "",
    }
    snapshot_summary = {
        "riskLevel": getattr(case, "_snapshot_risk_level", "") or "",
        "topAttackClass": getattr(case, "_snapshot_top_attack_class", "") or "",
        "alerts": getattr(case, "_snapshot_alert_count", 0) or 0,
        "packets": getattr(case, "_snapshot_packet_count", 0) or 0,
        "sessions": getattr(case, "_snapshot_session_count", 0) or 0,
    }
    latest_report = snapshot_case.get("latestReportId") or ""
    analysis_status = analysis_status_for_case(case)
    return {
        "id": case.id,
        "displayReference": case.display_reference,
        "organizationId": str(case.organization_id),
        "routeRef": str(case.route_ref),
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
        "analysisStatus": analysis_status,
        "reportEligible": analysis_status["reportEligible"],
        "reportBlockedReason": analysis_status["reportBlockedReason"],
        "riskLevel": snapshot_summary.get("riskLevel") or snapshot_case.get("riskLevel") or "low",
        "topAttackClass": snapshot_summary.get("topAttackClass") or snapshot_case.get("topAttackClass") or "Normal Baseline",
        "alertCount": snapshot_summary.get("alerts", 0),
        "packetCount": snapshot_summary.get("packets", 0),
        "sessionCount": snapshot_summary.get("sessions", 0),
        "latestReportId": latest_report,
        "latestReportDownloadUrl": snapshot_case.get("latestReportDownloadUrl", ""),
        "updatedAt": case.updated_at.isoformat(),
    }


def _admin_count() -> int:
    User = get_user_model()
    admin_profile_ids = set(UserProfile.objects.filter(role="Admin").values_list("user_id", flat=True))
    superuser_ids = set(User.objects.filter(is_superuser=True).values_list("id", flat=True))
    return len(admin_profile_ids | superuser_ids)


def _alert_timeline(alerts: list[dict]) -> list[dict]:
    buckets: dict[str, dict] = {}
    for row in alerts:
        raw_time = str(row.get("timestamp") or "")
        label = raw_time[11:16] if "T" in raw_time else raw_time[:5] or "time"
        bucket = buckets.setdefault(label, {"time": label, "alerts": 0, "mb": 0, "packets": 0})
        bucket["alerts"] += 1
    return list(buckets.values())[:24]


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


def _analysis_filter_error(request, normalized_type: str, requested_bpf: str) -> JsonResponse | None:
    try:
        for field in ("sourceIp", "destinationIp"):
            value = (request.POST.get(field) or "").strip()
            if value:
                ipaddress.ip_address(value)
        protocol = (request.POST.get("protocol") or "").strip().upper()
        if protocol and protocol not in {"DNS", "TLS", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "SMB", "TCP", "UDP", "ICMP"}:
            raise ValueError("Protocol filter is not supported.")
        for field, maximum in (("port", 65535), ("durationSeconds", 86400), ("packetLimit", settings.NETRA_PACKET_INDEX_CAP)):
            raw = (request.POST.get(field) or "").strip()
            if not raw:
                continue
            value = int(raw)
            if value < 1 or value > maximum:
                raise ValueError(f"{field} must be between 1 and {maximum}.")
        if requested_bpf:
            if normalized_type != EvidenceFile.EvidenceType.PCAP:
                raise ValueError("BPF filters can only be applied to PCAP or PCAPNG evidence.")
            validate_bpf_syntax(requested_bpf)
    except (TypeError, ValueError, RuntimeError) as exc:
        return JsonResponse({"error": str(exc), "code": "invalid_analysis_filter"}, status=400)
    return None


def _upload_session_problem_response(problem: UploadSessionProblem) -> JsonResponse:
    return JsonResponse({"error": problem.message, "code": problem.code}, status=problem.status)


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
    case_id_prefix = payload.get("caseIdPrefix", schedule.case_id_prefix if schedule else "CYB-GJ-SCHEDULED")
    validate_case_id(f"{case_id_prefix}-20000101-000000")
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
        "case_id_prefix": case_id_prefix,
    }


def _operational_event_dict(row: OperationalEvent) -> dict:
    timestamp = row.created_at.isoformat()
    return {"id": row.id, "type": row.event_type, "eventType": row.event_type, "caseId": row.case_id or "", "captureJobId": row.capture_job_id or "", "timestamp": timestamp, "createdAt": timestamp, "payload": row.payload_json}


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
    if getattr(settings, "NETRA_QUEUE_PROVIDER", "kafka") == "postgres-row-lock":
        return {"status": "ok", "provider": "postgres-row-lock", "detail": "ProcessingJob rows are the durable queue."}
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
    if not getattr(settings, "SUPABASE_SECRET_KEY", ""):
        details.append("Backend Supabase secret key is missing.")
        status = "failed"
    if getattr(settings, "NETRA_STORAGE_PROVIDER", "") == "supabase" and not getattr(settings, "SUPABASE_SECRET_KEY", ""):
        details.append("Supabase Storage cannot use private buckets without a backend secret key.")
        status = "failed"
    if getattr(settings, "NETRA_EVIDENCE_KEY", "") == "netra-development-evidence-key":
        details.append("Evidence encryption key is still the development default.")
        if status == "ok":
            status = "degraded"
    admin_count = _admin_count()
    if admin_count < 1:
        details.append("No Netra Admin profile exists yet; provision one server-side before production use.")
        if status == "ok":
            status = "degraded"
    return {
        "status": status,
        "authProvider": getattr(settings, "NETRA_AUTH_PROVIDER", "django"),
        "rbac": "enabled" if getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase" else "development",
        "devRoleHeaders": bool(getattr(settings, "NETRA_DEV_ROLE_HEADERS", False)),
        "secretKeyBackendOnly": True,
        "secretKeyConfigured": bool(getattr(settings, "SUPABASE_SECRET_KEY", "")),
        "adminProfiles": admin_count,
        "detail": "; ".join(details) if details else "Supabase Auth, RBAC, private Storage credentials, and audit logging are configured.",
    }


def _probe_evidence_normalization() -> dict:
    return {
        "status": "ok",
        "detail": "Evidence normalization, type-specific structured parsing, and unsupported extension blocking are enabled.",
        "supportedTypes": ["PCAP", "Firewall Logs", "DNS Logs", "TLS Metadata", "Mixed Evidence"],
        "fullyAnalyzable": ["PCAP", "Firewall Logs", "DNS Logs", "TLS Metadata", "Mixed Evidence"],
        "unsupportedExtensionBlocking": "enabled",
        "logEvidence": "structured-analysis-enabled",
    }


def _probe_packet_tools() -> dict:
    available = compatible_analysis_worker_available()
    return {
        "status": "ok" if available else "degraded",
        "runtimeRole": settings.NETRA_RUNTIME_ROLE,
        "mode": settings.NETRA_PROCESSING_MODE,
        "synchronousFallback": settings.NETRA_SYNC_FALLBACK_ENABLED,
        "compatibleWorkerAvailable": available,
    }


def _dead_letter_dict(row: DeadLetterEvent) -> dict:
    return {"id": row.id, "topic": row.topic, "workerName": row.worker_name, "jobId": row.job_id, "caseId": row.case_id, "error": row.error_message, "retryCount": row.retry_count, "status": row.status, "timestamp": row.created_at.isoformat()}


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


def _deliver_webhook(connection: IntegrationConnection, payload: dict, delivery_type: str, case: Case | None = None) -> IntegrationDelivery:
    key = hashlib.sha256(
        f"legacy-adapter:{connection.pk}:{case.pk if case else ''}:{delivery_type}:{json.dumps(payload, sort_keys=True)}".encode("utf-8")
    ).hexdigest()
    delivery, _ = queue_delivery(
        integration=connection,
        case=case,
        delivery_type=delivery_type,
        payload=payload,
        idempotency_key=key,
    )
    return delivery
