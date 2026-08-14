"""Job, worker, readiness, health, and operational endpoints."""

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
    _admin_count,
    _dead_letter_dict,
    _json_body,
    _operational_event_dict,
    _probe_elasticsearch,
    _probe_encryption,
    _probe_evidence_normalization,
    _probe_kafka,
    _probe_packet_tools,
    _probe_postgres,
    _probe_realtime,
    _probe_security,
    _probe_storage,
    _upload_session_problem_response,
)


def health(_request):
    return JsonResponse(
        {
            "status": "ok",
            "service": "netra-backend",
            "releaseId": settings.NETRA_RELEASE_ID,
        }
    )


def setup_status(_request):
    if not settings.NETRA_AUTH_PROXY_ENABLED:
        raise Http404("Endpoint disabled")
    admin_count = _admin_count()
    return JsonResponse({"requiresSetup": admin_count == 0, "adminCount": admin_count})


@csrf_exempt
@require_http_methods(["POST"])
def setup_admin(request):
    if not settings.NETRA_AUTH_PROXY_ENABLED or settings.NETRA_DEPLOYMENT_PROFILE != "local":
        raise Http404("Endpoint disabled")
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
    profile = UserProfile.objects.create(user=user, organization=netra_organization(), role="Admin", display_name=name)
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


def capabilities(_request):
    return JsonResponse({"results": public_capabilities()})
    if limited:
        return limited
    if not analysis_admission_available():
        return JsonResponse(
            {"error": "Analysis capacity is temporarily unavailable.", "code": "analysis_capacity_unavailable"},
            status=503,
        )
    if len(request.body) > 64 * 1024:
        return JsonResponse({"error": "Upload session metadata is too large.", "code": "upload_metadata_too_large"}, status=413)
    try:
        payload = _json_body(request)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"error": "Request body must be valid JSON.", "code": "invalid_json"}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({"error": "Request body must be a JSON object.", "code": "invalid_json"}, status=400)
    try:
        session, replayed = create_upload_session(
            actor_from_request(request),
            payload,
            (request.headers.get("Idempotency-Key") or "").strip(),
        )
        return JsonResponse(upload_session_payload(session, idempotent_replay=replayed), status=200 if replayed else 201)
    except UploadSessionProblem as problem:
        return _upload_session_problem_response(problem)


def operational_events(request):
    actor = actor_from_request(request)
    rows = OperationalEvent.objects.filter(organization_id=actor.organization_id).order_by("-id")
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


def job_status(_request, job_id: str):
    job = ProcessingJob.objects.filter(id=job_id).first()
    if job:
        return JsonResponse(job_status_payload(job))
    raise Http404("Job not found")


def job_events(_request, job_id: str):
    job = ProcessingJob.objects.filter(id=job_id).first()
    if not job:
        raise Http404("Job not found")
    return JsonResponse({"jobId": job_id, "results": job.events or []})


@csrf_exempt
@require_http_methods(["POST"])
def job_cancel(_request, job_id: str):
    job = ProcessingJob.objects.filter(id=job_id).first()
    if not job:
        raise Http404("Job not found")
    return JsonResponse(job_status_payload(request_job_cancellation(job.id)))


def system_workers(_request):
    postgres_worker_mode = settings.NETRA_PROCESSING_MODE == "postgres-worker"
    expected = ["postgres-analysis"] if postgres_worker_mode else ["capture", "pcap-ingestion", "parser", "decoder", "session", "detection", "anomaly", "analysis-finalizer", "report-export", "scheduler", "retention"]
    worker_mode = "enabled" if postgres_worker_mode or getattr(settings, "NETRA_SUPABASE_START_WORKERS", False) else "disabled"
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


def system_health_deep(request):
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
    return JsonResponse({"status": status, "checkedAt": datetime.now(timezone.utc).isoformat(), "checks": checks, "database": db, "access": access, "cache": storage_cache_status_payload(), "incidentReadiness": incident_readiness_payload(actor_from_request(request).organization_id)})


def system_incident_readiness(request):
    actor = actor_from_request(request)
    log_access(actor, "system.incident_readiness", resource_type="System", resource_id="incident-readiness")
    return JsonResponse(incident_readiness_payload(actor.organization_id))


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
    # Keep this operational endpoint on narrow, aggregate-only queries. Loading
    # ProcessingJob.stats here used to pull every analysis JSON document from
    # Supabase on every dashboard refresh, causing database egress to scale with
    # historical evidence rather than with the tiny metrics response.
    indexed_packets = SessionSummary.objects.aggregate(total=Sum("packet_count"))["total"] or 0
    return JsonResponse(
        {
            "cases": Case.objects.count(),
            "evidenceFiles": EvidenceFile.objects.count(),
            "alerts": Alert.objects.count(),
            "criticalAlerts": Alert.objects.filter(severity=Alert.Severity.CRITICAL).count(),
            "queuedJobs": ProcessingJob.objects.filter(status=ProcessingJob.Status.QUEUED).count(),
            "failedJobs": ProcessingJob.objects.filter(status=ProcessingJob.Status.FAILED).count(),
            "deadLetterEvents": DeadLetterEvent.objects.exclude(status=DeadLetterEvent.Status.RESOLVED).count(),
            "indexedPackets": indexed_packets,
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


def system_throughput(request):
    cutoff = datetime.now(timezone.utc).timestamp() - 60
    actor = actor_from_request(request)
    recent_chunks = [row for row in OperationalEvent.objects.filter(organization_id=actor.organization_id, event_type="capture.chunk_received").order_by("-created_at")[:500] if row.created_at.timestamp() >= cutoff]
    packets = sum(int(row.payload_json.get("chunkPackets", 0)) for row in recent_chunks)
    return JsonResponse({"windowSeconds": 60, "chunksPerMinute": len(recent_chunks), "packetsIndexedPerMinute": packets})


def system_index_retention(_request):
    policy = ensure_default_retention_policy()
    return JsonResponse({"status": "configured", "policy": retention_policy_payload(policy), "aliases": ["netra-packets", "netra-sessions", "netra-protocols", "netra-payloads", "netra-alerts", "netra-zeek", "netra-live-packets"]})


def _probe_workers() -> dict:
    if settings.NETRA_PROCESSING_MODE != "postgres-worker" and getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase" and not getattr(settings, "NETRA_SUPABASE_START_WORKERS", False):
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
    if settings.NETRA_PROCESSING_MODE == "postgres-worker":
        return JsonResponse(job_status_payload(retry_job(job.id)))
    job.events = (job.events or []) + [{"timestamp": datetime.now(timezone.utc).isoformat(), "event": "reprocess.requested", "detail": "Manual reprocess requested."}]
    job.save(update_fields=["events", "updated_at"])
    publish_event("netra.pcap.uploaded", {"type": "job.reprocess", "jobId": job.id, "caseId": job.case_id})
    return JsonResponse(job_status_payload(job))


def detection_rules(_request):
    return JsonResponse({"results": load_rules()})


def search(request):
    route_ref = (request.GET.get("caseRef") or "").strip()
    job_id = (request.GET.get("jobId") or "").strip()
    if not route_ref or not job_id:
        return api_error(
            request,
            "scope_required",
            "Both caseRef and jobId are required. Use the workspace-scoped search URL.",
            status=400,
        )
    from apps.forensics.api.features import scoped_search

    return scoped_search(request, route_ref, job_id)
