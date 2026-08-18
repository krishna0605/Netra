"""Case, workspace, membership, and case-history endpoints."""

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

from apps.forensics.models import AccessLog, Alert, AnomalyRecord, CaptureJob, CaptureSchedule, Case, CaseAnalysisSnapshot, CaseLink, CaseMembership, ComplianceControl, CustodyLedgerEvent, DeadLetterEvent, EvidenceFile, EvidenceManifest, EvidenceUploadSession, Export, IntegrationConnection, IntegrationCredential, IntegrationDelivery, OperationalEvent, ProcessingJob, Report, RetentionPolicy, RetentionRun, Sensor, SensorCommand, SensorGroup, SensorHealthSnapshot, SessionSummary, UserProfile, WorkerHeartbeat
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
    _alert_timeline,
    _case_dict,
    _case_list_dict,
    _case_scoped_analysis,
    _json_body,
    _paged,
    _visible_cases_queryset,
)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def cases(request):
    actor = actor_from_request(request)
    if request.method == "POST":
        denied = require_permission(request, "upload", resource_type="Case")
        if denied:
            return denied
        payload = _json_body(request)
        try:
            case_id = validate_case_id(payload["caseNumber"]) if payload.get("caseNumber") is not None else generate_case_id()
        except InvalidCaseId as exc:
            return JsonResponse({"error": str(exc), "code": "invalid_case_id"}, status=400)
        if Case.objects.filter(id=case_id).exists():
            return JsonResponse({"error": "A case with that identifier already exists."}, status=409)
        investigator, department = server_case_identity(actor)
        try:
            flags = validated_case_flags(payload.get("flags", []))
        except InvalidCaseFlags as exc:
            return JsonResponse({"error": str(exc), "code": "invalid_case_flags", "allowedFlags": list(ALLOWED_CASE_FLAGS)}, status=400)
        with transaction.atomic():
            case = Case.objects.create(
                id=case_id,
                organization_id=actor.organization_id,
                display_reference=case_id,
                title=payload.get("title") or f"Investigation {case_id}",
                investigator=investigator,
                department=department,
                priority=payload.get("priority") or "Standard",
                origin=payload.get("origin") if payload.get("origin") in {choice[0] for choice in Case.Origin.choices} else Case.Origin.OFFICER_UPLOAD,
                is_test=bool(payload.get("isTest", False)),
                opened_at=parse_datetime(payload.get("openedAt")) if payload.get("openedAt") else datetime.now(timezone.utc),
                closed_at=parse_datetime(payload.get("closedAt")) if payload.get("closedAt") else None,
                source_location=payload.get("sourceLocation", ""),
                remarks=payload.get("remarks", ""),
                flags_json=flags,
            )
            if actor.django_user_id:
                CaseMembership.objects.create(case=case, user_id=actor.django_user_id, role=actor.role, added_by=actor.user)
            add_history(case, actor, "Case created", "Investigation case created from API.")
        bump_case_list_cache_version()
        publish_event(
            "netra.case.events",
            {
                "type": "case.created",
                "caseId": case_id,
                "payload": {**payload, "investigator": investigator, "department": department, "flags": flags},
            },
        )
        return JsonResponse(_case_dict(case), status=201)
    actor_scope = actor.django_user_id or hashlib.sha256(f"{actor.role}:{actor.user}".encode("utf-8")).hexdigest()[:16]
    cache_key = f"netra:cases:list:{case_list_cache_version()}:{actor.organization_id}:{actor.role}:{actor_scope}:{request.GET.urlencode() or 'default'}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return JsonResponse(cached)
    rows = _visible_cases_queryset(request).annotate(
        _has_analysis_snapshot=Exists(CaseAnalysisSnapshot.objects.filter(case_id=OuterRef("pk"))),
        _snapshot_evidence_file_id=F("analysis_snapshot__snapshot_json__case__evidenceFileId"),
        _snapshot_evidence_filename=F("analysis_snapshot__snapshot_json__case__evidenceFilename"),
        _snapshot_alert_ids=F("analysis_snapshot__snapshot_json__case__alertIds"),
        _snapshot_latest_report_id=F("analysis_snapshot__snapshot_json__case__latestReportId"),
        _snapshot_latest_report_url=F("analysis_snapshot__snapshot_json__case__latestReportDownloadUrl"),
        _snapshot_risk_level=F("analysis_snapshot__snapshot_json__summary__riskLevel"),
        _snapshot_top_attack_class=F("analysis_snapshot__snapshot_json__summary__topAttackClass"),
        _snapshot_alert_count=F("analysis_snapshot__snapshot_json__summary__alerts"),
        _snapshot_packet_count=F("analysis_snapshot__snapshot_json__summary__packets"),
        _snapshot_session_count=F("analysis_snapshot__snapshot_json__summary__sessions"),
    ).prefetch_related(
        Prefetch("processing_jobs", queryset=ProcessingJob.objects.select_related("evidence_file").defer("stats", "events")),
        Prefetch("upload_sessions", queryset=EvidenceUploadSession.objects.select_related("processing_job", "processing_job__evidence_file").defer("processing_job__stats", "processing_job__events")),
        Prefetch("evidence_files", queryset=EvidenceFile.objects.only("id", "case_id", "filename", "status", "created_at", "updated_at")),
    )[:250]
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
        if "status" in payload and payload["status"] not in {Case.Status.OPEN, Case.Status.CLOSED}:
            return JsonResponse({"error": "Case status must be open or closed.", "code": "invalid_case_status"}, status=400)
        for field, attr in {
            "title": "title",
            "status": "status",
            "priority": "priority",
            "sourceLocation": "source_location",
            "remarks": "remarks",
        }.items():
            if field in payload:
                setattr(case, attr, payload[field] or "")
        if "flags" in payload:
            try:
                case.flags_json = validated_case_flags(payload["flags"])
            except InvalidCaseFlags as exc:
                return JsonResponse({"error": str(exc), "code": "invalid_case_flags", "allowedFlags": list(ALLOWED_CASE_FLAGS)}, status=400)
        if "closedAt" in payload:
            case.closed_at = parse_datetime(payload["closedAt"]) if payload["closedAt"] else None
            case.status = Case.Status.CLOSED if case.closed_at else Case.Status.OPEN
        case.save()
        add_history(case, actor_from_request(request), "Case metadata updated", "Case details, flags, or status were updated.")
        return JsonResponse(_case_dict(case))
    if case:
        return JsonResponse(_case_dict(case))
    analysis = _case_scoped_analysis(case_id=case_id)
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
    case_data = _case_scoped_analysis(case_id=case_id).get("case") or {}
    return JsonResponse({"caseId": case_id, "results": case_data.get("history", [])})


def case_light_summary(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    summary = dashboard_summary_payload(case_id)
    return JsonResponse({"case": _case_dict(case), "summary": summary})


def case_workspace(_request, case_id: str):
    case = Case.objects.select_related("analysis_snapshot").filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
    return JsonResponse(workspace_for_case(case))


def case_workspace_by_route(request, route_ref):
    case = visible_cases_for_actor(actor_from_request(request)).select_related("analysis_snapshot").filter(route_ref=route_ref).first()
    if not case:
        raise Http404("Case not found")
    return JsonResponse(workspace_for_case(case))


def case_workspace_status(request, route_ref):
    case = visible_cases_for_actor(actor_from_request(request)).annotate(
        _has_analysis_snapshot=Exists(CaseAnalysisSnapshot.objects.filter(case_id=OuterRef("pk")))
    ).filter(route_ref=route_ref).first()
    if not case:
        raise Http404("Case not found")
    return JsonResponse(workspace_status_payload(case))


def dashboard_summary_payload(case_id: str) -> dict:
    analysis = _case_scoped_analysis(case_id=case_id)
    return analysis["summary"] | {
        "topAttackClass": analysis.get("topAttackClass", analysis["summary"].get("topAttackClass", "Normal Baseline")),
        "riskLevel": analysis.get("riskLevel", analysis["summary"].get("riskLevel", "low")),
        "toolStatus": analysis.get("toolStatus", analysis["summary"].get("toolStatus", {})),
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
    analysis = _case_scoped_analysis(case_id=case_id)
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
    try:
        approved_incoming = validated_case_flags(incoming)
    except InvalidCaseFlags as exc:
        return JsonResponse({"error": str(exc), "code": "invalid_case_flags", "allowedFlags": list(ALLOWED_CASE_FLAGS)}, status=400)
    flags = list(dict.fromkeys([*(case.flags_json or []), *approved_incoming]))
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
        target_profile = UserProfile.objects.filter(user=user, organization_id=case.organization_id).first()
        if not target_profile:
            return JsonResponse({"error": "User not found", "code": "resource_not_found"}, status=404)
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
    return api_error(request, "feature_not_implemented", "Durable analysis references are not installed.", status=501)


def case_anomaly_explanation(request, case_id: str):
    model = ml_model_status_payload()
    rows = _case_scoped_analysis(case_id=case_id).get("anomalies", [])
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
