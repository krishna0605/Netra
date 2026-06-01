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
from django.db import connection
from django.http import FileResponse, Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import AccessLog, CaptureJob, Case, CaseMembership, ComplianceControl, CustodyLedgerEvent, DeadLetterEvent, EvidenceFile, EvidenceManifest, Export, IntegrationConnection, IntegrationCredential, IntegrationDelivery, OperationalEvent, ProcessingJob, Sensor, UserProfile, WorkerHeartbeat
from common.audit import access_log_dict, actor_from_request, add_history, log_access, require_permission
from common.analysis import analyze_pcap, build_alert_csv, build_evidence_bundle, build_report_html, empty_analysis
from common.custody import custody_event_dict, record_custody_event, verify_case_ledger
from common.detection import classify_detection, load_rules
from common.indexing import search_index
from common.jobs import job_status_payload
from common.kafka import publish_event
from common.pcap import available_packet_tools
from common.persistence import analysis_for_case, latest_job_for_case, persist_analysis, record_export, record_report, update_analysis_alert_status
from common.hashing import sha256_file, sha256_text
from common.operations import capture_job_payload, create_capture_job, emit_operational_event, ensure_capture_case, finalize_capture, heartbeat_state, ingest_capture_chunk, mark_capture_running, sensor_key_valid, sensor_payload, start_replay, stop_capture, validate_capture_bounds, worker_payload
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


def _case_dict(case: Case) -> dict:
    latest_job = latest_job_for_case(case.id)
    analysis = latest_job.stats.get("analysis", {}) if latest_job else {}
    return {
        "id": case.id,
        "title": case.title,
        "investigator": case.investigator,
        "status": case.status,
        "evidenceFileId": (latest_job.evidence_file_id if latest_job else ""),
        "alertIds": [alert.get("id") for alert in analysis.get("alerts", [])],
        "notes": [event.details for event in case.history.order_by("-created_at")[:8]],
        "history": [
            {"id": f"hist-{event.id}", "timestamp": event.created_at.isoformat(), "actor": event.actor_name, "action": event.action, "details": event.details}
            for event in case.history.order_by("-created_at")[:20]
        ],
        "createdAt": case.created_at.isoformat(),
        "reportStatus": case.report_status,
        "riskLevel": analysis.get("riskLevel", "low"),
        "topAttackClass": analysis.get("topAttackClass", "Normal Baseline"),
        "alertCount": len(analysis.get("alerts", [])),
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
                "department": payload.get("department") or "Gujarat Cyber Crime Cell",
                "priority": payload.get("priority") or "Standard",
                "source_location": payload.get("sourceLocation", ""),
                "remarks": payload.get("remarks", ""),
            },
        )
        add_history(case, actor, "Case created", "Investigation case created from API.")
        publish_event("netra.case.events", {"type": "case.created", "caseId": case_id, "payload": payload})
        return JsonResponse(_case_dict(case), status=201)
    rows = [_case_dict(case) for case in Case.objects.order_by("-updated_at")[:100]]
    if rows:
        return JsonResponse({"results": rows})
    return JsonResponse({"results": []})


def case_detail(_request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
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


def custody_ledger(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
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
    result = verify_case_ledger(case)
    record_custody_event(case, actor_from_request(request), "Custody ledger verified", result, resource_type="Case", resource_id=case_id)
    return JsonResponse(result)


def custody_export(_request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    if not case:
        raise Http404("Case not found")
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
    try:
        saved = save_uploaded_file(upload, "pcap")
    except OverflowError as exc:
        return JsonResponse({"error": str(exc)}, status=413)
    except ValueError as exc:
        message = str(exc)
        status = 422 if "valid PCAP" in message else 400
        return JsonResponse({"error": message}, status=status)
    saved["intake"] = {
        "investigator": (request.POST.get("investigator") or actor.user).strip(),
        "department": (request.POST.get("department") or "Gujarat Cyber Crime Cell").strip(),
        "sourceLocation": (request.POST.get("sourceLocation") or "").strip(),
        "priority": (request.POST.get("priority") or "Standard").strip(),
        "remarks": (request.POST.get("remarks") or "").strip(),
        "sourceIp": (request.POST.get("sourceIp") or "").strip(),
        "destinationIp": (request.POST.get("destinationIp") or "").strip(),
        "protocol": (request.POST.get("protocol") or "").strip().upper(),
        "port": (request.POST.get("port") or "").strip(),
        "durationSeconds": (request.POST.get("durationSeconds") or "").strip(),
        "packetLimit": (request.POST.get("packetLimit") or "").strip(),
        "bpfFilter": (request.POST.get("bpfFilter") or "").strip(),
    }
    evidence_id = f"ev-{uuid4().hex[:8]}"
    job_id = f"job-{uuid4().hex[:8]}"
    try:
        analysis = analyze_pcap(saved["analysis_path"], case_id, evidence_id, job_id, saved)
        job = persist_analysis(analysis, saved, actor)
    except Exception as exc:
        return JsonResponse({"error": f"PCAP analysis failed: {exc}", "id": evidence_id, "caseId": case_id, "jobId": job_id, **saved}, status=422)
    finally:
        if saved.get("analysis_path"):
            Path(saved["analysis_path"]).unlink(missing_ok=True)
    public_saved = {key: value for key, value in saved.items() if key != "analysis_path"}
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
    path = Path(evidence.stored_path)
    encrypted_hash = sha256_file(path) if path.exists() else ""
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
    if not sensor or heartbeat_state(sensor.last_heartbeat_at) != "healthy":
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
    try:
        packet_limit = int(request.POST.get("packetLimit", "10000"))
        chunk_interval = int(request.POST.get("chunkIntervalSeconds", "5"))
        duration = int(request.POST.get("durationSeconds", "900"))
        validate_capture_bounds(duration, packet_limit, chunk_interval)
        saved = save_uploaded_file(upload, "capture_chunk")
        Path(saved["analysis_path"]).unlink(missing_ok=True)
    except (OverflowError, TypeError, ValueError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
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
    return JsonResponse(capture_job_payload(job))


@csrf_exempt
@require_http_methods(["GET", "POST"])
def sensors(request):
    if request.method == "POST":
        return sensor_register(request)
    return JsonResponse({"results": [sensor_payload(row) for row in Sensor.objects.order_by("name")]})


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


def sensor_detail(_request, sensor_id: str):
    sensor = Sensor.objects.filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
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
    sensor.status = Sensor.Status.ONLINE
    sensor.interfaces_json = payload.get("interfaces", sensor.interfaces_json)
    sensor.metadata_json = sensor.metadata_json | payload.get("metadata", {})
    sensor.save(update_fields=["last_heartbeat_at", "status", "interfaces_json", "metadata_json", "updated_at"])
    emit_operational_event("sensor.heartbeat", sensor_payload(sensor))
    return JsonResponse(sensor_payload(sensor))


def sensor_next_command(request, sensor_id: str):
    if not sensor_key_valid(request):
        return JsonResponse({"error": "Invalid sensor key."}, status=403)
    sensor = Sensor.objects.filter(id=sensor_id).first()
    if not sensor:
        raise Http404("Sensor not found")
    job = CaptureJob.objects.filter(sensor=sensor, mode=CaptureJob.Mode.LIVE_CAPTURE, status=CaptureJob.Status.QUEUED).order_by("created_at").first()
    if job:
        mark_capture_running(job)
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
        return JsonResponse(finalize_capture(job))
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=422)


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
    emit_operational_event("capture.failed", capture_job_payload(job), capture_job=job)
    return JsonResponse(capture_job_payload(job))


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
    expected = ["capture", "parser", "decoder", "session", "detection", "anomaly", "report-export"]
    latest = {}
    for row in WorkerHeartbeat.objects.order_by("worker_name", "-last_seen_at"):
        latest.setdefault(row.worker_name, row)
    results = []
    for worker in expected:
        row = latest.get(worker)
        results.append(worker_payload(row, worker) if row else {"name": worker, "status": "offline", "lastSeen": None, "currentJobId": "", "details": {}})
    return JsonResponse({"processingMode": settings.NETRA_PROCESSING_MODE, "results": results})


def system_health_deep(_request):
    checks = {
        "postgres": _probe_postgres(),
        "elasticsearch": _probe_elasticsearch(),
        "kafka": _probe_kafka(),
        "storage": _probe_storage(),
        "encryption": _probe_encryption(),
        "packetTools": _probe_packet_tools(),
        "workers": _probe_workers(),
    }
    status = "ok" if all(value["status"] == "ok" for value in checks.values()) else "degraded"
    db = {
        "mode": getattr(settings, "NETRA_DATABASE_MODE", "docker-postgres"),
        "host": settings.DATABASES["default"]["HOST"],
        "port": settings.DATABASES["default"]["PORT"],
        "name": settings.DATABASES["default"]["NAME"],
        "tables": len(connection.introspection.table_names()),
    }
    access = {
        "mode": getattr(settings, "NETRA_ACCESS_MODE", "role-headers"),
        "label": "Trusted LAN" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "Development",
        "authentication": "disabled" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "development headers or JWT",
        "publicInternet": "not-supported" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "not-configured",
        "actor": getattr(settings, "NETRA_TRUSTED_LAN_ACTOR", "Local Investigator"),
        "role": getattr(settings, "NETRA_TRUSTED_LAN_ROLE", "LAN Operator"),
    }
    return JsonResponse({"status": status, "checkedAt": datetime.now(timezone.utc).isoformat(), "checks": checks, "database": db, "access": access})


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
    try:
        from common.search import get_elasticsearch_client
        rows = sorted(get_elasticsearch_client().indices.get_alias(index="netra-*").keys())
        return JsonResponse({"status": "ok", "results": rows})
    except Exception as exc:
        return JsonResponse({"status": "failed", "results": [], "detail": str(exc)}, status=503)


def system_kafka(_request):
    probe = _probe_kafka()
    return JsonResponse({"bootstrap": settings.NETRA_KAFKA_BOOTSTRAP, **probe, "topics": ["netra.pcap.uploaded", "netra.capture.chunk.received", "netra.packets.normalized", "netra.operational.events", "netra.dead_letter"]}, status=200 if probe["status"] == "ok" else 503)


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
    started = time.perf_counter()
    try:
        from common.search import get_elasticsearch_client
        ok = bool(get_elasticsearch_client().ping())
        return {"status": "ok" if ok else "failed", "latencyMs": round((time.perf_counter() - started) * 1000, 2)}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def _probe_kafka() -> dict:
    started = time.perf_counter()
    try:
        from kafka.admin import KafkaAdminClient
        admin = KafkaAdminClient(bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP, request_timeout_ms=2500, api_version_auto_timeout_ms=2500)
        topics = sorted(admin.list_topics())
        admin.close()
        return {"status": "ok", "latencyMs": round((time.perf_counter() - started) * 1000, 2), "topicCount": len(topics)}
    except Exception as exc:
        return {"status": "failed", "detail": str(exc)}


def _probe_storage() -> dict:
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


def _probe_packet_tools() -> dict:
    tools = available_packet_tools()
    return {"status": "ok" if tools.get("tshark") and tools.get("zeek") else "degraded", **tools}


def _probe_workers() -> dict:
    rows = system_workers(None).content
    payload = json.loads(rows)
    offline = [row["name"] for row in payload["results"] if row["status"] == "offline"]
    stale = [row["name"] for row in payload["results"] if row["status"] == "stale"]
    return {"status": "ok" if not offline and not stale else "degraded", "offline": offline, "stale": stale}


def system_database(_request):
    tables = connection.introspection.table_names()
    access = {
        "mode": getattr(settings, "NETRA_ACCESS_MODE", "role-headers"),
        "label": "Trusted LAN" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "Development",
        "authentication": "disabled" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "development headers or JWT",
        "publicInternet": "not-supported" if getattr(settings, "NETRA_ACCESS_MODE", "") == "trusted-lan" else "not-configured",
    }
    return JsonResponse(
        {
            "mode": getattr(settings, "NETRA_DATABASE_MODE", "docker-postgres"),
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
        analysis["summary"]
        | {
            "case": analysis.get("case"),
            "evidence": analysis.get("evidence"),
            "topAttackClass": analysis.get("topAttackClass", analysis["summary"].get("topAttackClass", "Normal Baseline")),
            "riskLevel": analysis.get("riskLevel", analysis["summary"].get("riskLevel", "low")),
            "toolStatus": analysis.get("toolStatus", analysis["summary"].get("toolStatus", available_packet_tools())),
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
            "timeline": analysis.get("trafficTimeline", []),
            "graph": analysis.get("graph", {}),
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
def report_generate(request, case_id: str):
    case = Case.objects.filter(id=case_id).first()
    denied = require_permission(request, "report", case=case, resource_type="Report", resource_id=case_id)
    if denied:
        return denied
    actor = actor_from_request(request)
    payload = _json_body(request)
    language = payload.get("language", "en")
    analysis = _analysis(case_id=case_id)
    custody = verify_case_ledger(case) if case else {}
    html = build_report_html(analysis, language).replace("</body>", f"<section><h2>Custody Ledger</h2><p>Verified: {custody.get('verified')} | Events: {custody.get('eventCount')} | Latest hash: {custody.get('latestHash','')}</p></section></body>")
    artifact = write_text_artifact(html, "report", f"{case_id}-{language}.html")
    record_report(case_id, artifact, language, actor)
    publish_event("netra.export.completed", {"type": "report.generated", "caseId": case_id, **artifact})
    return JsonResponse({"caseId": case_id, "language": language, "status": "ready", "reportId": artifact["filename"], "downloadUrl": f"/api/reports/{artifact['filename']}/download", **artifact}, status=201)


def report_download(_request, report_id: str):
    path = settings.NETRA_STORAGE_ROOT / "reports" / report_id
    if not path.exists():
        path = settings.NETRA_STORAGE_ROOT / "reports" / f"{report_id}.enc"
    if not path.exists():
        raise Http404("Report not found")
    filename = path.name.removesuffix(".enc")
    return HttpResponse(read_encrypted_or_plain(path), headers={"Content-Disposition": f'attachment; filename="{filename}"'}, content_type="text/html")


@csrf_exempt
@require_http_methods(["GET", "POST"])
def exports(request):
    if request.method == "POST":
        denied = require_permission(request, "export", resource_type="Export")
        if denied:
            return denied
        actor = actor_from_request(request)
        payload = _json_body(request)
        export_id = f"exp-{uuid4().hex[:8]}"
        case_id = payload.get("caseId") or request.GET.get("caseId") or _analysis().get("caseId", "")
        analysis = _analysis(case_id=case_id)
        export_type = (payload.get("type") or "json").lower()
        if "csv" in export_type or "alert" in export_type:
            filename = f"{export_id}-alerts.csv"
            content = build_alert_csv(analysis)
        else:
            filename = f"{export_id}-evidence.json"
            bundle = json.loads(build_evidence_bundle(analysis))
            case = Case.objects.filter(id=case_id).first()
            if case:
                bundle["custodyLedger"] = {"verification": verify_case_ledger(case), "events": [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("created_at", "id")]}
            content = json.dumps(bundle, indent=2)
        artifact = write_text_artifact(content, "export", filename)
        record_export(case_id, export_id, export_type, artifact, actor)
        publish_event("netra.export.requests", {"type": "export.created", "exportId": export_id, **payload})
        return JsonResponse({"id": export_id, "status": "ready", "type": export_type, "downloadUrl": f"/api/exports/{export_id}/download", **artifact}, status=201)
    generated = [
        {"id": row.id, "type": row.export_type, "caseId": row.case_id, "requestedBy": row.requested_by, "timestamp": row.created_at.isoformat(), "hash": row.sha256 or row.stored_path, "status": row.status}
        for row in Export.objects.order_by("-created_at")[:50]
    ]
    return JsonResponse({"results": generated})


def export_detail(_request, export_id: str):
    export = Export.objects.filter(id=export_id).first()
    if not export:
        raise Http404("Export not found")
    return JsonResponse({"id": export.id, "type": export.export_type, "caseId": export.case_id, "requestedBy": export.requested_by, "timestamp": export.created_at.isoformat(), "hash": export.sha256 or export.stored_path, "status": export.status})


def export_download(_request, export_id: str):
    export_dir = settings.NETRA_STORAGE_ROOT / "exports"
    path = next(iter(export_dir.glob(f"{export_id}*")), export_dir / f"{export_id}.json")
    if not path.exists():
        raise Http404("Export not found")
    filename = path.name.removesuffix(".enc")
    return HttpResponse(read_encrypted_or_plain(path), headers={"Content-Disposition": f'attachment; filename="{filename}"'}, content_type="application/octet-stream")


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
            response = urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method="POST"), timeout=5)
            summary = f"HTTP {response.status}"
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
    payload = _json_body(request)
    case_id = payload.get("caseId") or _analysis().get("caseId", "")
    analysis = _analysis(case_id=case_id)
    lines = [
        f"CEF:0|Netra|Network Forensics|3|{alert.get('ruleId','netra-alert')}|{alert.get('attackClass')}|{alert.get('confidence')}|src={alert.get('sourceIp')} dst={alert.get('destination')} cs1={case_id} cs1Label=caseId"
        for alert in analysis.get("alerts", [])
    ]
    artifact = write_text_artifact("\n".join(lines) or "CEF:0|Netra|Network Forensics|3|baseline|No critical alerts|0|", "export", f"siem-{case_id or 'latest'}-{uuid4().hex[:6]}.cef")
    return JsonResponse({"caseId": case_id, "status": "ready", "downloadUrl": f"/api/exports/{Path(artifact['filename']).stem}/download", **artifact}, status=201)


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
    return JsonResponse({"results": ["Admin", "Investigator", "Analyst", "Viewer"]})


def security_posture(_request):
    return JsonResponse({"encryptionAtRest": "ready", "rbac": "enabled", "auditLogs": "enabled", "standardsAlignment": "digital evidence workflow"})


def access_logs(_request):
    rows = AccessLog.objects.order_by("-created_at")[:100]
    if rows:
        return JsonResponse({"results": [access_log_dict(row) for row in rows]})
    return JsonResponse({"results": []})
