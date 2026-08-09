from __future__ import annotations

import hashlib
import re
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.forensics.api.errors import analysis_not_found, api_error
from apps.forensics.models import AnalysisReference, Case, ProcessingJob
from apps.forensics.services.analysis_scope import AnalysisScopeProblem, find_analysis_row, resolve_analysis_scope
from common.async_pipeline import queue_uploaded_evidence
from common.audit import actor_from_request, can, visible_cases_for_actor
from common.evidence_normalization import normalize_evidence_upload
from common.indexing import search_index
from common.storage import save_uploaded_file


_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REFERENCE_COLLECTIONS = {
    AnalysisReference.Kind.PACKET: "packets",
    AnalysisReference.Kind.SESSION: "sessions",
    AnalysisReference.Kind.PAYLOAD: "payloadFindings",
}
_IMPORT_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".ndjson"}


def _scope(request, route_ref, job_id):
    try:
        return resolve_analysis_scope(request, route_ref, job_id)
    except AnalysisScopeProblem as problem:
        return api_error(
            request,
            problem.code,
            "The requested analysis resource was not found."
            if problem.status == 404
            else "The selected analysis is not ready.",
            status=problem.status,
        )


def _reference_payload(row: AnalysisReference) -> dict:
    return {
        "id": str(row.id),
        "caseId": row.case_id,
        "jobId": row.processing_job_id,
        "kind": row.kind,
        "sourceReference": row.source_reference,
        "metadata": row.metadata_json,
        "createdBy": row.created_by_label,
        "createdAt": row.created_at.isoformat(),
    }


def _bounded_reference_metadata(kind: str, source: dict) -> dict:
    allowed = {
        "packet": ("id", "timestamp", "sourceIp", "destinationIp", "protocol", "length"),
        "session": ("id", "source", "destination", "protocol", "startTime", "endTime", "packetCount"),
        "payload": ("id", "protocol", "risk", "summary", "finding"),
    }[kind]
    return {key: source.get(key) for key in allowed if key in source}


@csrf_exempt
@require_http_methods(["GET", "POST"])
def analysis_references(request, route_ref, job_id, kind: str):
    if kind not in _REFERENCE_COLLECTIONS:
        return analysis_not_found(request)
    scope = _scope(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    queryset = AnalysisReference.objects.filter(
        organization_id=scope.case.organization_id,
        case=scope.case,
        processing_job=scope.job,
        kind=kind,
    ).order_by("created_at", "id")
    if request.method == "GET":
        return JsonResponse({"results": [_reference_payload(row) for row in queryset]})
    try:
        import json

        payload = json.loads(request.body.decode("utf-8")) if request.body else {}
    except (UnicodeDecodeError, ValueError):
        return api_error(request, "invalid_request_body", "A valid JSON request body is required.", status=400)
    source_reference = str(payload.get("sourceReference") or "").strip()
    if not source_reference or len(source_reference) > 160:
        return api_error(request, "invalid_source_reference", "A bounded source reference is required.", status=400)
    source = find_analysis_row(scope, _REFERENCE_COLLECTIONS[kind], source_reference)
    if not source:
        return analysis_not_found(request)
    reference, created = AnalysisReference.objects.get_or_create(
        organization=scope.case.organization,
        case=scope.case,
        processing_job=scope.job,
        kind=kind,
        source_reference=source_reference,
        defaults={
            "evidence_file": scope.job.evidence_file,
            "metadata_json": _bounded_reference_metadata(kind, source),
            "created_by_id": scope.actor.django_user_id,
            "created_by_label": scope.actor.user,
        },
    )
    return JsonResponse(_reference_payload(reference), status=201 if created else 200)


def _visible_case(request, route_ref):
    actor = actor_from_request(request)
    case = visible_cases_for_actor(actor).filter(route_ref=route_ref).first()
    return actor, case


def _idempotency_key(request, organization_id) -> tuple[str | None, JsonResponse | None]:
    raw = (request.headers.get("Idempotency-Key") or "").strip()
    if not _IDEMPOTENCY_KEY.fullmatch(raw):
        return None, api_error(
            request,
            "invalid_idempotency_key",
            "A safe Idempotency-Key header is required.",
            status=400,
        )
    return hashlib.sha256(f"{organization_id}\0{raw}".encode("utf-8")).hexdigest(), None


def _import_response(job: ProcessingJob) -> JsonResponse:
    return JsonResponse(
        {
            "jobId": job.id,
            "caseId": job.case_id,
            "operationKind": job.operation_kind,
            "status": job.status,
        },
        status=202,
    )


def _durable_log_import(request, route_ref, operation_kind: str):
    if not getattr(settings, "NETRA_ENABLE_STRUCTURED_IMPORTS", False):
        return api_error(request, "feature_disabled", "Structured imports are disabled for this deployment profile.", status=503)
    actor, case = _visible_case(request, route_ref)
    if not case:
        return api_error(request, "resource_not_found", "The requested workspace was not found.", status=404)
    if not can(actor, "upload"):
        return api_error(request, "permission_denied", "Permission denied.", status=403)
    key, error = _idempotency_key(request, case.organization_id)
    if error:
        return error
    existing = ProcessingJob.objects.filter(idempotency_key=key).first()
    if existing:
        if existing.case_id != case.id or existing.operation_kind != operation_kind:
            return api_error(request, "idempotency_conflict", "The idempotency key belongs to another operation.", status=409)
        return _import_response(existing)
    upload = request.FILES.get("file")
    if not upload:
        return api_error(request, "file_required", "A structured log file is required.", status=400)
    if not upload.size or upload.size > 25 * 1024 * 1024:
        return api_error(request, "invalid_import_size", "Import files must be between 1 byte and 25 MiB.", status=400)
    extension = Path(upload.name).suffix.lower()
    if extension not in _IMPORT_EXTENSIONS:
        return api_error(request, "unsupported_import_type", "The structured log extension is not supported.", status=400)
    if operation_kind == ProcessingJob.OperationKind.CAPTURE_LOG_IMPORT:
        normalization = normalize_evidence_upload(upload, "Auto-detect")
        if not normalization.valid or normalization.normalized_type == "PCAP":
            return api_error(request, normalization.code or "invalid_structured_log", normalization.reason, status=400)
        normalization_payload = normalization.to_dict()
    else:
        normalization_payload = {
            "valid": True,
            "normalizedType": "Mixed Evidence",
            "detectedType": "Zeek Logs",
            "parser": "zeek-log",
            "features": {"extension": extension},
        }
    upload.seek(0)
    evidence_id = f"ev-log-{uuid4().hex[:12]}"
    saved = save_uploaded_file(upload, "structured", evidence_id=evidence_id, case_id=case.id)
    saved["filename"] = Path(upload.name).name
    saved["normalization"] = normalization_payload
    saved["intake"] = {
        "investigator": case.investigator,
        "department": case.department,
        "priority": case.priority,
        "sourceLocation": case.source_location,
    }
    job = queue_uploaded_evidence(
        saved,
        case.id,
        evidence_id,
        f"job-import-{uuid4().hex[:12]}",
        actor,
        idempotency_key=key,
    )
    job.operation_kind = operation_kind
    job.save(update_fields=["operation_kind", "updated_at"])
    return _import_response(job)


@csrf_exempt
@require_http_methods(["POST"])
def capture_log_import(request, route_ref):
    return _durable_log_import(request, route_ref, ProcessingJob.OperationKind.CAPTURE_LOG_IMPORT)


@csrf_exempt
@require_http_methods(["POST"])
def zeek_log_import(request, route_ref):
    return _durable_log_import(request, route_ref, ProcessingJob.OperationKind.ZEEK_LOG_IMPORT)


@require_http_methods(["GET"])
def scoped_search(request, route_ref, job_id):
    scope = _scope(request, route_ref, job_id)
    if isinstance(scope, JsonResponse):
        return scope
    kind = (request.GET.get("type") or "packet").strip().lower()
    mapping = {
        "packet": ("packets", "packets"),
        "session": ("sessions", "sessions"),
        "alert": ("alerts", "alerts"),
        "payload": ("payloads", "payloadFindings"),
        "zeek": ("zeek", "zeek"),
    }
    if kind not in mapping:
        return api_error(request, "invalid_search_type", "The requested search type is not supported.", status=400)
    query = (request.GET.get("q") or "").strip()
    if len(query) > 256 or query.startswith(("*", "?")) or any(ord(character) < 32 for character in query):
        return api_error(request, "invalid_search_query", "The search query is invalid or too long.", status=400)
    try:
        limit = max(1, min(int(request.GET.get("limit") or 100), 100))
    except ValueError:
        return api_error(request, "invalid_search_limit", "The search limit must be an integer.", status=400)
    index_kind, collection = mapping[kind]
    fallback = scope.analysis.get(collection, [])
    if kind == "zeek" and isinstance(fallback, dict):
        fallback = [row for rows in (fallback.get("records") or {}).values() for row in rows if isinstance(row, dict)]
    if not isinstance(fallback, list):
        fallback = []
    rows, provider = search_index(index_kind, scope.case.id, query, fallback, job_id=scope.job.id)
    return JsonResponse({"caseId": scope.case.id, "jobId": scope.job.id, "provider": provider, "results": rows[:limit]})


@csrf_exempt
@require_http_methods(["POST"])
def capture_stop(request, route_ref, job_id):
    actor, case = _visible_case(request, route_ref)
    if not case:
        return api_error(request, "resource_not_found", "The requested workspace was not found.", status=404)
    if not can(actor, "operations"):
        return api_error(request, "permission_denied", "Permission denied.", status=403)
    from apps.forensics.models import CaptureJob
    from common.operations import stop_capture

    job = CaptureJob.objects.filter(pk=job_id, case=case).first()
    if not job:
        return api_error(request, "resource_not_found", "The requested capture job was not found.", status=404)
    return JsonResponse(stop_capture(job))
