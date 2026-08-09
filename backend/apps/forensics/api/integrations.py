from __future__ import annotations

import hashlib
import json
import re
from uuid import UUID

from django.conf import settings
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.forensics.api.errors import api_error
from apps.forensics.models import IntegrationCaseLink, IntegrationConnection, IntegrationDelivery
from apps.forensics.services.administration import AdministrationProblem, require_privileged_admin
from apps.forensics.services.analysis_scope import AnalysisScopeProblem, resolve_analysis_scope
from apps.forensics.services.integration_credentials import store_integration_secret
from apps.forensics.services.webhook_delivery import WebhookDeliveryProblem, queue_delivery, validate_webhook_url
from common.audit import actor_from_request, visible_cases_for_actor


_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _enabled(request):
    if not settings.NETRA_ENABLE_INTEGRATIONS:
        return api_error(request, "feature_disabled", "Integrations are disabled for this deployment profile.", status=503)
    return None


def _delivery_enabled(request):
    disabled = _enabled(request)
    if disabled:
        return disabled
    if not settings.NETRA_WEBHOOK_ALLOWED_HOSTS:
        return api_error(request, "feature_disabled", "Outbound webhooks require an exact hostname allowlist.", status=503)
    return None


def _payload(request):
    try:
        return json.loads(request.body.decode("utf-8")) if request.body else {}
    except (UnicodeDecodeError, ValueError):
        return None


def _admin_error(request, problem: AdministrationProblem):
    return api_error(request, problem.code, problem.message, status=problem.status)


def _require_admin(request):
    try:
        require_privileged_admin(actor_from_request(request), actor_from_request(request).organization_id)
        return None
    except AdministrationProblem as problem:
        return _admin_error(request, problem)


def _connection(request, integration_id):
    actor = actor_from_request(request)
    try:
        identifier = int(integration_id)
    except (TypeError, ValueError):
        return None
    return IntegrationConnection.objects.filter(pk=identifier, organization_id=actor.organization_id).first()


def _connection_payload(connection: IntegrationConnection) -> dict:
    return {
        "id": connection.pk,
        "system": connection.system_name,
        "systemName": connection.system_name,
        "status": connection.status,
        "apiMode": connection.api_mode,
        "config": {key: value for key, value in connection.config.items() if key != "secret"},
        "linkedCases": connection.case_links.count(),
        "lastSync": connection.last_sync_at.isoformat() if connection.last_sync_at else None,
    }


@csrf_exempt
@require_http_methods(["GET", "POST"])
def connections(request):
    disabled = _enabled(request)
    if disabled:
        return disabled
    actor = actor_from_request(request)
    if request.method == "GET":
        rows = IntegrationConnection.objects.filter(organization_id=actor.organization_id).order_by("system_name")
        return JsonResponse({"results": [_connection_payload(row) for row in rows]})
    denied = _require_admin(request)
    if denied:
        return denied
    payload = _payload(request)
    if payload is None:
        return api_error(request, "invalid_request_body", "A valid JSON request body is required.", status=400)
    if "secret" in payload:
        return api_error(request, "secret_not_accepted", "Use the dedicated credential endpoint.", status=400)
    name = str(payload.get("systemName") or "").strip()
    if not name or len(name) > 160:
        return api_error(request, "invalid_integration_name", "A bounded system name is required.", status=400)
    config = payload.get("config") if isinstance(payload.get("config"), dict) else {}
    url = str(config.get("url") or "").strip()
    if url:
        try:
            validate_webhook_url(url)
        except WebhookDeliveryProblem as problem:
            return api_error(request, problem.code, str(problem), status=400)
    connection, created = IntegrationConnection.objects.update_or_create(
        organization_id=actor.organization_id,
        system_name=name,
        defaults={"status": "pending", "api_mode": str(payload.get("mode") or "webhook-json"), "config": config},
    )
    return JsonResponse(_connection_payload(connection), status=201 if created else 200)


@csrf_exempt
@require_http_methods(["PATCH"])
def connection_detail(request, integration_id):
    disabled = _enabled(request)
    if disabled:
        return disabled
    denied = _require_admin(request)
    if denied:
        return denied
    connection = _connection(request, integration_id)
    if not connection:
        return api_error(request, "resource_not_found", "The requested integration was not found.", status=404)
    payload = _payload(request)
    if payload is None or "secret" in payload:
        return api_error(request, "secret_not_accepted", "Use the dedicated credential endpoint.", status=400)
    config = payload.get("config") if isinstance(payload.get("config"), dict) else connection.config
    if config.get("url"):
        try:
            validate_webhook_url(str(config["url"]))
        except WebhookDeliveryProblem as problem:
            return api_error(request, problem.code, str(problem), status=400)
    connection.api_mode = str(payload.get("mode") or connection.api_mode)
    connection.status = str(payload.get("status") or connection.status)
    connection.config = config
    connection.save(update_fields=["api_mode", "status", "config", "updated_at"])
    return JsonResponse(_connection_payload(connection))


@csrf_exempt
@require_http_methods(["PUT"])
def credential(request, integration_id):
    disabled = _enabled(request)
    if disabled:
        return disabled
    denied = _require_admin(request)
    if denied:
        return denied
    connection = _connection(request, integration_id)
    if not connection:
        return api_error(request, "resource_not_found", "The requested integration was not found.", status=404)
    payload = _payload(request)
    if payload is None:
        return api_error(request, "invalid_request_body", "A valid JSON request body is required.", status=400)
    try:
        stored = store_integration_secret(connection, str(payload.get("secret") or ""), label=str(payload.get("label") or "webhook-hmac"))
    except (ValueError, RuntimeError) as exc:
        return api_error(request, "credential_not_configured", str(exc), status=400)
    return JsonResponse({"integrationId": connection.pk, "label": stored.secret_label, "keyId": stored.secret_key_id, "encrypted": True})


@require_http_methods(["GET"])
def workspace_connections(request, route_ref):
    disabled = _enabled(request)
    if disabled:
        return disabled
    actor = actor_from_request(request)
    case = visible_cases_for_actor(actor).filter(route_ref=route_ref).first()
    if not case:
        return api_error(request, "resource_not_found", "The requested workspace was not found.", status=404)
    links = IntegrationCaseLink.objects.filter(case=case, organization_id=actor.organization_id).select_related("integration")
    return JsonResponse({"caseId": case.id, "results": [{**_connection_payload(link.integration), "link": {"id": link.id, "syncEnabled": link.sync_enabled, "syncStatus": link.sync_status, "externalCaseReference": link.external_case_reference}} for link in links]})


@csrf_exempt
@require_http_methods(["POST"])
def link_case(request, route_ref, integration_id):
    disabled = _enabled(request)
    if disabled:
        return disabled
    actor = actor_from_request(request)
    case = visible_cases_for_actor(actor).filter(route_ref=route_ref).first()
    connection = _connection(request, integration_id)
    if not case or not connection or connection.organization_id != case.organization_id:
        return api_error(request, "resource_not_found", "The requested resource was not found.", status=404)
    payload = _payload(request) or {}
    link, created = IntegrationCaseLink.objects.get_or_create(
        organization=case.organization,
        case=case,
        integration=connection,
        defaults={
            "external_case_reference": str(payload.get("externalCaseReference") or "")[:160],
            "created_by_id": actor.django_user_id,
        },
    )
    return JsonResponse({"id": link.id, "caseId": case.id, "integrationId": connection.pk, "syncStatus": link.sync_status}, status=201 if created else 200)


def _delivery_key(request, organization_id: UUID, operation: str):
    raw = (request.headers.get("Idempotency-Key") or "").strip()
    if not _IDEMPOTENCY_KEY.fullmatch(raw):
        return None
    return hashlib.sha256(f"{organization_id}\0{operation}\0{raw}".encode("utf-8")).hexdigest()


@csrf_exempt
@require_http_methods(["POST"])
def send_alerts(request, route_ref, job_id, integration_id):
    disabled = _delivery_enabled(request)
    if disabled:
        return disabled
    try:
        scope = resolve_analysis_scope(request, route_ref, job_id)
    except AnalysisScopeProblem as problem:
        return api_error(request, problem.code, "The requested analysis resource was not found.", status=problem.status)
    connection = _connection(request, integration_id)
    if not connection or connection.organization_id != scope.case.organization_id:
        return api_error(request, "resource_not_found", "The requested resource was not found.", status=404)
    key = _delivery_key(request, scope.case.organization_id, f"alerts:{job_id}:{integration_id}")
    if not key:
        return api_error(request, "invalid_idempotency_key", "A safe Idempotency-Key header is required.", status=400)
    alerts = scope.analysis.get("alerts") if isinstance(scope.analysis.get("alerts"), list) else []
    payload = {
        "source": "netra",
        "caseId": scope.case.id,
        "jobId": scope.job.id,
        "alerts": [
            {key: alert.get(key) for key in ("id", "attackClass", "severity", "confidence", "timestamp")}
            for alert in alerts[:20]
            if isinstance(alert, dict)
        ],
    }
    try:
        delivery, created = queue_delivery(
            integration=connection,
            case=scope.case,
            delivery_type="alerts",
            payload=payload,
            idempotency_key=key,
        )
    except WebhookDeliveryProblem as problem:
        return api_error(request, problem.code, str(problem), status=400)
    return JsonResponse({"deliveryId": delivery.pk, "status": delivery.result, "created": created}, status=202)


@csrf_exempt
@require_http_methods(["POST"])
def test_delivery(request, integration_id):
    disabled = _delivery_enabled(request)
    if disabled:
        return disabled
    denied = _require_admin(request)
    if denied:
        return denied
    connection = _connection(request, integration_id)
    if not connection:
        return api_error(request, "resource_not_found", "The requested integration was not found.", status=404)
    key = _delivery_key(request, connection.organization_id, f"test:{integration_id}")
    if not key:
        return api_error(request, "invalid_idempotency_key", "A safe Idempotency-Key header is required.", status=400)
    delivery, created = queue_delivery(
        integration=connection,
        case=None,
        delivery_type="test",
        payload={"source": "netra", "type": "integration.test"},
        idempotency_key=key,
    )
    return JsonResponse({"deliveryId": delivery.pk, "status": delivery.result, "created": created}, status=202)


@require_http_methods(["GET"])
def deliveries(request, integration_id):
    connection = _connection(request, integration_id)
    if not connection:
        return api_error(request, "resource_not_found", "The requested integration was not found.", status=404)
    rows = connection.deliveries.order_by("-created_at")[:50]
    return JsonResponse({"results": [{"id": row.pk, "caseId": row.case_id, "type": row.delivery_type, "result": row.result, "errorCode": row.error_code, "createdAt": row.created_at.isoformat()} for row in rows]})


@csrf_exempt
@require_http_methods(["POST"])
def retry_delivery(request, integration_id, delivery_id):
    connection = _connection(request, integration_id)
    delivery = IntegrationDelivery.objects.filter(pk=delivery_id, integration=connection).first() if connection else None
    if not delivery:
        return api_error(request, "resource_not_found", "The requested delivery was not found.", status=404)
    with transaction.atomic():
        locked = IntegrationDelivery.objects.select_for_update().get(pk=delivery.pk)
        locked.result = "queued"
        locked.attempt_count = 0
        locked.error_code = ""
        locked.response_summary = ""
        locked.next_attempt_at = None
        locked.save()
    return JsonResponse({"deliveryId": delivery.pk, "status": "queued"}, status=202)


@csrf_exempt
@require_http_methods(["POST"])
def external_sync(request, integration_id):
    return api_error(request, "feature_not_implemented", "No reviewed external synchronization adapter is installed.", status=501)
