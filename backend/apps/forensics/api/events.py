from __future__ import annotations

import json
import time

from django.conf import settings
from django.db import close_old_connections
from django.http import JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_http_methods

from apps.forensics.api.errors import api_error
from apps.forensics.models import OperationalEvent
from common.audit import actor_from_request, visible_cases_for_actor
from common.rate_limits import RateLimitSpec, consume_rate_limits
from common.rate_limit_middleware import rate_limit_response


def _cursor(request):
    value = (request.headers.get("Last-Event-ID") or request.GET.get("lastEventId") or "0").strip()
    try:
        cursor = int(value)
    except (TypeError, ValueError):
        return None
    return cursor if cursor >= 0 else None


def _event_payload(row: OperationalEvent) -> dict:
    payload = row.payload_json if isinstance(row.payload_json, dict) else {}
    return {
        "id": row.pk,
        "type": row.event_type,
        "caseId": row.case_id,
        "captureJobId": row.capture_job_id,
        "jobId": str(payload.get("jobId") or ""),
        "occurredAt": row.created_at.isoformat(),
    }


@require_http_methods(["GET"])
def event_stream(request):
    actor = actor_from_request(request)
    route_ref = (request.GET.get("caseRef") or "").strip()
    if not route_ref:
        return api_error(request, "scope_required", "A workspace reference is required.", status=400)
    case = visible_cases_for_actor(actor).filter(route_ref=route_ref).first()
    if not case:
        return api_error(request, "resource_not_found", "The requested workspace was not found.", status=404)
    cursor = _cursor(request)
    if cursor is None:
        return api_error(request, "invalid_event_cursor", "Last-Event-ID must be a non-negative integer.", status=400)
    limit = consume_rate_limits(
        actor,
        [
            RateLimitSpec("sse-connect", settings.NETRA_RATE_LIMIT_SSE_USER_PER_MINUTE, 60),
            RateLimitSpec("sse-connect-org", settings.NETRA_RATE_LIMIT_SSE_ORG_PER_MINUTE, 60, scope="organization"),
        ],
    )
    if not limit.allowed:
        return rate_limit_response(limit)

    def generate():
        last_id = cursor
        started = time.monotonic()
        heartbeat_at = started
        yield "retry: 5000\n\n"
        try:
            while time.monotonic() - started < settings.NETRA_SSE_MAX_SECONDS:
                close_old_connections()
                rows = list(
                    OperationalEvent.objects.filter(
                        organization_id=actor.organization_id,
                        case=case,
                        pk__gt=last_id,
                    )
                    .only("id", "event_type", "case_id", "capture_job_id", "payload_json", "created_at")
                    .order_by("id")[: settings.NETRA_SSE_BATCH_SIZE]
                )
                for row in rows:
                    last_id = row.pk
                    payload = json.dumps(_event_payload(row), separators=(",", ":"))
                    yield f"id: {row.pk}\nevent: invalidate\ndata: {payload}\n\n"
                now = time.monotonic()
                if now - heartbeat_at >= settings.NETRA_SSE_HEARTBEAT_SECONDS:
                    heartbeat_at = now
                    yield ": heartbeat\n\n"
                remaining = settings.NETRA_SSE_MAX_SECONDS - (now - started)
                if remaining <= 0:
                    break
                time.sleep(min(settings.NETRA_SSE_POLL_SECONDS, remaining))
        finally:
            close_old_connections()

    response = StreamingHttpResponse(generate(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache, no-store"
    response["X-Accel-Buffering"] = "no"
    response["X-RateLimit-Limit"] = str(limit.limit)
    response["X-RateLimit-Remaining"] = str(limit.remaining)
    return response

