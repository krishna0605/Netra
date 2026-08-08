from __future__ import annotations

from uuid import uuid4

from django.http import JsonResponse


def request_id(request) -> str:
    existing = getattr(request, "netra_request_id", "")
    if existing:
        return str(existing)
    incoming = (request.headers.get("X-Request-ID") or "").strip()
    value = incoming[:128] if incoming else uuid4().hex
    request.netra_request_id = value
    return value


def api_error(request, code: str, message: str, *, status: int) -> JsonResponse:
    response = JsonResponse(
        {
            "error": {
                "code": code,
                "message": message,
                "requestId": request_id(request),
            }
        },
        status=status,
    )
    response["X-Request-ID"] = request_id(request)
    return response


def analysis_not_found(request) -> JsonResponse:
    return api_error(
        request,
        "analysis_resource_not_found",
        "The requested analysis resource was not found.",
        status=404,
    )
