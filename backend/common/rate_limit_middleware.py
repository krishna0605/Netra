from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse

from common.rate_limits import RateLimitSpec, consume_rate_limits, request_byte_count


EXEMPT_PATHS = {"/api/health", "/api/auth/login", "/api/auth/refresh"}


def rate_limit_response(result):
    status = 503 if result.unavailable else 429
    code = "rate_limit_unavailable" if result.unavailable else "rate_limit_exceeded"
    response = JsonResponse(
        {"error": {"code": code, "message": "Request limiting is temporarily unavailable." if result.unavailable else "Too many requests. Retry later."}},
        status=status,
    )
    response["Retry-After"] = str(result.retry_after)
    response["X-RateLimit-Limit"] = str(result.limit)
    response["X-RateLimit-Remaining"] = str(result.remaining)
    response["X-RateLimit-Reset"] = str(int(result.reset_at.timestamp()))
    response["X-RateLimit-Scope"] = result.scope
    return response


class NetraRateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path.rstrip("/") or "/"
        actor = getattr(request, "netra_actor", None)
        if (
            not settings.NETRA_RATE_LIMITS_ENABLED
            or not path.startswith("/api/")
            or path in EXEMPT_PATHS
            or request.method == "OPTIONS"
            or actor is None
            or not actor.organization_id
            or getattr(request, "netra_sensor_authenticated", False)
        ):
            return self.get_response(request)
        if request.method in {"GET", "HEAD"}:
            spec = RateLimitSpec("read", settings.NETRA_RATE_LIMIT_READ_PER_MINUTE, 60)
        else:
            spec = RateLimitSpec("mutation", settings.NETRA_RATE_LIMIT_MUTATION_PER_MINUTE, 60)
        result = consume_rate_limits(actor, [spec], byte_count=request_byte_count(request))
        if not result.allowed:
            return rate_limit_response(result)
        response = self.get_response(request)
        response["X-RateLimit-Limit"] = str(result.limit)
        response["X-RateLimit-Remaining"] = str(result.remaining)
        response["X-RateLimit-Reset"] = str(int(result.reset_at.timestamp()))
        response["X-RateLimit-Scope"] = result.scope
        return response
