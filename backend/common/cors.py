from django.conf import settings
from django.http import HttpResponse
from django.utils.cache import patch_vary_headers


class LocalCorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "OPTIONS":
            response = HttpResponse()
        else:
            response = self.get_response(request)
        origin = request.headers.get("Origin", "")
        allowed = [item.strip() for item in getattr(settings, "NETRA_FRONTEND_ORIGINS", []) if item.strip()]
        if origin and origin in allowed:
            response["Access-Control-Allow-Origin"] = origin
            patch_vary_headers(response, ("Origin",))
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        allowed_headers = ["Content-Type", "Authorization", "X-Netra-Sensor-Key", "Last-Event-ID"]
        if settings.NETRA_DEV_ROLE_HEADERS:
            allowed_headers.extend(["X-Netra-Role", "X-Netra-User"])
        response["Access-Control-Allow-Headers"] = ", ".join(allowed_headers)
        response["Access-Control-Expose-Headers"] = "Content-Disposition, Content-Length, X-Request-ID"
        response["Access-Control-Max-Age"] = "600"
        return response
