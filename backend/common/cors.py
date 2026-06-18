from django.conf import settings
from django.http import HttpResponse


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
        if origin and (origin in allowed or (settings.DEBUG and not allowed)):
            response["Access-Control-Allow-Origin"] = origin
            response["Vary"] = "Origin"
        elif settings.DEBUG and not origin:
            response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, PATCH, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Netra-Role, X-Netra-User, X-Netra-Sensor-Key, Last-Event-ID"
        return response
