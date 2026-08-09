class ApiSecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path.startswith("/api/"):
            response.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            response.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
            response.setdefault("X-Content-Type-Options", "nosniff")
            response.setdefault("X-Frame-Options", "DENY")
            response.setdefault("Referrer-Policy", "no-referrer")
            response.setdefault("Cross-Origin-Resource-Policy", "cross-origin")
            response.setdefault("Cache-Control", "no-store")
        return response
