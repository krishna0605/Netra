from __future__ import annotations

from django.conf import settings
from django.http import JsonResponse


ADMIN_NAMESPACE = "/api/admin/v1/"


class AdminConsoleOriginMiddleware:
    """Restrict the administration namespace to the origins that serve it.

    This is defence in depth, not the authorization control. Every view under
    the namespace still resolves an actor, re-reads the administrator profile
    from the database and requires aal2 — a request that gets past this guard
    has gained nothing. What the guard removes is the class of attack where a
    page on an unrelated origin uses a signed-in officer's browser to reach
    administrative routes.

    Two decisions worth stating plainly.

    It answers 404 rather than 403. A 403 confirms the namespace exists and is
    worth attacking; a 404 is indistinguishable from a route that was never
    deployed. That matters here because the whole hosting design keeps the word
    "admin" out of anything a user or a search engine can see, and an
    authenticated-looking rejection would undo it.

    A request with no Origin header passes through. Browsers attach Origin to
    every cross-origin request, which is the case this guard exists for — the
    console and the API are on different hosts in both local development and
    production. Requests without the header are not browser cross-origin
    requests: server-to-server calls, health probes, curl. Rejecting them would
    break operational tooling while stopping nothing, because anything that can
    omit a header can also forge one.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(ADMIN_NAMESPACE):
            origin = request.headers.get("Origin", "").strip()
            allowed = [item.strip() for item in getattr(settings, "NETRA_ADMIN_ORIGINS", []) if item.strip()]
            if origin and origin not in allowed:
                return JsonResponse(
                    {"error": "Resource not found", "code": "resource_not_found"},
                    status=404,
                )
        return self.get_response(request)
