"""Administration console API.

Kept in its own module for the same reason authentication.py is: the routes
that can change who holds which permission should not be reachable by editing
a file whose job is something else. The module boundary test names this file
explicitly.

Every view here goes through require_privileged_admin, which re-reads the
administrator profile from the database on each request. That matters more than
it looks. The console is served from a frozen URL that never says "admin", and
that URL is privacy hardening — it hides which screen an operator is on from
browser history and shoulder-surfers. It authorizes nothing. Authorization is
this check, on every request, regardless of which bundle the edge happened to
serve.
"""

from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from apps.forensics.api.errors import api_error
from apps.forensics.models import Organization
from apps.forensics.services.administration import AdministrationProblem, require_privileged_admin
from apps.forensics.services.admin_directory import directory_snapshot, role_slug
from common.audit import ROLE_PERMISSIONS, Actor, actor_from_request, log_access


def _privileged_actor(request) -> tuple[Actor | None, JsonResponse | None]:
    actor = actor_from_request(request)
    if not actor.authenticated:
        return None, api_error(request, "authentication_required", "Authentication required.", status=401)
    try:
        require_privileged_admin(actor, actor.organization_id)
    except AdministrationProblem as problem:
        # Recorded whether or not it succeeded: a refused attempt to reach the
        # administration namespace is exactly the event an audit reviewer wants
        # to find, and it is invisible if only successes are written.
        log_access(actor, "admin_console.denied", resource_type="AdminConsole", result="denied")
        return None, api_error(request, problem.code, problem.message, status=problem.status)
    return actor, None


@require_http_methods(["GET"])
def admin_session(request):
    """Resolve the caller's own administrative standing.

    The console calls this before it offers Administration as a workspace. It
    replaces a local fallback in the browser that treated any account that
    could authenticate as an administrator — fenced behind a development flag,
    but the wrong shape of answer to trust for anything.
    """
    actor, denied = _privileged_actor(request)
    if denied:
        return denied
    log_access(actor, "admin_console.session", resource_type="AdminConsole", result="allowed")
    return JsonResponse(
        {
            "userId": actor.django_user_id,
            "name": actor.user,
            "email": actor.email,
            "role": actor.role,
            "roleSlug": role_slug(actor.role),
            "aal": actor.aal,
            "permissions": sorted(ROLE_PERMISSIONS.get(actor.role, set())),
            "organization": {
                "id": str(actor.organization_id),
                "slug": actor.organization_slug,
            },
        }
    )


@require_http_methods(["GET"])
def admin_directory(request):
    """One read for all nine screens. See services/admin_directory.py."""
    actor, denied = _privileged_actor(request)
    if denied:
        return denied
    organization = Organization.objects.filter(pk=actor.organization_id).first()
    if organization is None:
        return api_error(request, "resource_not_found", "The requested resource was not found.", status=404)
    log_access(actor, "admin_console.directory", resource_type="AdminConsole", result="allowed")
    return JsonResponse(directory_snapshot(organization))
