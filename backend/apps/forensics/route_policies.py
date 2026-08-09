from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


AuthenticationPolicy = Literal["anonymous", "bearer", "sensor-key"]
ScopePolicy = Literal["none", "organization", "case", "case+job"]
AalPolicy = Literal["none", "aal1", "aal2"]
RatePolicy = Literal["read", "mutation", "specialized", "excluded"]


@dataclass(frozen=True)
class RoutePolicy:
    authentication: AuthenticationPolicy
    scope: ScopePolicy
    capability: str | None
    aal: AalPolicy
    rate_category: RatePolicy
    deprecated: bool = False


_ANONYMOUS = {"health", "capabilities", "auth/login", "auth/refresh"}
_SENSOR_SUFFIXES = (
    "sensors/register",
    "/heartbeat",
    "/commands/next",
    "/chunks",
    "/complete",
    "/fail",
)
_AAL2_PREFIXES = ("setup/", "users", "admin/")
_MUTATION_MARKERS = (
    "/status",
    "/notes",
    "/flags",
    "/links",
    "/members",
    "/start",
    "/stop",
    "/cancel",
    "/retry",
    "/ignore",
    "/reprocess",
    "/run-now",
    "/enable",
    "/disable",
    "/execute",
    "/legal-hold",
    "/sync",
    "/test",
    "/credential",
)
_DEPRECATED_PREFIXES = (
    "dashboard/",
    "alerts",
    "packets",
    "sessions",
    "decoder/",
    "payloads",
    "detection/matches",
    "anomalies",
    "graph",
    "search",
    "capture/live/stop",
    "capture/replay/stop",
)


def _capability(route: str) -> str | None:
    if "/references/" in route:
        return "analysis_references"
    if route.endswith("imports/capture-log") or route == "capture/log-import":
        return "structured_log_import"
    if route.endswith("imports/zeek-log") or route == "logs/import/zeek":
        return "zeek_log_import"
    if route == "events/stream":
        return "sse"
    if route == "search" or route.endswith("/search"):
        return "postgres_search"
    if route.startswith("integrations") or "/integrations" in route:
        if route.endswith("/sync"):
            return "integration_external_sync"
        if route.endswith("/link"):
            return "integration_case_linking"
        if route.endswith("/alerts") or "/deliveries" in route or route.endswith("/test"):
            return "integration_delivery"
        return "integration_configuration"
    if "/capture/jobs/" in route and route.endswith("/stop"):
        return "capture_stop"
    return None


def _authentication(route: str) -> AuthenticationPolicy:
    if route in _ANONYMOUS:
        return "anonymous"
    if route.startswith("sensors/") and any(route == suffix or route.endswith(suffix) for suffix in _SENSOR_SUFFIXES):
        return "sensor-key"
    return "bearer"


def _scope(route: str, authentication: AuthenticationPolicy) -> ScopePolicy:
    if authentication in {"anonymous", "sensor-key"} or route.startswith("auth/"):
        return "none"
    if route == "search" or ("route_ref" in route and "job_id" in route):
        return "case+job"
    if any(
        marker in route
        for marker in (
            "case_id",
            "route_ref",
            "evidence_id",
            "report_id",
            "export_id",
            "upload_session_id",
            "job_id",
        )
    ):
        return "case"
    return "organization"


def _rate_category(route: str, authentication: AuthenticationPolicy) -> RatePolicy:
    if authentication in {"anonymous", "sensor-key"}:
        return "excluded"
    if any(
        marker in route
        for marker in (
            "upload",
            "imports/",
            "report",
            "export",
            "events/stream",
            "integrations",
        )
    ):
        return "specialized"
    if any(marker in route for marker in _MUTATION_MARKERS):
        return "mutation"
    return "read"


def policy_for_route(route: str) -> RoutePolicy:
    normalized = route.strip("/")
    authentication = _authentication(normalized)
    aal: AalPolicy = "none" if authentication != "bearer" else "aal1"
    if authentication == "bearer" and (
        normalized.startswith(_AAL2_PREFIXES)
        or (normalized.startswith("integrations/") and normalized.endswith("/credential"))
    ):
        aal = "aal2"
    return RoutePolicy(
        authentication=authentication,
        scope=_scope(normalized, authentication),
        capability=_capability(normalized),
        aal=aal,
        rate_category=_rate_category(normalized, authentication),
        deprecated=normalized.startswith(_DEPRECATED_PREFIXES),
    )


def attach_route_policies(urlpatterns) -> None:
    for pattern in urlpatterns:
        route = str(pattern.pattern)
        pattern.netra_route_policy = policy_for_route(route)


def route_policy_inventory(urlpatterns) -> list[dict]:
    inventory = []
    for pattern in urlpatterns:
        policy = getattr(pattern, "netra_route_policy", None)
        if policy is None:
            raise RuntimeError(f"Route {pattern.pattern} has no Netra security policy.")
        inventory.append(
            {
                "route": str(pattern.pattern),
                "view": f"{pattern.callback.__module__}.{pattern.callback.__name__}",
                **asdict(policy),
            }
        )
    return sorted(inventory, key=lambda item: (item["route"], item["view"]))
