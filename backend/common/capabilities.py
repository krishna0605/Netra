from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from django.conf import settings


CapabilityState = Literal["available", "disabled", "not_implemented", "degraded"]


@dataclass(frozen=True)
class CapabilityDefinition:
    key: str
    implemented: bool
    enabled: bool
    state: CapabilityState
    reason: str
    requires_aal2: bool = False
    durable_consumer: str | None = None

    def as_public_dict(self) -> dict:
        return asdict(self)


def _defined(
    key: str,
    *,
    implemented: bool,
    enabled: bool,
    reason: str,
    requires_aal2: bool = False,
    durable_consumer: str | None = None,
    degraded: bool = False,
) -> CapabilityDefinition:
    if not implemented:
        state: CapabilityState = "not_implemented"
    elif degraded:
        state = "degraded"
    elif not enabled:
        state = "disabled"
    else:
        state = "available"
    return CapabilityDefinition(
        key=key,
        implemented=implemented,
        enabled=enabled,
        state=state,
        reason=reason,
        requires_aal2=requires_aal2,
        durable_consumer=durable_consumer,
    )


def capability_registry() -> dict[str, CapabilityDefinition]:
    integrations_enabled = bool(getattr(settings, "NETRA_ENABLE_INTEGRATIONS", False))
    delivery_enabled = integrations_enabled and bool(getattr(settings, "NETRA_WEBHOOK_ALLOWED_HOSTS", []))
    search_provider = getattr(settings, "NETRA_SEARCH_PROVIDER", "postgres")
    return {
        "user_invitations": _defined(
            "user_invitations",
            implemented=True,
            enabled=bool(getattr(settings, "NETRA_AUTH_INVITATIONS_ENABLED", False)),
            reason="Organization user invitations are available."
            if getattr(settings, "NETRA_AUTH_INVITATIONS_ENABLED", False)
            else "User invitations require an approved custom SMTP domain.",
            requires_aal2=True,
        ),
        "password_recovery": _defined(
            "password_recovery",
            implemented=True,
            enabled=bool(getattr(settings, "NETRA_PASSWORD_RECOVERY_ENABLED", False)),
            reason="Password recovery is available."
            if getattr(settings, "NETRA_PASSWORD_RECOVERY_ENABLED", False)
            else "Password recovery requires an approved custom SMTP domain.",
        ),
        "analysis_references": _defined(
            "analysis_references",
            implemented=True,
            enabled=True,
            reason="Durable workspace and analysis-job scoped references are available.",
        ),
        "structured_log_import": _defined(
            "structured_log_import",
            implemented=True,
            enabled=bool(getattr(settings, "NETRA_ENABLE_STRUCTURED_IMPORTS", False)),
            reason="Structured-log import is available."
            if getattr(settings, "NETRA_ENABLE_STRUCTURED_IMPORTS", False)
            else "Structured-log import is disabled for this deployment profile.",
            durable_consumer="postgres-worker:capture_log_import",
        ),
        "zeek_log_import": _defined(
            "zeek_log_import",
            implemented=True,
            enabled=bool(getattr(settings, "NETRA_ENABLE_STRUCTURED_IMPORTS", False)),
            reason="Zeek-log import is available."
            if getattr(settings, "NETRA_ENABLE_STRUCTURED_IMPORTS", False)
            else "Zeek-log import is disabled for this deployment profile.",
            durable_consumer="postgres-worker:zeek_log_import",
        ),
        "integration_configuration": _defined(
            "integration_configuration",
            implemented=True,
            enabled=integrations_enabled,
            reason="Integration configuration is disabled for this deployment profile."
            if not integrations_enabled
            else "Organization-scoped integration configuration is available.",
            requires_aal2=True,
        ),
        "integration_delivery": _defined(
            "integration_delivery",
            implemented=True,
            enabled=delivery_enabled,
            reason="Durable outbound webhook delivery is available."
            if delivery_enabled
            else "Outbound delivery requires integrations and an exact webhook hostname allowlist.",
            requires_aal2=True,
            durable_consumer="postgres-worker:integration_delivery",
        ),
        "integration_case_linking": _defined(
            "integration_case_linking",
            implemented=True,
            enabled=integrations_enabled,
            reason="Durable organization-scoped case links are available."
            if integrations_enabled
            else "Integration case linking is disabled for this deployment profile.",
        ),
        "integration_external_sync": _defined(
            "integration_external_sync",
            implemented=False,
            enabled=False,
            reason="No reviewed external synchronization adapter is installed.",
        ),
        "sse": _defined(
            "sse",
            implemented=True,
            enabled=getattr(settings, "NETRA_REALTIME_PROVIDER", "sse") == "sse",
            reason="Bounded authenticated Django SSE is available."
            if getattr(settings, "NETRA_REALTIME_PROVIDER", "sse") == "sse"
            else "Django SSE is not the selected realtime provider.",
        ),
        "postgres_search": _defined(
            "postgres_search",
            implemented=True,
            enabled=search_provider == "postgres",
            reason="Scoped Postgres search is available."
            if search_provider == "postgres"
            else "Postgres search is not the selected provider.",
        ),
        "elasticsearch_search": _defined(
            "elasticsearch_search",
            implemented=True,
            enabled=False,
            reason="Elasticsearch search is experimental and disabled in production.",
        ),
        "capture_stop": _defined(
            "capture_stop",
            implemented=True,
            enabled=bool(getattr(settings, "NETRA_ENABLE_SENSOR_CAPTURE", False)),
            reason="Capture controls are disabled for this deployment profile."
            if not getattr(settings, "NETRA_ENABLE_SENSOR_CAPTURE", False)
            else "Scoped capture control is available.",
        ),
    }


def public_capabilities() -> dict[str, dict]:
    return {key: value.as_public_dict() for key, value in capability_registry().items()}
