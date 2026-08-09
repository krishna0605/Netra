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
    search_provider = getattr(settings, "NETRA_SEARCH_PROVIDER", "postgres")
    return {
        "analysis_references": _defined(
            "analysis_references",
            implemented=False,
            enabled=False,
            reason="Durable scoped analysis references are not installed yet.",
        ),
        "structured_log_import": _defined(
            "structured_log_import",
            implemented=False,
            enabled=False,
            reason="The durable structured-log consumer is not installed yet.",
        ),
        "zeek_log_import": _defined(
            "zeek_log_import",
            implemented=False,
            enabled=False,
            reason="The durable Zeek-log consumer is not installed yet.",
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
            implemented=False,
            enabled=False,
            reason="Outbound delivery remains unavailable until the durable worker is installed.",
            requires_aal2=True,
        ),
        "integration_case_linking": _defined(
            "integration_case_linking",
            implemented=False,
            enabled=False,
            reason="Durable integration case links are not installed yet.",
        ),
        "integration_external_sync": _defined(
            "integration_external_sync",
            implemented=False,
            enabled=False,
            reason="No reviewed external synchronization adapter is installed.",
        ),
        "sse": _defined(
            "sse",
            implemented=False,
            enabled=False,
            reason="The bounded authenticated SSE transport is not installed yet.",
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

