"""One-release compatibility façade for legacy view imports.

New URL registrations import the feature-owned API modules.  This module stays
small so older tests and internal integrations can migrate without reopening
the former route monolith.
"""

from apps.forensics.api.legacy_views import (
    integration_case_link,
    integration_case_link_detail,
    integration_deliveries,
    integration_delivery_retry,
    integration_detail,
    integration_send_alerts,
    integration_sync,
    integration_test,
    integrations,
    operational_event_stream,
)

__all__ = [
    "integration_case_link",
    "integration_case_link_detail",
    "integration_deliveries",
    "integration_delivery_retry",
    "integration_detail",
    "integration_send_alerts",
    "integration_sync",
    "integration_test",
    "integrations",
    "operational_event_stream",
]
