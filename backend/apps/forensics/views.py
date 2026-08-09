"""One-release compatibility façade for legacy view imports.

New URL registrations import the feature-owned API modules.  This module stays
small so older tests and internal integrations can migrate without reopening
the former route monolith.
"""

from apps.forensics.api.legacy_views import *  # noqa: F401,F403
