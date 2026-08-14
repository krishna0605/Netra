from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings
from django.db import connection, transaction


@dataclass(frozen=True)
class AccessLogMaintenanceResult:
    status: str
    created_partitions: int = 0
    dropped_partitions: int = 0
    deleted_rows: int = 0


def maintain_access_log_partitions() -> AccessLogMaintenanceResult:
    """Create the rolling partition window and enforce the configured retention."""
    if connection.vendor != "postgresql":
        return AccessLogMaintenanceResult(status="not-postgresql")

    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute(
            "SELECT created_partitions, dropped_partitions, deleted_rows "
            "FROM public.netra_maintain_access_log_partitions(%s)",
            [settings.NETRA_ACCESS_LOG_RETENTION_DAYS],
        )
        row = cursor.fetchone()
    if row is None:
        raise RuntimeError("AccessLog partition maintenance returned no result")
    return AccessLogMaintenanceResult(
        status="ok",
        created_partitions=int(row[0]),
        dropped_partitions=int(row[1]),
        deleted_rows=int(row[2]),
    )
