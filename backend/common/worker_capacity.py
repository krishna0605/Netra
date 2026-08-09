from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.forensics.models import WorkerHeartbeat


CAPACITY_CACHE_KEY = "netra:worker-capacity:postgres-analysis"


def analysis_capacity_required() -> bool:
    return not (settings.DEBUG and settings.NETRA_DEPLOYMENT_PROFILE == "local")


def compatible_analysis_worker_available() -> bool:
    """Return whether a recent worker advertises the production queue contract."""
    cached = cache.get(CAPACITY_CACHE_KEY)
    if cached is not None:
        return bool(cached)
    cutoff = timezone.now() - timedelta(seconds=settings.NETRA_WORKER_STALE_AFTER_SECONDS)
    candidates = WorkerHeartbeat.objects.filter(
        worker_name="postgres-analysis",
        status="healthy",
        last_seen_at__gte=cutoff,
    ).values_list("details_json", flat=True)
    available = any(
        isinstance(details, dict)
        and details.get("runtimeRole", "worker") == "worker"
        and details.get("processingMode") == "postgres-worker"
        and details.get("queueProvider") == "postgres-row-lock"
        for details in candidates
    )
    cache.set(CAPACITY_CACHE_KEY, available, settings.NETRA_WORKER_CAPACITY_CACHE_SECONDS)
    return available


def analysis_admission_available() -> bool:
    return not analysis_capacity_required() or compatible_analysis_worker_available()


def invalidate_worker_capacity_cache() -> None:
    cache.delete(CAPACITY_CACHE_KEY)
