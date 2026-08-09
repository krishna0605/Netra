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
        and (not settings.NETRA_REQUIRE_WORKER_RELEASE_MATCH or details.get("releaseId") == settings.NETRA_RELEASE_ID)
        and isinstance(details.get("capabilities"), dict)
        and details["capabilities"].get("pcap") is True
        and details["capabilities"].get("pcapng") is True
        and isinstance(details["capabilities"].get("tshark"), dict)
        and details["capabilities"]["tshark"].get("available") is True
        and details["capabilities"]["tshark"].get("version") == settings.NETRA_REQUIRED_TSHARK_VERSION
        and isinstance(details["capabilities"].get("zeek"), dict)
        and details["capabilities"]["zeek"].get("available") is True
        and details["capabilities"]["zeek"].get("version") == settings.NETRA_REQUIRED_ZEEK_VERSION
        for details in candidates
    )
    cache.set(CAPACITY_CACHE_KEY, available, settings.NETRA_WORKER_CAPACITY_CACHE_SECONDS)
    return available


def analysis_admission_available() -> bool:
    return not analysis_capacity_required() or compatible_analysis_worker_available()


def invalidate_worker_capacity_cache() -> None:
    cache.delete(CAPACITY_CACHE_KEY)
