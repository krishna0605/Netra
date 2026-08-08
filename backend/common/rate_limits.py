from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db import DatabaseError, IntegrityError, transaction
from django.utils import timezone

from apps.forensics.models import ApiRateLimitBucket
from common.audit import Actor


@dataclass(frozen=True)
class RateLimitSpec:
    route_key: str
    limit: int
    window_seconds: int
    scope: str = "user"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_at: datetime
    scope: str
    unavailable: bool = False

    @property
    def retry_after(self) -> int:
        return max(1, int((self.reset_at - timezone.now()).total_seconds()) + 1)


def _window_start(now: datetime, seconds: int) -> datetime:
    epoch = int(now.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % seconds), tz=dt_timezone.utc)


def _scope(actor: Actor, spec: RateLimitSpec):
    if spec.scope == "organization":
        return f"org:{actor.organization_id}", None
    return f"user:{actor.django_user_id}", actor.django_user_id


def consume_rate_limits(actor: Actor, specs: list[RateLimitSpec], *, byte_count: int = 0) -> RateLimitResult:
    if not specs or not actor.organization_id:
        now = timezone.now()
        return RateLimitResult(True, 0, 0, now, "none")
    now = timezone.now()
    bounded_bytes = max(0, min(int(byte_count or 0), 1 << 40))
    try:
        with transaction.atomic():
            pending = []
            strictest = None
            for spec in specs:
                scope_key, user_id = _scope(actor, spec)
                start = _window_start(now, spec.window_seconds)
                expires_at = start + timedelta(seconds=spec.window_seconds * 2)
                try:
                    bucket, _ = ApiRateLimitBucket.objects.get_or_create(
                        organization_id=actor.organization_id,
                        scope_key=scope_key,
                        route_key=spec.route_key,
                        defaults={
                            "user_id": user_id,
                            "window_start": start,
                            "window_seconds": spec.window_seconds,
                            "expires_at": expires_at,
                        },
                    )
                except IntegrityError:
                    bucket = ApiRateLimitBucket.objects.get(
                        organization_id=actor.organization_id,
                        scope_key=scope_key,
                        route_key=spec.route_key,
                    )
                bucket = ApiRateLimitBucket.objects.select_for_update().get(pk=bucket.pk)
                if bucket.window_start != start or bucket.window_seconds != spec.window_seconds:
                    bucket.window_start = start
                    bucket.window_seconds = spec.window_seconds
                    bucket.request_count = 0
                    bucket.byte_count = 0
                reset_at = start + timedelta(seconds=spec.window_seconds)
                candidate = RateLimitResult(
                    bucket.request_count < spec.limit,
                    spec.limit,
                    max(0, spec.limit - bucket.request_count - 1),
                    reset_at,
                    spec.scope,
                )
                if not candidate.allowed and (strictest is None or candidate.retry_after > strictest.retry_after):
                    strictest = candidate
                bucket.expires_at = expires_at
                pending.append((bucket, candidate))
            if strictest:
                transaction.set_rollback(True)
                return strictest
            for bucket, _candidate in pending:
                bucket.request_count += 1
                bucket.byte_count += bounded_bytes
                bucket.save(
                    update_fields=[
                        "window_start",
                        "window_seconds",
                        "request_count",
                        "byte_count",
                        "expires_at",
                        "updated_at",
                    ]
                )
            return min((candidate for _, candidate in pending), key=lambda item: item.remaining)
    except DatabaseError:
        now = timezone.now()
        return RateLimitResult(False, 0, 0, now + timedelta(seconds=60), "database", unavailable=True)


def request_byte_count(request) -> int:
    try:
        return max(0, min(int(request.headers.get("Content-Length", "0")), 1 << 30))
    except (TypeError, ValueError):
        return 0
