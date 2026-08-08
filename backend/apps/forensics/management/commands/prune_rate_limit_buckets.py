from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.forensics.models import ApiRateLimitBucket


class Command(BaseCommand):
    help = "Delete a bounded batch of expired API rate-limit buckets."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=1000)

    def handle(self, *args, **options):
        limit = max(1, min(int(options["limit"]), 10_000))
        ids = list(
            ApiRateLimitBucket.objects.filter(expires_at__lt=timezone.now())
            .order_by("expires_at")
            .values_list("id", flat=True)[:limit]
        )
        deleted, _ = ApiRateLimitBucket.objects.filter(id__in=ids).delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted} expired rate-limit bucket(s)."))
