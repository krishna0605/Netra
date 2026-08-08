from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import ApiRateLimitBucket, Case, ProcessingJob, UserProfile
from common.audit import Actor
from common.queue_limits import OrganizationQueueLimit, lock_and_check_queue_capacity
from common.rate_limits import RateLimitSpec, consume_rate_limits
from common.tenancy import netra_organization


SECURE_SETTINGS = override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_DEV_ROLE_HEADERS=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_RATE_LIMITS_ENABLED=True,
)


@SECURE_SETTINGS
class RateLimitTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        self.user = get_user_model().objects.create_user(username="limited@example.test")
        UserProfile.objects.create(user=self.user, organization=self.organization, role="Investigator")
        self.actor = Actor(
            user=self.user.username,
            role="Investigator",
            authenticated=True,
            django_user_id=self.user.id,
            organization_id=self.organization.id,
            organization_slug=self.organization.slug,
        )

    def test_exact_limit_succeeds_and_next_request_is_rejected(self):
        spec = RateLimitSpec("focused-test", 2, 60)
        first = consume_rate_limits(self.actor, [spec])
        second = consume_rate_limits(self.actor, [spec])
        rejected = consume_rate_limits(self.actor, [spec])

        self.assertTrue(first.allowed)
        self.assertTrue(second.allowed)
        self.assertFalse(rejected.allowed)
        self.assertEqual(rejected.remaining, 0)
        bucket = ApiRateLimitBucket.objects.get(route_key="focused-test")
        self.assertEqual(bucket.request_count, 2)

    def test_user_and_organization_limits_are_evaluated_atomically(self):
        specs = [
            RateLimitSpec("upload-test", 10, 3600),
            RateLimitSpec("upload-test", 1, 3600, scope="organization"),
        ]
        self.assertTrue(consume_rate_limits(self.actor, specs, byte_count=512).allowed)
        self.assertFalse(consume_rate_limits(self.actor, specs, byte_count=512).allowed)
        user_bucket = ApiRateLimitBucket.objects.get(scope_key=f"user:{self.user.id}", route_key="upload-test")
        organization_bucket = ApiRateLimitBucket.objects.get(scope_key=f"org:{self.organization.id}", route_key="upload-test")
        self.assertEqual(user_bucket.request_count, 1)
        self.assertEqual(organization_bucket.request_count, 1)
        self.assertEqual(user_bucket.byte_count, 512)

    @override_settings(NETRA_RATE_LIMIT_READ_PER_MINUTE=2)
    def test_middleware_returns_rate_headers_and_retry_after(self):
        client = Client()
        headers = {"HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.user).access_token}"}
        self.assertEqual(client.get("/api/cases", **headers).status_code, 200)
        second = client.get("/api/cases", **headers)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second["X-RateLimit-Remaining"], "0")
        rejected = client.get("/api/cases", **headers)
        self.assertEqual(rejected.status_code, 429)
        self.assertEqual(rejected.json()["error"]["code"], "rate_limit_exceeded")
        self.assertTrue(int(rejected["Retry-After"]) > 0)

    def test_stale_window_resets_counter(self):
        spec = RateLimitSpec("window-reset-test", 1, 60)
        self.assertTrue(consume_rate_limits(self.actor, [spec]).allowed)
        ApiRateLimitBucket.objects.filter(route_key="window-reset-test").update(
            window_start=timezone.now() - timedelta(minutes=5),
            expires_at=timezone.now() - timedelta(minutes=1),
        )
        self.assertTrue(consume_rate_limits(self.actor, [spec]).allowed)


class OrganizationQueueLimitTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        self.organization.max_queued_analyses = 1
        self.organization.save(update_fields=["max_queued_analyses", "updated_at"])
        self.case = Case.objects.create(
            id="CASE-QUEUE-LIMIT",
            display_reference="CASE-QUEUE-LIMIT",
            organization=self.organization,
            title="Queue",
            investigator="Investigator",
        )

    def test_active_jobs_consume_capacity_but_completed_jobs_do_not(self):
        ProcessingJob.objects.create(id="job-active", case=self.case, status=ProcessingJob.Status.QUEUED)
        with self.assertRaises(OrganizationQueueLimit):
            lock_and_check_queue_capacity(self.organization.id, job_id="job-next")
        ProcessingJob.objects.filter(pk="job-active").update(status=ProcessingJob.Status.COMPLETED)
        locked = lock_and_check_queue_capacity(self.organization.id, job_id="job-next")
        self.assertEqual(locked.id, self.organization.id)

    def test_idempotent_existing_job_does_not_consume_another_slot(self):
        ProcessingJob.objects.create(id="job-replay", case=self.case, status=ProcessingJob.Status.RUNNING)
        locked = lock_and_check_queue_capacity(self.organization.id, job_id="job-replay")
        self.assertEqual(locked.id, self.organization.id)
