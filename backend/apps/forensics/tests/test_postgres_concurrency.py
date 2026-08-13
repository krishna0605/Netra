from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from django.contrib.auth import get_user_model
from django.db import connection, connections, transaction
from django.test import TransactionTestCase, skipUnlessDBFeature

from apps.forensics.models import (
    AccessLog,
    ApiRateLimitBucket,
    Case,
    OperationalEvent,
    Organization,
    ProcessingJob,
    UserProfile,
)
from apps.forensics.services.administration import AdministrationProblem, transfer_administrator
from common.audit import Actor
from common.queue_limits import OrganizationQueueLimit, lock_and_check_queue_capacity
from common.rate_limits import RateLimitSpec, consume_rate_limits


class PostgreSQLSecurityConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL is required for row-lock concurrency verification.")
        self.organization = Organization.objects.create(
            name="PostgreSQL concurrency",
            slug="postgres-concurrency",
            max_queued_analyses=5,
        )

    @skipUnlessDBFeature("has_select_for_update")
    def test_rate_limit_never_exceeds_exact_concurrent_limit(self):
        user = get_user_model().objects.create_user(username="concurrent-limit@example.test")
        UserProfile.objects.create(user=user, organization=self.organization, role=UserProfile.Role.INVESTIGATOR)
        actor_values = {
            "user": user.username,
            "role": UserProfile.Role.INVESTIGATOR,
            "authenticated": True,
            "django_user_id": user.id,
            "organization_id": self.organization.id,
            "organization_slug": self.organization.slug,
        }
        barrier = Barrier(20)

        def consume(_sequence):
            connections.close_all()
            barrier.wait(timeout=10)
            result = consume_rate_limits(Actor(**actor_values), [RateLimitSpec("postgres-concurrent", 10, 60)])
            connections.close_all()
            return result.allowed, result.unavailable

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(consume, range(20)))

        self.assertEqual(sum(allowed for allowed, _ in results), 10)
        self.assertFalse(any(unavailable for _, unavailable in results))
        self.assertEqual(ApiRateLimitBucket.objects.get(route_key="postgres-concurrent").request_count, 10)

    @skipUnlessDBFeature("has_select_for_update")
    def test_queue_creation_never_exceeds_organization_capacity(self):
        case = Case.objects.create(
            id="CASE-PG-QUEUE",
            organization=self.organization,
            display_reference="CASE-PG-QUEUE",
            title="Concurrent queue",
            investigator="Synthetic Investigator",
        )
        barrier = Barrier(10)

        def create_job(sequence):
            connections.close_all()
            barrier.wait(timeout=10)
            try:
                with transaction.atomic():
                    lock_and_check_queue_capacity(self.organization.id, job_id=f"pg-job-{sequence}")
                    ProcessingJob.objects.create(
                        id=f"pg-job-{sequence}",
                        case_id=case.id,
                        status=ProcessingJob.Status.QUEUED,
                    )
                created = True
            except OrganizationQueueLimit:
                created = False
            finally:
                connections.close_all()
            return created

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(create_job, range(10)))

        self.assertEqual(sum(results), 5)
        self.assertEqual(
            ProcessingJob.objects.filter(case=case, status=ProcessingJob.Status.QUEUED).count(),
            5,
        )

    @skipUnlessDBFeature("has_select_for_update")
    def test_competing_admin_transfers_leave_one_admin_and_one_audit_pair(self):
        admin = get_user_model().objects.create_user(username="concurrent-admin@example.test", is_active=True)
        UserProfile.objects.create(user=admin, organization=self.organization, role=UserProfile.Role.ADMIN)
        targets = []
        for sequence in range(2):
            target = get_user_model().objects.create_user(
                username=f"concurrent-target-{sequence}@example.test",
                is_active=True,
            )
            UserProfile.objects.create(
                user=target,
                organization=self.organization,
                role=UserProfile.Role.INVESTIGATOR,
            )
            targets.append(target)
        actor_values = {
            "user": admin.username,
            "role": UserProfile.Role.ADMIN,
            "authenticated": True,
            "django_user_id": admin.id,
            "organization_id": self.organization.id,
            "organization_slug": self.organization.slug,
            "aal": "aal2",
        }
        barrier = Barrier(2)

        def transfer(target_id):
            connections.close_all()
            barrier.wait(timeout=10)
            try:
                transfer_administrator(
                    actor=Actor(**actor_values),
                    organization_id=self.organization.id,
                    target_user_id=target_id,
                    reason="Approved concurrent administrator rotation test.",
                )
                outcome = "committed"
            except AdministrationProblem:
                outcome = "rejected"
            finally:
                connections.close_all()
            return outcome

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(transfer, [target.id for target in targets]))

        self.assertEqual(results.count("committed"), 1)
        self.assertEqual(results.count("rejected"), 1)
        self.assertEqual(
            UserProfile.objects.filter(organization=self.organization, role=UserProfile.Role.ADMIN, user__is_active=True).count(),
            1,
        )
        self.assertEqual(AccessLog.objects.filter(action="organization.admin_transfer").count(), 1)
        self.assertEqual(OperationalEvent.objects.filter(event_type="organization.admin_transferred").count(), 1)


class AdminAuditChainConcurrencyTests(TransactionTestCase):
    """The failure that never reproduces on a laptop.

    Without the lock on the organization row, two administrators acting at the
    same moment both read the same highest chain index and both try to write
    the next one. The unique constraint saves the chain from corruption, but
    the losing append is simply gone — an administrative change that happened
    and left no record. SQLite serialises writes anyway, so only PostgreSQL can
    show whether the lock is doing its job.
    """

    reset_sequences = True

    def setUp(self):
        self.organization = Organization.objects.create(name="Audit Concurrency", slug="audit-concurrency")
        user = get_user_model().objects.create_user(username="chief@concurrency.test", email="chief@concurrency.test")
        UserProfile.objects.create(user=user, organization=self.organization, role=UserProfile.Role.ADMIN)
        self.actor = Actor(
            user="Chief A. Rao",
            role="Admin",
            authenticated=True,
            django_user_id=user.id,
            email="chief@concurrency.test",
            organization_id=self.organization.id,
            organization_slug=self.organization.slug,
            aal="aal2",
        )

    @skipUnlessDBFeature("has_select_for_update")
    def test_fifty_concurrent_appends_lose_nothing_and_form_one_valid_chain(self):
        from apps.forensics.models import AdminAuditEvent
        from common.admin_audit import record_admin_event, verify_admin_chain

        self.assertEqual(connection.vendor, "postgresql")

        def append(sequence: int) -> None:
            connections.close_all()
            organization = Organization.objects.get(pk=self.organization.pk)
            record_admin_event(
                organization=organization,
                actor=self.actor,
                action="user.role_changed",
                target_type="User",
                target_id=str(sequence),
                reason="Concurrent append under test.",
            )
            connections.close_all()

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(append, range(50)))

        report = verify_admin_chain(Organization.objects.get(pk=self.organization.pk))

        self.assertEqual(report["eventCount"], 50, "an append was lost")
        self.assertTrue(report["verified"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(
            list(
                AdminAuditEvent.objects.filter(organization=self.organization)
                .order_by("chain_index")
                .values_list("chain_index", flat=True)
            ),
            list(range(1, 51)),
        )
        # Every recorded target survived. Counting rows alone would pass even
        # if the same change were written twice and another lost entirely.
        self.assertEqual(
            {row.target_id for row in AdminAuditEvent.objects.filter(organization=self.organization)},
            {str(sequence) for sequence in range(50)},
        )
