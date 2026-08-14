from datetime import timedelta

from django.db import DatabaseError, connection, transaction
from django.test import TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone

from apps.forensics.models import AccessLog, Organization, UserProfile
from common.access_log_retention import maintain_access_log_partitions
from common.tenancy import NETRA_ORGANIZATION_ID


class NonPostgresAccessLogMaintenanceTests(TestCase):
    def test_non_postgres_database_reports_that_partition_maintenance_is_inapplicable(self):
        if connection.vendor == "postgresql":
            self.skipTest("PostgreSQL lifecycle is covered separately")

        self.assertEqual(maintain_access_log_partitions().status, "not-postgresql")


@skipUnlessDBFeature("supports_table_check_constraints")
class PostgresAccessLogLifecycleTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Declarative partition behavior requires PostgreSQL")
        # TransactionTestCase truncates every table between tests and does not
        # put migration-seeded rows back, so the deterministic Netra
        # organization vanishes after the first one. Recreating it is steadier
        # than serialized_rollback, which depends on how the test database was
        # built and fails only when this module runs alongside others.
        self.organization, _ = Organization.objects.get_or_create(
            pk=NETRA_ORGANIZATION_ID, defaults={"name": "Netra", "slug": "netra"}
        )

    def _log(self) -> AccessLog:
        return AccessLog.objects.create(
            organization=self.organization,
            user_label="lifecycle-test",
            role=UserProfile.Role.ADMIN,
            action="test.access_log_lifecycle",
            result="allowed",
        )

    def test_access_log_table_is_range_partitioned(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid = %s::regclass)",
                [AccessLog._meta.db_table],
            )
            self.assertTrue(cursor.fetchone()[0])

    def test_access_log_rows_are_append_only(self):
        row = self._log()

        with self.assertRaises(DatabaseError), transaction.atomic():
            AccessLog.objects.filter(pk=row.pk).update(result="denied")

        row.refresh_from_db()
        self.assertEqual(row.result, "allowed")

    @override_settings(NETRA_ACCESS_LOG_RETENTION_DAYS=1)
    def test_maintenance_removes_only_expired_rows(self):
        expired = self._log()
        current = self._log()
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('netra.access_log_maintenance', 'on', false)")
            cursor.execute(
                "UPDATE public.forensics_accesslog SET created_at = %s WHERE id = %s",
                [timezone.now() - timedelta(days=2), expired.pk],
            )
            cursor.execute("SELECT set_config('netra.access_log_maintenance', 'off', false)")

        result = maintain_access_log_partitions()

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.deleted_rows, 1)
        self.assertFalse(AccessLog.objects.filter(pk=expired.pk).exists())
        self.assertTrue(AccessLog.objects.filter(pk=current.pk).exists())
