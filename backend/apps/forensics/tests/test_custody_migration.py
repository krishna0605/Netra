from importlib import import_module
from types import SimpleNamespace

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TransactionTestCase

from apps.forensics.tests.migration_harness import MigrationHarnessMixin
from common.tenancy import NETRA_ORGANIZATION_ID


custody_migration = import_module("apps.forensics.migrations.0015_custody_chain_index")


def event(pk, previous_hash, event_hash):
    return SimpleNamespace(pk=pk, previous_hash=previous_hash, event_hash=event_hash)


class CustodyChainMigrationValidationTests(SimpleTestCase):
    def test_orders_events_by_cryptographic_links(self):
        events = [event("third", "b", "c"), event("root", "", "a"), event("second", "a", "b")]
        self.assertEqual(
            [row.pk for row in custody_migration.ordered_chain(events, "CASE-1")],
            ["root", "second", "third"],
        )

    def test_rejects_branches(self):
        events = [event("root", "", "a"), event("left", "a", "b"), event("right", "a", "c")]
        with self.assertRaisesRegex(RuntimeError, "branch"):
            custody_migration.ordered_chain(events, "CASE-1")

    def test_rejects_disconnected_or_cyclic_events(self):
        events = [event("root", "", "a"), event("cycle-a", "c", "b"), event("cycle-b", "b", "c")]
        with self.assertRaisesRegex(RuntimeError, "disconnected"):
            custody_migration.ordered_chain(events, "CASE-1")

    def test_rejects_duplicate_hashes(self):
        events = [event("root", "", "a"), event("duplicate", "a", "a")]
        with self.assertRaisesRegex(RuntimeError, "duplicate event hash"):
            custody_migration.ordered_chain(events, "CASE-1")


class CustodyChainMigrationBackfillTests(MigrationHarnessMixin, TransactionTestCase):
    migrate_from = [("forensics", "0014_security_tenancy_and_rate_limits")]
    migrate_to = [("forensics", "0015_custody_chain_index")]

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        Organization = old_apps.get_model("forensics", "Organization")
        Case = old_apps.get_model("forensics", "Case")
        CustodyLedgerEvent = old_apps.get_model("forensics", "CustodyLedgerEvent")

        # TransactionTestCase flushes data between tests, while migration state
        # is retained. Recreate the deterministic seed explicitly so this test
        # remains independent of execution order.
        organization, _ = Organization.objects.get_or_create(
            pk=NETRA_ORGANIZATION_ID,
            defaults={"name": "Netra", "slug": "netra", "max_queued_analyses": 5},
        )
        case = Case.objects.create(
            id="CASE-CUSTODY-MIGRATION",
            organization_id=organization.pk,
            display_reference="CASE-CUSTODY-MIGRATION",
            title="Custody migration",
            investigator="Synthetic Investigator",
        )
        common = {
            "case_id": case.pk,
            "actor_user": "system",
            "actor_label": "system",
            "actor_role": "System",
            "action": "migration-test",
            "details_json": {},
        }
        CustodyLedgerEvent.objects.create(id="cust-z-root", previous_hash="", event_hash="a" * 64, **common)
        CustodyLedgerEvent.objects.create(id="cust-a-second", previous_hash="a" * 64, event_hash="b" * 64, **common)
        CustodyLedgerEvent.objects.create(id="cust-m-third", previous_hash="b" * 64, event_hash="c" * 64, **common)

        executor = MigrationExecutor(connection)
        executor.migrate(self.migrate_to)

    def test_existing_chain_is_backfilled_from_hash_links(self):
        apps = MigrationExecutor(connection).loader.project_state(self.migrate_to).apps
        CustodyLedgerEvent = apps.get_model("forensics", "CustodyLedgerEvent")
        rows = list(
            CustodyLedgerEvent.objects.filter(case_id="CASE-CUSTODY-MIGRATION")
            .order_by("chain_index")
            .values_list("id", "chain_index")
        )
        self.assertEqual(rows, [("cust-z-root", 1), ("cust-a-second", 2), ("cust-m-third", 3)])
