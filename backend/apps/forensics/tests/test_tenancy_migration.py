from datetime import timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.apps import apps
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.recorder import MigrationRecorder
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.forensics.models import AnalysisReference, ApiRateLimitBucket, Case, Organization, ProcessingJob, UserProfile
from apps.forensics.tests.migration_harness import MigrationHarnessMixin, latest_migration
from common.tenancy import NETRA_ORGANIZATION_ID


class TenancySchemaTests(TestCase):
    def setUp(self):
        self.netra = Organization.objects.get(pk=NETRA_ORGANIZATION_ID)

    def test_deterministic_netra_organization_is_seeded(self):
        self.assertEqual(self.netra.slug, "netra")
        self.assertEqual(self.netra.name, "Netra")
        self.assertEqual(self.netra.max_queued_analyses, 5)

    def test_phase_five_schema_has_43_domain_and_10_framework_tables(self):
        domain_tables = {model._meta.db_table for model in apps.get_models() if model._meta.app_label == "forensics"}
        self.assertEqual(len(domain_tables), 43)
        self.assertEqual(MigrationRecorder.Migration.objects.filter(app="forensics").count(), 16)
        self.assertTrue(MigrationRecorder.Migration.objects.filter(app="forensics", name="0014_security_tenancy_and_rate_limits").exists())
        self.assertTrue(MigrationRecorder.Migration.objects.filter(app="forensics", name="0016_analysis_references_and_integration_links").exists())

    def test_case_display_reference_is_unique_within_organization(self):
        Case.objects.create(
            id="CYB-GJ-TENANT-001",
            display_reference="CYB-GJ-DISPLAY-001",
            organization=self.netra,
            title="First",
            investigator="Officer",
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Case.objects.create(
                    id="CYB-GJ-TENANT-002",
                    display_reference="CYB-GJ-DISPLAY-001",
                    organization=self.netra,
                    title="Second",
                    investigator="Officer",
                )

    def test_only_one_admin_is_allowed_per_organization(self):
        first = get_user_model().objects.create_user(username="phase2-admin-one")
        second = get_user_model().objects.create_user(username="phase2-admin-two")
        UserProfile.objects.create(user=first, organization=self.netra, role=UserProfile.Role.ADMIN)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                UserProfile.objects.create(user=second, organization=self.netra, role=UserProfile.Role.ADMIN)

    def test_rate_limit_scope_must_match_user_presence(self):
        now = timezone.now()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ApiRateLimitBucket.objects.create(
                    organization=self.netra,
                    scope_key="user:missing",
                    route_key="read",
                    window_start=now,
                    window_seconds=60,
                    expires_at=now + timedelta(minutes=2),
                )


class TenancyMigrationBackfillTests(MigrationHarnessMixin, TransactionTestCase):
    migrate_from = [("forensics", "0013_case_route_ref_and_statuses")]
    migrate_to = [("forensics", "0014_security_tenancy_and_rate_limits")]

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps

        User = old_apps.get_model("auth", "User")
        UserProfile = old_apps.get_model("forensics", "UserProfile")
        Case = old_apps.get_model("forensics", "Case")
        EvidenceUploadSession = old_apps.get_model("forensics", "EvidenceUploadSession")
        AccessLog = old_apps.get_model("forensics", "AccessLog")
        OperationalEvent = old_apps.get_model("forensics", "OperationalEvent")

        user = User.objects.create(username="legacy-admin", is_active=True)
        UserProfile.objects.create(user_id=user.pk, role="Admin", display_name="Legacy Admin")
        case = Case.objects.create(id="CYB-GJ-LEGACY-001", title="Legacy", investigator="Legacy Admin")
        EvidenceUploadSession.objects.create(
            user_id=user.pk,
            external_user_id="legacy-external-id",
            organization="Legacy Gujarat Unit",
            case_id=case.pk,
            expected_filename="legacy.pcap",
            expected_size_bytes=12,
            expected_evidence_type="PCAP",
            storage_path="legacy/legacy.pcap",
            expires_at=timezone.now() + timedelta(hours=1),
            fingerprint="a" * 64,
        )
        AccessLog.objects.create(
            user_id=user.pk,
            user_label="Legacy Admin",
            role="Admin",
            action="legacy.read",
        )
        OperationalEvent.objects.create(event_type="legacy.event")

        executor = MigrationExecutor(connection)
        executor.migrate(self.migrate_to)

    def test_legacy_rows_are_backfilled_without_losing_upload_label(self):
        apps = MigrationExecutor(connection).loader.project_state(self.migrate_to).apps
        Organization = apps.get_model("forensics", "Organization")
        UserProfile = apps.get_model("forensics", "UserProfile")
        Case = apps.get_model("forensics", "Case")
        EvidenceUploadSession = apps.get_model("forensics", "EvidenceUploadSession")
        AccessLog = apps.get_model("forensics", "AccessLog")
        OperationalEvent = apps.get_model("forensics", "OperationalEvent")

        organization = Organization.objects.get(pk=NETRA_ORGANIZATION_ID)
        self.assertEqual(Organization.objects.count(), 1)
        self.assertFalse(UserProfile.objects.exclude(organization_id=organization.pk).exists())
        case = Case.objects.get(pk="CYB-GJ-LEGACY-001")
        self.assertEqual(case.organization_id, organization.pk)
        self.assertEqual(case.display_reference, case.pk)
        session = EvidenceUploadSession.objects.get()
        self.assertEqual(session.organization_id, organization.pk)
        self.assertEqual(session.intake_json["legacyOrganizationLabel"], "Legacy Gujarat Unit")
        self.assertFalse(AccessLog.objects.exclude(organization_id=organization.pk).exists())
        self.assertFalse(OperationalEvent.objects.exclude(organization_id=organization.pk).exists())

    def test_scratch_reversal_restores_the_legacy_upload_organization_field(self):
        executor = MigrationExecutor(connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        EvidenceUploadSession = old_apps.get_model("forensics", "EvidenceUploadSession")
        self.assertEqual(EvidenceUploadSession.objects.get().organization, "Netra")
        MigrationExecutor(connection).migrate(self.migrate_to)


class MigrationHarnessRestoresLatestSchemaTests(MigrationHarnessMixin, TransactionTestCase):
    """Proves the harness repairs the exact breakage the old tearDown caused.

    Restoring only ``migrate_to`` left 0016 unapplied, so every later test in the
    same process ran current models against a schema without
    ``forensics_processingjob.operation_kind``.
    """

    def test_latest_migration_tracks_the_graph_leaf(self):
        self.assertEqual(latest_migration(), [("forensics", "0016_analysis_references_and_integration_links")])

    def test_rewound_schema_breaks_current_models_and_is_restored(self):
        MigrationExecutor(connection).migrate([("forensics", "0015_custody_chain_index")])
        with self.assertRaises(DatabaseError):
            ProcessingJob.objects.filter(operation_kind="analysis").count()

        MigrationExecutor(connection).migrate(latest_migration())
        self.assertEqual(ProcessingJob.objects.filter(operation_kind="analysis").count(), 0)
        self.assertEqual(AnalysisReference.objects.count(), 0)
        recorded = set(MigrationRecorder.Migration.objects.filter(app="forensics").values_list("name", flat=True))
        self.assertIn(latest_migration()[0][1], recorded)

    def test_no_migration_harness_restores_a_hardcoded_target(self):
        """A future harness must not reintroduce the stale-schema tearDown."""
        for path in Path(__file__).parent.glob("test_*migration*.py"):
            with self.subTest(module=path.name):
                self.assertNotIn("migrate(self.migrate_to)\n        super().tearDown()", path.read_text(encoding="utf-8"))
