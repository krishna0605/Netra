from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.forensics.models import ApiRateLimitBucket, Case, Organization, UserProfile
from common.tenancy import NETRA_ORGANIZATION_ID


class TenancySchemaTests(TestCase):
    def setUp(self):
        self.netra = Organization.objects.get(pk=NETRA_ORGANIZATION_ID)

    def test_deterministic_netra_organization_is_seeded(self):
        self.assertEqual(self.netra.slug, "netra")
        self.assertEqual(self.netra.name, "Netra")
        self.assertEqual(self.netra.max_queued_analyses, 5)

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


class TenancyMigrationBackfillTests(TransactionTestCase):
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

    def tearDown(self):
        MigrationExecutor(connection).migrate(self.migrate_to)
        super().tearDown()

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
