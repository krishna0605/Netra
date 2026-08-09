from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from apps.forensics.models import AnomalyRecord, Case, Organization
from apps.forensics.tests.migration_harness import MigrationHarnessMixin
from common.tenancy import NETRA_ORGANIZATION_ID


class DetectorProvenanceTests(TestCase):
    def test_new_anomaly_uses_truthful_deterministic_detector_label(self):
        organization = Organization.objects.get(pk=NETRA_ORGANIZATION_ID)
        case = Case.objects.create(
            id="CYB-GJ-DETECTOR-DEFAULT",
            display_reference="CYB-GJ-DETECTOR-DEFAULT",
            organization=organization,
            title="Detector provenance",
            investigator="Synthetic Investigator",
        )
        anomaly = AnomalyRecord.objects.create(
            id="detector-default-anomaly",
            case=case,
            entity="synthetic-session",
            behaviour="deterministic rule match",
            baseline="none",
            observed="reviewed signal",
            deviation="not-applicable",
            hypothesis="requires investigator review",
        )
        self.assertEqual(anomaly.model_version, "detector-registry-v1")


class DetectorProvenanceMigrationTests(MigrationHarnessMixin, TransactionTestCase):
    migrate_from = [("forensics", "0016_analysis_references_and_integration_links")]
    migrate_to = [("forensics", "0017_phase8_security_closure")]

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate(self.migrate_from)
        old_apps = executor.loader.project_state(self.migrate_from).apps
        Organization = old_apps.get_model("forensics", "Organization")
        Case = old_apps.get_model("forensics", "Case")
        AnomalyRecord = old_apps.get_model("forensics", "AnomalyRecord")
        organization = Organization.objects.get(pk=NETRA_ORGANIZATION_ID)
        case = Case.objects.create(
            id="CYB-GJ-DETECTOR-MIGRATION",
            display_reference="CYB-GJ-DETECTOR-MIGRATION",
            organization_id=organization.pk,
            title="Detector migration",
            investigator="Synthetic Investigator",
        )
        AnomalyRecord.objects.create(
            id="legacy-mislabelled-anomaly",
            case_id=case.pk,
            entity="synthetic-session",
            behaviour="deterministic rule match",
            baseline="none",
            observed="reviewed signal",
            deviation="not-applicable",
            hypothesis="requires investigator review",
            model_version="scikit-v1",
        )
        MigrationExecutor(connection).migrate(self.migrate_to)

    def test_migration_corrects_existing_mislabelled_rows(self):
        apps = MigrationExecutor(connection).loader.project_state(self.migrate_to).apps
        AnomalyRecord = apps.get_model("forensics", "AnomalyRecord")
        anomaly = AnomalyRecord.objects.get(pk="legacy-mislabelled-anomaly")
        self.assertEqual(anomaly.model_version, "detector-registry-v1")
        self.assertEqual(AnomalyRecord._meta.get_field("model_version").default, "detector-registry-v1")
