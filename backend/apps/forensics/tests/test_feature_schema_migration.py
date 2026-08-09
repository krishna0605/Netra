from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase

from apps.forensics.models import (
    AnalysisReference,
    Case,
    IntegrationCaseLink,
    IntegrationConnection,
    ProcessingJob,
)
from apps.forensics.tests.factories import netra_organization


class PhaseFiveSchemaTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        self.case = Case.objects.create(
            id="CASE-PHASE5-SCHEMA",
            organization=self.organization,
            display_reference="CASE-PHASE5-SCHEMA",
            title="Feature schema",
            investigator="Synthetic Investigator",
        )
        self.job = ProcessingJob.objects.create(id="job-phase5-schema", case=self.case)

    def test_processing_jobs_use_worker_safe_defaults(self):
        self.assertEqual(self.job.processing_path, "postgres-worker")
        self.assertEqual(self.job.operation_kind, ProcessingJob.OperationKind.ANALYSIS)

    def test_analysis_reference_is_unique_inside_one_job(self):
        AnalysisReference.objects.create(
            organization=self.organization,
            case=self.case,
            processing_job=self.job,
            kind=AnalysisReference.Kind.PACKET,
            source_reference="packet-1",
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AnalysisReference.objects.create(
                    organization=self.organization,
                    case=self.case,
                    processing_job=self.job,
                    kind=AnalysisReference.Kind.PACKET,
                    source_reference="packet-1",
                )

    def test_integration_names_and_links_are_tenant_scoped(self):
        connection = IntegrationConnection.objects.create(
            organization=self.organization,
            system_name="Synthetic webhook",
            api_mode="webhook-json",
        )
        creator = get_user_model().objects.create_user(username="phase5-schema@example.test")
        IntegrationCaseLink.objects.create(
            organization=self.organization,
            case=self.case,
            integration=connection,
            created_by=creator,
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                IntegrationCaseLink.objects.create(
                    organization=self.organization,
                    case=self.case,
                    integration=connection,
                )
