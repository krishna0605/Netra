from __future__ import annotations

from django.db import transaction

from apps.forensics.models import Organization, ProcessingJob


class OrganizationQueueLimit(Exception):
    pass


def lock_and_check_queue_capacity(organization_id, *, job_id: str | None = None) -> Organization:
    """Serialize capacity checks for all job producers in one organization."""
    organization = Organization.objects.select_for_update().get(pk=organization_id)
    if job_id and ProcessingJob.objects.filter(pk=job_id, case__organization_id=organization.id).exists():
        return organization
    active_jobs = ProcessingJob.objects.filter(
        case__organization_id=organization.id,
        status__in=[ProcessingJob.Status.QUEUED, ProcessingJob.Status.RUNNING],
    ).count()
    if active_jobs >= organization.max_queued_analyses:
        raise OrganizationQueueLimit("The organization has reached its active analysis capacity.")
    return organization


def queue_capacity(organization_id) -> tuple[int, int]:
    organization = Organization.objects.get(pk=organization_id)
    active = ProcessingJob.objects.filter(
        case__organization_id=organization.id,
        status__in=[ProcessingJob.Status.QUEUED, ProcessingJob.Status.RUNNING],
    ).count()
    return active, organization.max_queued_analyses
