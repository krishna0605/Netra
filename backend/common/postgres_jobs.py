from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from apps.forensics.models import EvidenceFile, EvidenceUploadSession, ProcessingJob
from common.jobs import initial_steps


TERMINAL_JOB_STATUSES = {
    ProcessingJob.Status.COMPLETED,
    ProcessingJob.Status.FAILED,
    ProcessingJob.Status.CANCELED,
}


class JobCancellationRequested(RuntimeError):
    pass


def _event(job: ProcessingJob, name: str, detail: str) -> None:
    events = list(job.events or [])
    events.append({"timestamp": timezone.now().isoformat(), "event": name, "detail": detail})
    job.events = events[-100:]


@transaction.atomic
def claim_next_job(worker_id: str) -> ProcessingJob | None:
    now = timezone.now()
    expired = list(
        ProcessingJob.objects.select_for_update(skip_locked=True)
        .filter(status=ProcessingJob.Status.RUNNING, lease_expires_at__lt=now)
        .order_by("lease_expires_at")[:25]
    )
    for job in expired:
        job.lease_owner = ""
        job.lease_expires_at = None
        job.heartbeat_at = now
        if job.cancel_requested_at:
            job.status = ProcessingJob.Status.CANCELED
            job.step = "canceled"
            job.completed_at = now
            _event(job, "job.canceled", "Cancellation completed after the previous worker lease expired.")
        elif job.attempt_count >= job.max_attempts:
            job.status = ProcessingJob.Status.FAILED
            job.step = "failed"
            job.completed_at = now
            job.error_code = "lease_expired"
            job.error_message = "Worker lease expired and the retry limit was reached."
            _event(job, "job.failed", job.error_message)
        else:
            job.status = ProcessingJob.Status.QUEUED
            job.step = "retry_wait"
            job.next_attempt_at = now
            _event(job, "job.requeued", "Expired worker lease was recovered by the PostgreSQL queue.")
        job.save()

    job = (
        ProcessingJob.objects.select_for_update(skip_locked=True)
        .filter(status=ProcessingJob.Status.QUEUED, cancel_requested_at__isnull=True)
        .filter(Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
        .filter(attempt_count__lt=F("max_attempts"))
        .order_by("created_at")
        .first()
    )
    if job is None:
        return None

    job.status = ProcessingJob.Status.RUNNING
    job.step = "packet_parsing"
    job.progress = max(job.progress, 10)
    job.attempt_count += 1
    job.lease_owner = worker_id
    job.claimed_at = now
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=settings.NETRA_JOB_LEASE_SECONDS)
    job.next_attempt_at = None
    job.started_at = job.started_at or now
    job.last_progress_at = now
    job.steps = initial_steps("packet_parsing")
    _event(job, "job.claimed", f"Durable worker claimed attempt {job.attempt_count} of {job.max_attempts}.")
    job.save()
    return job


def renew_job_lease(job_id: str, worker_id: str) -> bool:
    now = timezone.now()
    updated = ProcessingJob.objects.filter(
        pk=job_id,
        status=ProcessingJob.Status.RUNNING,
        lease_owner=worker_id,
    ).update(
        heartbeat_at=now,
        lease_expires_at=now + timedelta(seconds=settings.NETRA_JOB_LEASE_SECONDS),
        last_progress_at=now,
    )
    return updated == 1


@transaction.atomic
def mark_job_failure(job_id: str, worker_id: str, exc: Exception) -> ProcessingJob:
    job = ProcessingJob.objects.select_for_update().get(pk=job_id)
    if job.status == ProcessingJob.Status.COMPLETED:
        return job
    now = timezone.now()
    job.lease_owner = ""
    job.lease_expires_at = None
    job.heartbeat_at = now
    safe_error = str(exc).strip()[:1000] or exc.__class__.__name__
    job.error_code = "analysis_failed"
    job.error_message = safe_error
    if job.cancel_requested_at or isinstance(exc, JobCancellationRequested):
        job.status = ProcessingJob.Status.CANCELED
        job.step = "canceled"
        job.completed_at = now
        _event(job, "job.canceled", "The durable worker honored the cancellation request.")
    elif job.attempt_count < job.max_attempts:
        delay = min(60, 2 ** max(1, job.attempt_count))
        job.status = ProcessingJob.Status.QUEUED
        job.step = "retry_wait"
        job.next_attempt_at = now + timedelta(seconds=delay)
        _event(job, "job.retry_scheduled", f"Attempt failed on {worker_id}; retry scheduled in {delay} seconds.")
    else:
        job.status = ProcessingJob.Status.FAILED
        job.step = "failed"
        job.completed_at = now
        _event(job, "job.failed", "The durable worker exhausted the configured retry limit.")
        if job.evidence_file_id:
            EvidenceFile.objects.filter(pk=job.evidence_file_id).update(status=EvidenceFile.Status.FAILED)
    job.save()
    if job.status == ProcessingJob.Status.CANCELED:
        EvidenceUploadSession.objects.filter(processing_job=job).update(status=EvidenceUploadSession.Status.CANCELED, failure_code="job_canceled")
    elif job.status == ProcessingJob.Status.FAILED:
        EvidenceUploadSession.objects.filter(processing_job=job).update(status=EvidenceUploadSession.Status.FAILED, failure_code=job.error_code)
    return job


@transaction.atomic
def request_job_cancellation(job_id: str) -> ProcessingJob:
    job = ProcessingJob.objects.select_for_update().get(pk=job_id)
    if job.status in TERMINAL_JOB_STATUSES:
        return job
    now = timezone.now()
    job.cancel_requested_at = now
    _event(job, "job.cancel_requested", "An authorized user requested cancellation.")
    if job.status == ProcessingJob.Status.QUEUED:
        job.status = ProcessingJob.Status.CANCELED
        job.step = "canceled"
        job.completed_at = now
        job.lease_owner = ""
        job.lease_expires_at = None
        if job.evidence_file_id:
            EvidenceFile.objects.filter(pk=job.evidence_file_id).update(status=EvidenceFile.Status.FAILED)
    job.save()
    if job.status == ProcessingJob.Status.CANCELED:
        EvidenceUploadSession.objects.filter(processing_job=job).update(status=EvidenceUploadSession.Status.CANCELED, failure_code="job_canceled")
    return job


@transaction.atomic
def retry_job(job_id: str) -> ProcessingJob:
    job = ProcessingJob.objects.select_for_update().get(pk=job_id)
    if job.status not in {ProcessingJob.Status.FAILED, ProcessingJob.Status.CANCELED}:
        return job
    now = timezone.now()
    job.status = ProcessingJob.Status.QUEUED
    job.step = "queued"
    job.progress = 0
    job.steps = initial_steps()
    job.attempt_count = 0
    job.lease_owner = ""
    job.lease_expires_at = None
    job.claimed_at = None
    job.heartbeat_at = None
    job.next_attempt_at = now
    job.cancel_requested_at = None
    job.completed_at = None
    job.error_code = ""
    job.error_message = ""
    if job.evidence_file_id:
        EvidenceFile.objects.filter(pk=job.evidence_file_id).update(status=EvidenceFile.Status.PROCESSING)
    EvidenceUploadSession.objects.filter(processing_job=job).update(status=EvidenceUploadSession.Status.QUEUED, failure_code="")
    _event(job, "job.retry_requested", "An authorized user reset the durable job for retry.")
    job.save()
    return job
