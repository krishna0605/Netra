from __future__ import annotations

import shutil
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.forensics.models import (
    CaptureChunk,
    CaptureJob,
    CaptureSchedule,
    Case,
    EvidenceFile,
    RetentionCandidate,
    RetentionPolicy,
    RetentionRun,
    Sensor,
    SensorCommand,
    SensorGroup,
)
from common.operations import capture_job_payload, create_capture_job, emit_operational_event, heartbeat_state
from common.storage_provider import storage_provider


def sensor_group_payload(group: SensorGroup) -> dict[str, Any]:
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "color": group.color,
        "sensorCount": group.sensors.count(),
    }


def schedule_payload(schedule: CaptureSchedule) -> dict[str, Any]:
    return {
        "id": schedule.id,
        "name": schedule.name,
        "sensorId": schedule.sensor_id,
        "sensorName": schedule.sensor.name,
        "enabled": schedule.enabled,
        "scheduleType": schedule.schedule_type,
        "startAt": schedule.start_at.isoformat(),
        "timezone": schedule.timezone,
        "weekdays": schedule.weekdays_json,
        "durationSeconds": schedule.duration_seconds,
        "packetLimit": schedule.packet_limit,
        "chunkIntervalSeconds": schedule.chunk_interval_seconds,
        "interfaceName": schedule.interface_name,
        "bpfFilter": schedule.bpf_filter,
        "caseIdPrefix": schedule.case_id_prefix,
        "lastRunAt": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
        "nextRunAt": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "lastJobId": schedule.last_job_id or "",
    }


def calculate_next_run(schedule: CaptureSchedule, after=None):
    current = after or timezone.now()
    candidate = schedule.start_at
    if schedule.schedule_type == CaptureSchedule.ScheduleType.ONE_TIME:
        return candidate if candidate > current and not schedule.last_run_at else None
    while candidate <= current:
        if schedule.schedule_type == CaptureSchedule.ScheduleType.DAILY:
            candidate += timedelta(days=1)
        else:
            candidate += timedelta(days=1)
            weekdays = set(schedule.weekdays_json or [candidate.weekday()])
            while candidate.weekday() not in weekdays:
                candidate += timedelta(days=1)
    return candidate


@transaction.atomic
def queue_schedule_run(schedule: CaptureSchedule) -> CaptureJob | None:
    schedule = CaptureSchedule.objects.select_for_update().select_related("sensor").get(id=schedule.id)
    sensor = schedule.sensor
    active = CaptureJob.objects.filter(sensor=sensor, status__in=[CaptureJob.Status.QUEUED, CaptureJob.Status.RUNNING]).exists()
    if not sensor.enabled or heartbeat_state(sensor.last_heartbeat_at) == "offline" or active:
        reason = "sensor-disabled" if not sensor.enabled else "sensor-offline" if heartbeat_state(sensor.last_heartbeat_at) == "offline" else "sensor-busy"
        emit_operational_event("schedule.capture_skipped", {"scheduleId": schedule.id, "sensorId": sensor.id, "reason": reason})
        schedule.last_run_at = timezone.now()
        schedule.next_run_at = calculate_next_run(schedule, schedule.last_run_at)
        schedule.save(update_fields=["last_run_at", "next_run_at", "updated_at"])
        return None
    stamp = timezone.localtime().strftime("%Y%m%d-%H%M%S")
    case, _ = Case.objects.get_or_create(
        id=f"{schedule.case_id_prefix}-{stamp}"[:64],
        defaults={"title": schedule.name, "investigator": "Local Investigator", "source_location": sensor.location or sensor.name},
    )
    job = create_capture_job(
        case=case,
        mode=CaptureJob.Mode.LIVE_CAPTURE,
        sensor=sensor,
        interface_name=schedule.interface_name,
        duration_seconds=schedule.duration_seconds,
        packet_limit=schedule.packet_limit,
        chunk_interval_seconds=schedule.chunk_interval_seconds,
        bpf_filter=schedule.bpf_filter,
        source_label=f"Scheduled capture: {schedule.name}",
    )
    SensorCommand.objects.create(sensor=sensor, capture_job=job, command_type="capture.start", payload_json=capture_job_payload(job))
    schedule.last_run_at = timezone.now()
    schedule.next_run_at = calculate_next_run(schedule, schedule.last_run_at)
    schedule.last_job = job
    schedule.save(update_fields=["last_run_at", "next_run_at", "last_job", "updated_at"])
    emit_operational_event("schedule.capture_queued", {"scheduleId": schedule.id, **capture_job_payload(job)}, capture_job=job)
    return job


def ensure_default_retention_policy() -> RetentionPolicy:
    policy, _ = RetentionPolicy.objects.get_or_create(
        name="Default local fleet policy",
        defaults={"high_volume_search_days": 30, "evidence_days": 90, "capture_chunk_days": 7, "enabled": True},
    )
    return policy


def retention_policy_payload(policy: RetentionPolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "name": policy.name,
        "highVolumeSearchDays": policy.high_volume_search_days,
        "evidenceDays": policy.evidence_days,
        "captureChunkDays": policy.capture_chunk_days,
        "enabled": policy.enabled,
        "updatedAt": policy.updated_at.isoformat(),
    }


def retention_preview() -> RetentionRun:
    policy = ensure_default_retention_policy()
    now = timezone.now()
    chunk_before = now - timedelta(days=policy.capture_chunk_days)
    evidence_before = now - timedelta(days=policy.evidence_days)
    candidates: list[dict[str, Any]] = []
    RetentionCandidate.objects.filter(status__in=["pending", "requires-approval", "skipped"]).delete()
    for chunk in CaptureChunk.objects.select_related("capture_job__case").filter(created_at__lte=chunk_before, capture_job__final_evidence_file__isnull=False):
        candidate = RetentionCandidate.objects.create(
            resource_type="capture-chunk",
            resource_id=chunk.id,
            case=chunk.capture_job.case,
            reason="Final immutable evidence exists and chunk retention elapsed.",
            expires_at=chunk.retention_expires_at or chunk_before,
            status=RetentionCandidate.Status.PENDING,
        )
        candidates.append(_candidate_payload(candidate))
    for evidence in EvidenceFile.objects.select_related("case").filter(created_at__lte=evidence_before):
        held = evidence.legal_hold or evidence.case.legal_hold
        candidate = RetentionCandidate.objects.create(
            resource_type="immutable-evidence",
            resource_id=evidence.id,
            case=evidence.case,
            reason="Immutable evidence retention elapsed.",
            expires_at=evidence.retention_expires_at or evidence_before,
            legal_hold=held,
            status=RetentionCandidate.Status.SKIPPED if held else RetentionCandidate.Status.REQUIRES_APPROVAL,
        )
        candidates.append(_candidate_payload(candidate))
    return RetentionRun.objects.create(started_at=now, completed_at=timezone.now(), mode="preview", status="completed", candidates_json=candidates)


def execute_safe_retention() -> RetentionRun:
    preview = retention_preview()
    deleted = []
    reclaimed = 0
    for candidate in RetentionCandidate.objects.filter(status=RetentionCandidate.Status.PENDING, resource_type="capture-chunk"):
        chunk = CaptureChunk.objects.filter(id=candidate.resource_id).first()
        if not chunk:
            continue
        try:
            reclaimed += storage_provider.stat(chunk.stored_path).size_bytes
            storage_provider.delete(chunk.stored_path)
            chunk.delete()
            candidate.status = RetentionCandidate.Status.DELETED
            candidate.save(update_fields=["status", "updated_at"])
            deleted.append(_candidate_payload(candidate))
        except Exception as exc:
            deleted.append(_candidate_payload(candidate) | {"error": str(exc)})
    preview.mode = "safe-cleanup"
    preview.deleted_json = deleted
    preview.bytes_reclaimed = reclaimed
    preview.save(update_fields=["mode", "deleted_json", "bytes_reclaimed", "updated_at"])
    return preview


def _candidate_payload(candidate: RetentionCandidate) -> dict[str, Any]:
    return {
        "id": candidate.id,
        "resourceType": candidate.resource_type,
        "resourceId": candidate.resource_id,
        "caseId": candidate.case_id or "",
        "reason": candidate.reason,
        "expiresAt": candidate.expires_at.isoformat(),
        "legalHold": candidate.legal_hold,
        "status": candidate.status,
    }


def retention_run_payload(run: RetentionRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "startedAt": run.started_at.isoformat(),
        "completedAt": run.completed_at.isoformat() if run.completed_at else None,
        "mode": run.mode,
        "status": run.status,
        "candidates": run.candidates_json,
        "deleted": run.deleted_json,
        "bytesReclaimed": run.bytes_reclaimed,
        "error": run.error_message,
    }


def capacity_payload() -> dict[str, Any]:
    usage = shutil.disk_usage(settings.NETRA_STORAGE_ROOT)
    used = usage.total - usage.free
    used_percent = round((used / usage.total) * 100, 2) if usage.total else 0
    lag = kafka_lag_payload()
    if used_percent >= settings.NETRA_DISK_CRITICAL_PERCENT or lag["lag"] >= settings.NETRA_KAFKA_LAG_CRITICAL:
        status = "critical"
    elif used_percent >= settings.NETRA_DISK_WARNING_PERCENT or lag["lag"] >= settings.NETRA_KAFKA_LAG_WARNING:
        status = "warning"
    else:
        status = "ok"
    search = search_capacity_payload()
    return {
        "status": status,
        "kafka": lag,
        "storage": {"usedBytes": used, "freeBytes": usage.free, "totalBytes": usage.total, "usedPercent": used_percent},
        "search": search,
        "sensors": {
            "total": Sensor.objects.count(),
            "online": sum(1 for row in Sensor.objects.all() if heartbeat_state(row.last_heartbeat_at) == "healthy"),
            "capturing": CaptureJob.objects.filter(status=CaptureJob.Status.RUNNING).count(),
            "offline": sum(1 for row in Sensor.objects.all() if heartbeat_state(row.last_heartbeat_at) == "offline"),
        },
    }


def search_capacity_payload() -> dict[str, Any]:
    try:
        from common.search import get_elasticsearch_client

        response = get_elasticsearch_client().count(index="netra-*")
        return {"indexedDocuments": response["count"], "failedBulkRequests": 0, "available": True}
    except Exception as exc:
        return {"indexedDocuments": 0, "failedBulkRequests": 0, "available": False, "detail": str(exc)}


def kafka_lag_payload() -> dict[str, Any]:
    groups = [
        "netra-capture",
        "netra-pcap-ingestion",
        "netra-parser",
        "netra-decoder",
        "netra-session",
        "netra-detection",
        "netra-anomaly",
        "netra-analysis-finalizer",
        "netra-report-export",
    ]
    try:
        from kafka import KafkaConsumer
        from kafka.admin import KafkaAdminClient

        admin = KafkaAdminClient(bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP, request_timeout_ms=3000)
        consumer = KafkaConsumer(
            bootstrap_servers=settings.NETRA_KAFKA_BOOTSTRAP,
            enable_auto_commit=False,
            request_timeout_ms=3000,
            api_version_auto_timeout_ms=3000,
        )
        group_lag = {}
        for group in groups:
            offsets = admin.list_consumer_group_offsets(group)
            if not offsets:
                continue
            active_offsets = {
                partition: metadata
                for partition, metadata in offsets.items()
                if partition.partition in (consumer.partitions_for_topic(partition.topic) or set())
            }
            if not active_offsets:
                continue
            end_offsets = consumer.end_offsets(list(active_offsets))
            group_lag[group] = sum(max(0, end_offsets.get(partition, 0) - max(0, metadata.offset)) for partition, metadata in active_offsets.items())
        consumer.close()
        admin.close()
        return {
            "lag": sum(group_lag.values()),
            "consumerGroups": group_lag,
            "brokerAvailable": True,
            "warningThreshold": settings.NETRA_KAFKA_LAG_WARNING,
            "criticalThreshold": settings.NETRA_KAFKA_LAG_CRITICAL,
        }
    except Exception as exc:
        return {
            "lag": 0,
            "consumerGroups": {},
            "brokerAvailable": False,
            "detail": str(exc),
            "warningThreshold": settings.NETRA_KAFKA_LAG_WARNING,
            "criticalThreshold": settings.NETRA_KAFKA_LAG_CRITICAL,
        }


def backpressure_allows_new_capture() -> tuple[bool, dict[str, Any]]:
    capacity = capacity_payload()
    return capacity["status"] != "critical", capacity
