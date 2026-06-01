from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.utils import timezone as django_timezone
from scapy.all import PcapReader, PcapWriter

from apps.forensics.models import CaptureChunk, CaptureJob, Case, OperationalEvent, Sensor, WorkerHeartbeat
from common.analysis import analyze_pcap
from common.audit import Actor
from common.hashing import sha256_file
from common.kafka import publish_event
from common.persistence import persist_analysis
from common.storage import save_uploaded_file
from common.vault import decrypt_file


MAX_CAPTURE_DURATION_SECONDS = 15 * 60
MAX_CAPTURE_PACKETS = 250_000
MAX_CHUNK_INTERVAL_SECONDS = 30
MIN_CHUNK_INTERVAL_SECONDS = 2


def emit_operational_event(event_type: str, payload: dict[str, Any], capture_job: CaptureJob | None = None, case: Case | None = None) -> OperationalEvent:
    if capture_job and case is None:
        case = capture_job.case
    event = OperationalEvent.objects.create(case=case, capture_job=capture_job, event_type=event_type, payload_json=payload)
    publish_event("netra.operational.events", {"id": event.id, "type": event_type, **payload})
    return event


def sensor_key_valid(request) -> bool:
    expected = settings.NETRA_SENSOR_SHARED_KEY
    return bool(expected) and request.headers.get("X-Netra-Sensor-Key", "") == expected


def validate_capture_bounds(duration_seconds: int, packet_limit: int, chunk_interval_seconds: int, bpf_filter: str = "") -> None:
    if not 1 <= duration_seconds <= MAX_CAPTURE_DURATION_SECONDS:
        raise ValueError(f"durationSeconds must be between 1 and {MAX_CAPTURE_DURATION_SECONDS}.")
    if not 1 <= packet_limit <= MAX_CAPTURE_PACKETS:
        raise ValueError(f"packetLimit must be between 1 and {MAX_CAPTURE_PACKETS}.")
    if not MIN_CHUNK_INTERVAL_SECONDS <= chunk_interval_seconds <= MAX_CHUNK_INTERVAL_SECONDS:
        raise ValueError(f"chunkIntervalSeconds must be between {MIN_CHUNK_INTERVAL_SECONDS} and {MAX_CHUNK_INTERVAL_SECONDS}.")
    if len(bpf_filter) > 255 or any(ch in bpf_filter for ch in [";", "|", "&", "`", "$"]):
        raise ValueError("Unsafe BPF filter.")


def ensure_capture_case(case_id: str, investigator: str = "Local Investigator") -> Case:
    case, _ = Case.objects.update_or_create(
        id=case_id,
        defaults={
            "title": f"Live evidence capture: {case_id}",
            "investigator": investigator,
            "status": Case.Status.OPEN,
            "source_location": "Netra sensor",
        },
    )
    return case


def create_capture_job(
    *,
    case: Case,
    mode: str,
    sensor: Sensor | None = None,
    interface_name: str = "",
    duration_seconds: int,
    packet_limit: int,
    chunk_interval_seconds: int,
    bpf_filter: str = "",
    source_label: str = "",
) -> CaptureJob:
    validate_capture_bounds(duration_seconds, packet_limit, chunk_interval_seconds, bpf_filter)
    job = CaptureJob.objects.create(
        id=f"cap-{uuid4().hex[:10]}",
        case=case,
        mode=mode,
        sensor=sensor,
        interface_name=interface_name,
        duration_seconds=duration_seconds,
        packet_limit=packet_limit,
        chunk_interval_seconds=chunk_interval_seconds,
        bpf_filter=bpf_filter,
        source_label=source_label,
        status=CaptureJob.Status.QUEUED,
        progress=0,
    )
    emit_operational_event("capture.queued", capture_job_payload(job), capture_job=job)
    return job


def capture_job_payload(job: CaptureJob) -> dict[str, Any]:
    return {
        "jobId": job.id,
        "caseId": job.case_id,
        "sensorId": job.sensor_id or "",
        "mode": job.mode,
        "status": job.status,
        "interfaceName": job.interface_name,
        "durationSeconds": job.duration_seconds,
        "packetLimit": job.packet_limit,
        "chunkIntervalSeconds": job.chunk_interval_seconds,
        "bpfFilter": job.bpf_filter,
        "packetsCaptured": job.packets_captured,
        "packetsReceived": job.packets_captured,
        "bytesCaptured": job.bytes_captured,
        "chunksReceived": job.chunk_count,
        "progress": job.progress,
        "source": job.source_label or job.mode,
        "sourceLabel": job.source_label,
        "error": job.error_message,
        "startedAt": job.started_at.isoformat() if job.started_at else None,
        "completedAt": job.completed_at.isoformat() if job.completed_at else None,
        "evidenceId": job.final_evidence_file_id or "",
        "finalEvidenceId": job.final_evidence_file_id or "",
    }


def mark_capture_running(job: CaptureJob) -> None:
    if job.status == CaptureJob.Status.QUEUED:
        job.status = CaptureJob.Status.RUNNING
        job.started_at = django_timezone.now()
        job.save(update_fields=["status", "started_at", "updated_at"])
        emit_operational_event("capture.started", capture_job_payload(job), capture_job=job)


def _count_packets(path: str | Path) -> int:
    result = subprocess.run(
        ["tshark", "-r", str(path), "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "tshark could not count capture chunk packets")
    return len([line for line in result.stdout.splitlines() if line.strip()])


@transaction.atomic
def ingest_capture_chunk(job: CaptureJob, upload, sequence: int, sensor: Sensor | None = None) -> CaptureChunk:
    existing = CaptureChunk.objects.filter(capture_job=job, sequence=sequence).first()
    if existing:
        return existing
    mark_capture_running(job)
    saved = save_uploaded_file(upload, "capture_chunk")
    try:
        packet_count = _count_packets(saved["analysis_path"])
    finally:
        Path(saved["analysis_path"]).unlink(missing_ok=True)
    chunk = CaptureChunk.objects.create(
        id=f"{job.id}-chunk-{sequence:05d}",
        capture_job=job,
        sensor=sensor,
        sequence=sequence,
        stored_path=saved["stored_path"],
        plaintext_sha256=saved["plaintext_sha256"],
        encrypted_sha256=saved["encrypted_sha256"],
        packet_count=packet_count,
        byte_count=saved["size_bytes"],
        status=CaptureChunk.Status.PARSED,
    )
    job.chunk_count += 1
    job.last_chunk_sequence = max(job.last_chunk_sequence, sequence)
    job.packets_captured += packet_count
    job.bytes_captured += saved["size_bytes"]
    if job.packet_limit:
        job.progress = min(95, int(job.packets_captured * 100 / job.packet_limit))
    job.save(update_fields=["chunk_count", "last_chunk_sequence", "packets_captured", "bytes_captured", "progress", "updated_at"])
    payload = capture_job_payload(job) | {"chunkId": chunk.id, "sequence": sequence, "chunkPackets": packet_count, "chunkBytes": chunk.byte_count}
    emit_operational_event("capture.chunk_received", payload, capture_job=job)
    publish_event("netra.capture.chunk.received", payload)
    return chunk


def _merge_chunks(job: CaptureJob) -> tuple[Path, list[Path]]:
    chunks = list(job.chunks.order_by("sequence"))
    if not chunks:
        raise ValueError("Capture cannot be finalized without chunks.")
    working_dir = Path(tempfile.mkdtemp(prefix=f"netra-{job.id}-"))
    decrypted_paths = []
    for chunk in chunks:
        target = working_dir / f"{chunk.sequence:05d}.pcap"
        decrypt_file(chunk.stored_path, target)
        decrypted_paths.append(target)
    merged = working_dir / f"{job.id}.pcap"
    if len(decrypted_paths) == 1:
        shutil.copyfile(decrypted_paths[0], merged)
    else:
        result = subprocess.run(["mergecap", "-w", str(merged), *map(str, decrypted_paths)], capture_output=True, text=True, timeout=120, check=False)
        if result.returncode != 0:
            raise ValueError(result.stderr.strip() or "mergecap could not merge capture chunks")
    return merged, decrypted_paths


def finalize_capture(job: CaptureJob, actor: Actor | str = "Netra capture engine") -> dict[str, Any]:
    if job.final_evidence_file_id:
        return capture_job_payload(job)
    merged = None
    working_dir = None
    analysis_path = None
    try:
        emit_operational_event("analysis.started", capture_job_payload(job), capture_job=job)
        merged, _ = _merge_chunks(job)
        working_dir = merged.parent
        uploaded = SimpleUploadedFile(f"{job.id}.pcap", merged.read_bytes(), content_type="application/vnd.tcpdump.pcap")
        saved = save_uploaded_file(uploaded, "pcap")
        analysis_path = saved["analysis_path"]
        evidence_id = f"ev-{uuid4().hex[:8]}"
        analysis_job_id = f"job-{uuid4().hex[:8]}"
        analysis = analyze_pcap(analysis_path, job.case_id, evidence_id, analysis_job_id, saved | {"intake": {"investigator": job.case.investigator}})
        persistence_actor = actor if isinstance(actor, Actor) else Actor(str(actor), "System", authenticated=True)
        persist_analysis(analysis, saved, persistence_actor)
        job.final_evidence_file_id = evidence_id
        job.status = CaptureJob.Status.COMPLETED
        job.progress = 100
        job.completed_at = django_timezone.now()
        job.save(update_fields=["final_evidence_file", "status", "progress", "completed_at", "updated_at"])
        emit_operational_event("analysis.completed", capture_job_payload(job), capture_job=job)
        emit_operational_event("capture.completed", capture_job_payload(job), capture_job=job)
        publish_event("netra.capture.finalize", capture_job_payload(job))
        return capture_job_payload(job)
    except Exception as exc:
        job.status = CaptureJob.Status.FAILED
        job.error_message = str(exc)
        job.completed_at = django_timezone.now()
        job.save(update_fields=["status", "error_message", "completed_at", "updated_at"])
        emit_operational_event("capture.failed", capture_job_payload(job), capture_job=job)
        raise
    finally:
        if analysis_path:
            Path(analysis_path).unlink(missing_ok=True)
        if working_dir:
            shutil.rmtree(working_dir, ignore_errors=True)


def start_replay(job: CaptureJob, encrypted_source: str, speed: str = "max") -> None:
    thread = threading.Thread(target=_run_replay, args=(job.id, encrypted_source, speed), daemon=True, name=f"netra-replay-{job.id}")
    thread.start()


def _run_replay(job_id: str, encrypted_source: str, speed: str) -> None:
    job = CaptureJob.objects.get(id=job_id)
    source_dir = Path(tempfile.mkdtemp(prefix=f"netra-replay-{job_id}-"))
    plain_source = source_dir / "source.pcap"
    try:
        decrypt_file(encrypted_source, plain_source)
        mark_capture_running(job)
        sequence = 0
        emitted_packets = 0
        chunk_writer = None
        chunk_path = None
        chunk_started = None
        scale = {"1x": 1.0, "5x": 0.2, "max": 0.0}.get(speed, 0.0)
        for packet in PcapReader(str(plain_source)):
            job.refresh_from_db()
            if job.status == CaptureJob.Status.STOPPED:
                emit_operational_event("capture.stopped", capture_job_payload(job), capture_job=job)
                return
            packet_time = float(packet.time)
            if chunk_writer is None:
                sequence += 1
                chunk_path = source_dir / f"replay-{sequence:05d}.pcap"
                chunk_writer = PcapWriter(str(chunk_path), append=False, sync=True)
                chunk_started = packet_time
            if packet_time - float(chunk_started) >= job.chunk_interval_seconds and emitted_packets:
                chunk_writer.close()
                _ingest_replay_file(job, chunk_path, sequence)
                if scale:
                    time.sleep(job.chunk_interval_seconds * scale)
                chunk_writer = None
                chunk_path = None
                chunk_started = None
            if chunk_writer is None:
                sequence += 1
                chunk_path = source_dir / f"replay-{sequence:05d}.pcap"
                chunk_writer = PcapWriter(str(chunk_path), append=False, sync=True)
                chunk_started = packet_time
            chunk_writer.write(packet)
            emitted_packets += 1
            if emitted_packets >= job.packet_limit:
                break
        if chunk_writer is not None and chunk_path is not None:
            chunk_writer.close()
            _ingest_replay_file(job, chunk_path, sequence)
        finalize_capture(job)
    except Exception as exc:
        job.refresh_from_db()
        job.status = CaptureJob.Status.FAILED
        job.error_message = str(exc)
        job.completed_at = django_timezone.now()
        job.save(update_fields=["status", "error_message", "completed_at", "updated_at"])
        emit_operational_event("capture.failed", capture_job_payload(job), capture_job=job)
    finally:
        shutil.rmtree(source_dir, ignore_errors=True)


def _ingest_replay_file(job: CaptureJob, path: Path, sequence: int) -> None:
    upload = SimpleUploadedFile(path.name, path.read_bytes(), content_type="application/vnd.tcpdump.pcap")
    ingest_capture_chunk(job, upload, sequence)


def stop_capture(job: CaptureJob) -> dict[str, Any]:
    if job.status not in {CaptureJob.Status.COMPLETED, CaptureJob.Status.FAILED}:
        job.status = CaptureJob.Status.STOPPED
        job.completed_at = django_timezone.now()
        job.save(update_fields=["status", "completed_at", "updated_at"])
        emit_operational_event("capture.stopped", capture_job_payload(job), capture_job=job)
    return capture_job_payload(job)


def heartbeat_state(last_seen: datetime | None) -> str:
    if not last_seen:
        return "offline"
    age = django_timezone.now() - last_seen
    if age <= timedelta(seconds=30):
        return "healthy"
    if age <= timedelta(seconds=90):
        return "stale"
    return "offline"


def sensor_payload(sensor: Sensor) -> dict[str, Any]:
    state = heartbeat_state(sensor.last_heartbeat_at)
    return {
        "id": sensor.id,
        "name": sensor.name,
        "hostname": sensor.hostname,
        "platform": sensor.platform,
        "agentVersion": sensor.agent_version,
        "captureEngine": sensor.capture_engine,
        "captureEngineVersion": sensor.capture_engine_version,
        "status": "online" if state == "healthy" else state,
        "lastHeartbeatAt": sensor.last_heartbeat_at.isoformat() if sensor.last_heartbeat_at else None,
        "interfaces": sensor.interfaces_json,
        "metadata": sensor.metadata_json,
    }


def worker_payload(row: WorkerHeartbeat, expected_name: str | None = None) -> dict[str, Any]:
    return {
        "name": expected_name or row.worker_name,
        "instanceId": row.instance_id,
        "status": heartbeat_state(row.last_seen_at) if row.status == "healthy" else row.status,
        "lastSeen": row.last_seen_at.isoformat(),
        "currentJobId": row.current_job_id,
        "details": row.details_json,
    }
