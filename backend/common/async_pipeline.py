from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from apps.forensics.models import AnalysisChunk, Case, EvidenceFile, EvidenceManifest, ProcessingJob
from common.analysis import analyze_pcap
from common.audit import Actor, add_history, log_access
from common.custody import record_custody_event
from common.jobs import append_job_event, initial_steps
from common.kafka import publish_event
from common.persistence import case_origin, is_validator_case, persist_analysis
from common.storage import save_uploaded_file
from common.vault import build_manifest_payload, temporary_decrypted_copy


def queue_uploaded_evidence(saved: dict, case_id: str, evidence_id: str, job_id: str, actor: Actor) -> ProcessingJob:
    intake = saved.get("intake", {})
    case, _ = Case.objects.update_or_create(
        id=case_id,
        defaults={
            "title": f"Queued PCAP analysis: {saved['filename']}",
            "investigator": intake.get("investigator") or actor.user,
            "department": intake.get("department") or "Gujarat Cyber Crime Cell",
            "priority": intake.get("priority") or "Standard",
            "origin": case_origin(case_id, intake),
            "is_test": is_validator_case(case_id, intake),
            "opened_at": datetime.now(timezone.utc),
            "source_location": intake.get("sourceLocation", ""),
            "remarks": intake.get("remarks", ""),
            "flags_json": intake.get("flags", []),
        },
    )
    evidence, _ = EvidenceFile.objects.update_or_create(
        id=evidence_id,
        defaults={
            "case": case,
            "filename": saved["filename"],
            "stored_path": saved["stored_path"],
            "size_bytes": saved["size_bytes"],
            "sha256": saved["sha256"],
            "uploaded_by": actor.user,
            "status": EvidenceFile.Status.PROCESSING,
            "retention_expires_at": datetime.now(timezone.utc) + timedelta(days=90),
        },
    )
    manifest_payload = build_manifest_payload(saved, evidence.id, case.id)
    EvidenceManifest.objects.update_or_create(
        id=manifest_payload["id"],
        defaults={
            "case": case,
            "evidence_file": evidence,
            "plaintext_sha256": manifest_payload["plaintextSha256"],
            "encrypted_sha256": manifest_payload["encryptedSha256"],
            "storage_uri": manifest_payload["storageUri"],
            "original_filename": manifest_payload["originalFilename"],
            "size_bytes": manifest_payload["sizeBytes"],
            "encryption_algorithm": manifest_payload["encryptionAlgorithm"],
            "key_id": manifest_payload["keyId"],
            "manifest_json": manifest_payload,
            "manifest_hash": manifest_payload["manifestHash"],
        },
    )
    public_saved = {key: value for key, value in saved.items() if key != "analysis_path"}
    job, _ = ProcessingJob.objects.update_or_create(
        id=job_id,
        defaults={
            "case": case,
            "evidence_file": evidence,
            "status": ProcessingJob.Status.QUEUED,
            "step": "queued",
            "progress": 0,
            "steps": initial_steps(),
            "processing_path": "async-workers",
            "last_progress_at": datetime.now(timezone.utc),
            "stats": {"saved": public_saved, "intake": intake},
        },
    )
    add_history(case, actor, "Evidence queued", f"{saved['filename']} encrypted and queued for async analysis.", saved["sha256"])
    record_custody_event(case, actor, "Evidence uploaded", {"filename": saved["filename"], "sha256": saved["sha256"], "processingPath": "async-workers"}, evidence, "EvidenceFile", evidence.id)
    record_custody_event(case, "Netra vault", "Evidence encrypted", {"encryptedSha256": saved["encrypted_sha256"], "keyId": manifest_payload["keyId"]}, evidence, "EvidenceManifest", manifest_payload["id"])
    log_access(actor, "evidence.queue", case=case, resource_type="EvidenceFile", resource_id=evidence.id)
    return job


def process_queued_evidence(payload: dict) -> ProcessingJob:
    job = ProcessingJob.objects.select_related("evidence_file", "case").get(id=payload["jobId"])
    if job.status == ProcessingJob.Status.COMPLETED:
        return job
    saved = dict(payload["saved"])
    saved["intake"] = payload.get("intake", {})
    temporary = temporary_decrypted_copy(saved["stored_path"])
    try:
        job.status = ProcessingJob.Status.RUNNING
        job.step = "packet_parsing"
        job.progress = 12
        job.last_progress_at = datetime.now(timezone.utc)
        job.started_at = job.started_at or datetime.now(timezone.utc)
        job.save(update_fields=["status", "step", "progress", "last_progress_at", "started_at", "updated_at"])
        append_job_event(job, "async.analysis.started", "pcap-ingestion-worker started immutable evidence analysis.")
        chunks = _prepare_large_analysis_chunks(job, Path(temporary))
        analysis = analyze_pcap(temporary, job.case_id, job.evidence_file_id, job.id, saved)
        analysis["processingPath"] = "async-workers"
        analysis["searchCompleteness"] = "truncated-search-index" if chunks else "complete"
        actor = Actor("Netra async worker", "System", authenticated=True)
        completed = persist_analysis(analysis, saved, actor)
        append_job_event(completed, "async.analysis.completed", "Async worker pipeline persisted final analysis.")
        return completed
    finally:
        Path(temporary).unlink(missing_ok=True)


def _prepare_large_analysis_chunks(job: ProcessingJob, plaintext_path: Path) -> list[AnalysisChunk]:
    threshold_bytes = settings.NETRA_ANALYSIS_SPLIT_THRESHOLD_MB * 1024 * 1024
    if plaintext_path.stat().st_size < threshold_bytes:
        return []
    chunks: list[AnalysisChunk] = []
    with TemporaryDirectory(prefix=f"{job.id}-split-") as folder:
        target = Path(folder) / "analysis.pcap"
        subprocess.run(
            ["editcap", "-c", str(settings.NETRA_ANALYSIS_CHUNK_PACKETS), str(plaintext_path), str(target)],
            check=True,
            capture_output=True,
            text=True,
        )
        for sequence, split_path in enumerate(sorted(Path(folder).glob("analysis*.pcap")), start=1):
            upload = SimpleUploadedFile(split_path.name, split_path.read_bytes(), content_type="application/vnd.tcpdump.pcap")
            saved = save_uploaded_file(upload, "capture_chunk")
            Path(saved["analysis_path"]).unlink(missing_ok=True)
            chunk = AnalysisChunk.objects.create(
                processing_job=job,
                sequence=sequence,
                encrypted_source_path=saved["stored_path"],
                plaintext_sha256=saved["sha256"],
                byte_count=saved["size_bytes"],
            )
            chunks.append(chunk)
    job.expected_chunk_count = len(chunks)
    job.completeness_status = "truncated-search-index"
    job.save(update_fields=["expected_chunk_count", "completeness_status", "updated_at"])
    append_job_event(job, "async.analysis.chunked", f"Large PCAP split into {len(chunks)} encrypted parser chunks.")
    for chunk in chunks:
        publish_event(
            "netra.analysis.chunk.ready",
            {
                "type": "analysis.chunk.ready",
                "jobId": job.id,
                "caseId": job.case_id,
                "evidenceId": job.evidence_file_id,
                "analysisChunkId": chunk.id,
                "sequence": chunk.sequence,
            },
            key=f"{job.id}:{chunk.id}",
        )
    return chunks
