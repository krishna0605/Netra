from __future__ import annotations

import subprocess
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from uuid import uuid4

from django.conf import settings
from django.core.files import File
from django.core.files.uploadedfile import SimpleUploadedFile

from apps.forensics.models import AnalysisChunk, Case, CaseMembership, EvidenceFile, EvidenceManifest, EvidenceUploadSession, ProcessingJob, WorkerStageReceipt
from common.analysis import analyze_pcap
from common.audit import Actor, add_history, log_access
from common.custody import record_custody_event
from common.evidence_normalization import normalize_evidence_upload
from common.jobs import append_job_event, initial_steps
from common.kafka import publish_event
from common.persistence import case_origin, is_validator_case, persist_analysis
from common.postgres_jobs import JobCancellationRequested
from common.storage import save_uploaded_file
from common.storage_provider import storage_provider
from common.structured_analysis import analyze_structured_evidence
from common.vault import build_manifest_payload, temporary_decrypted_copy
from common.vault_v2 import encrypt_evidence_v2


def queue_uploaded_evidence(
    saved: dict,
    case_id: str,
    evidence_id: str,
    job_id: str,
    actor: Actor,
    *,
    idempotency_key: str | None = None,
) -> ProcessingJob:
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
    if actor.django_user_id:
        CaseMembership.objects.update_or_create(
            case=case,
            user_id=actor.django_user_id,
            defaults={"role": actor.role, "added_by": "upload"},
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
    public_saved = {key: value for key, value in saved.items() if key not in {"analysis_path", "v2_manifest"}}
    job, _ = ProcessingJob.objects.update_or_create(
        id=job_id,
        defaults={
            "case": case,
            "evidence_file": evidence,
            "status": ProcessingJob.Status.QUEUED,
            "step": "queued",
            "progress": 0,
            "steps": initial_steps(),
            "processing_path": "postgres-worker",
            "last_progress_at": datetime.now(timezone.utc),
            "idempotency_key": idempotency_key,
            "max_attempts": settings.NETRA_WORKER_MAX_RETRIES,
            "stats": {
                "saved": public_saved,
                "intake": intake,
                "actor": {
                    "user": actor.user,
                    "role": actor.role,
                    "djangoUserId": actor.django_user_id,
                    "email": actor.email,
                    "externalId": actor.external_id,
                },
            },
        },
    )
    add_history(case, actor, "Evidence queued", f"{saved['filename']} encrypted and queued for async analysis.", saved["sha256"])
    record_custody_event(case, actor, "Evidence uploaded", {"filename": saved["filename"], "sha256": saved["sha256"], "processingPath": "postgres-worker"}, evidence, "EvidenceFile", evidence.id)
    record_custody_event(case, "Netra vault", "Evidence encrypted", {"encryptedSha256": saved["encrypted_sha256"], "keyId": manifest_payload["keyId"]}, evidence, "EvidenceManifest", manifest_payload["id"])
    log_access(actor, "evidence.queue", case=case, resource_type="EvidenceFile", resource_id=evidence.id)
    return job


def process_queued_evidence(payload: dict) -> ProcessingJob:
    job = ProcessingJob.objects.select_related("evidence_file", "case").get(id=payload["jobId"])
    if job.status == ProcessingJob.Status.COMPLETED:
        return job
    if job.cancel_requested_at or job.status == ProcessingJob.Status.CANCELED:
        raise JobCancellationRequested("Job cancellation was requested before analysis started.")
    saved = dict(payload["saved"])
    saved["intake"] = payload.get("intake", {})
    temporary = payload.get("analysisPath") or temporary_decrypted_copy(saved["stored_path"])
    try:
        job.status = ProcessingJob.Status.RUNNING
        job.step = "packet_parsing"
        job.progress = 12
        job.last_progress_at = datetime.now(timezone.utc)
        job.started_at = job.started_at or datetime.now(timezone.utc)
        job.save(update_fields=["status", "step", "progress", "last_progress_at", "started_at", "updated_at"])
        append_job_event(job, "async.analysis.started", "pcap-ingestion-worker started immutable evidence analysis.")
        chunks = _prepare_large_analysis_chunks(job, Path(temporary))
        evidence_type = (saved.get("normalization") or {}).get("normalizedType", "PCAP")
        analysis = (
            analyze_pcap(temporary, job.case_id, job.evidence_file_id, job.id, saved)
            if evidence_type == EvidenceFile.EvidenceType.PCAP
            else analyze_structured_evidence(temporary, job.case_id, job.evidence_file_id, job.id, saved)
        )
        job.refresh_from_db(fields=["cancel_requested_at"])
        if job.cancel_requested_at:
            raise JobCancellationRequested("Job cancellation was requested during analysis.")
        analysis["processingPath"] = "postgres-worker"
        analysis["searchCompleteness"] = "truncated-search-index" if chunks else "complete"
        actor_data = payload.get("actor") or {}
        actor = Actor(
            actor_data.get("user") or "Netra durable worker",
            actor_data.get("role") or "Investigator",
            authenticated=True,
            django_user_id=actor_data.get("djangoUserId"),
            email=actor_data.get("email") or "",
            external_id=actor_data.get("externalId") or "",
        )
        completed = persist_analysis(analysis, saved, actor)
        WorkerStageReceipt.objects.update_or_create(
            idempotency_key=f"{job.id}:analysis-finalized",
            defaults={
                "worker_name": "postgres-analysis",
                "job_id": job.id,
                "stage": "analysis-finalized",
                "result_json": {"status": "completed", "summary": analysis.get("summary", {})},
            },
        )
        append_job_event(completed, "async.analysis.completed", "Async worker pipeline persisted final analysis.")
        EvidenceUploadSession.objects.filter(processing_job_id=completed.id).update(
            status=EvidenceUploadSession.Status.COMPLETED,
            failure_code="",
        )
        return completed
    finally:
        Path(temporary).unlink(missing_ok=True)


def process_claimed_job(job: ProcessingJob) -> ProcessingJob:
    payload = dict(job.stats or {})
    saved = dict(payload.get("saved") or {})
    analysis_path = None
    if not saved and payload.get("uploadSessionId"):
        saved, analysis_path = _prepare_quarantine_evidence(job, payload)
    if not saved:
        raise ValueError("Queued job is missing its immutable evidence descriptor.")
    return process_queued_evidence(
        {
            "jobId": job.id,
            "saved": saved,
            "intake": payload.get("intake") or saved.get("intake") or {},
            "actor": payload.get("actor") or {},
            "analysisPath": analysis_path,
        }
    )


def _actor_from_job_payload(payload: dict) -> Actor:
    actor_data = payload.get("actor") or {}
    return Actor(
        actor_data.get("user") or "Netra durable worker",
        actor_data.get("role") or "Investigator",
        authenticated=True,
        django_user_id=actor_data.get("djangoUserId"),
        email=actor_data.get("email") or "",
        external_id=actor_data.get("externalId") or "",
    )


def _prepare_quarantine_evidence(job: ProcessingJob, payload: dict) -> tuple[dict, str]:
    session = EvidenceUploadSession.objects.select_related("case", "user").get(
        pk=payload["uploadSessionId"],
        processing_job=job,
    )
    session.status = EvidenceUploadSession.Status.PROCESSING
    session.save(update_fields=["status", "updated_at"])
    settings.NETRA_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(delete=False, dir=settings.NETRA_TEMP_ROOT, suffix=Path(session.expected_filename).suffix or ".evidence") as temporary:
        plaintext_path = Path(temporary.name)
    os.chmod(plaintext_path, 0o600)
    quarantine_bucket = settings.SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE
    try:
        downloaded = storage_provider.download_bucket_object(
            quarantine_bucket,
            session.storage_path,
            plaintext_path,
            max_bytes=session.expected_size_bytes,
        )
        if downloaded.size_bytes != session.expected_size_bytes:
            raise ValueError("Quarantine object size changed after finalization.")
        with plaintext_path.open("rb") as handle:
            normalization_result = normalize_evidence_upload(
                File(handle, name=session.expected_filename),
                session.expected_evidence_type,
            )
        if not normalization_result.valid:
            session.status = EvidenceUploadSession.Status.FAILED
            session.failure_code = normalization_result.code or "evidence_validation_failed"
            session.normalization_json = normalization_result.to_dict()
            session.save(update_fields=["status", "failure_code", "normalization_json", "updated_at"])
            raise ValueError(normalization_result.reason)

        evidence_id = str(payload.get("evidenceId") or f"ev-{uuid4().hex[:12]}")
        saved = encrypt_evidence_v2(plaintext_path, evidence_id, session.case_id)
        saved.update(
            {
                "filename": session.expected_filename,
                "analysis_path": str(plaintext_path),
                "intake": session.intake_json,
                "normalization": normalization_result.to_dict(),
            }
        )
        actor = _actor_from_job_payload(payload)
        evidence, _ = EvidenceFile.objects.update_or_create(
            id=evidence_id,
            defaults={
                "case": session.case,
                "filename": session.expected_filename,
                "stored_path": saved["stored_path"],
                "evidence_type": normalization_result.normalized_type,
                "size_bytes": saved["size_bytes"],
                "sha256": saved["sha256"],
                "uploaded_by": actor.user,
                "status": EvidenceFile.Status.PROCESSING,
                "retention_expires_at": datetime.now(timezone.utc) + timedelta(days=90),
            },
        )
        manifest_payload = build_manifest_payload(saved, evidence.id, session.case_id)
        EvidenceManifest.objects.update_or_create(
            id=manifest_payload["id"],
            defaults={
                "case": session.case,
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
        public_saved = {key: value for key, value in saved.items() if key not in {"analysis_path", "v2_manifest"}}
        job.evidence_file = evidence
        job.step = "hash_verified"
        job.progress = 10
        job.last_progress_at = datetime.now(timezone.utc)
        job.stats = {**payload, "saved": public_saved, "summary": {}}
        job.save(update_fields=["evidence_file", "step", "progress", "last_progress_at", "stats", "updated_at"])
        session.actual_sha256 = saved["sha256"]
        session.normalization_json = normalization_result.to_dict()
        session.save(update_fields=["actual_sha256", "normalization_json", "updated_at"])
        add_history(session.case, actor, "Evidence secured", f"{session.expected_filename} passed full-file validation and V2 encryption.", saved["sha256"])
        record_custody_event(
            session.case,
            actor,
            "Evidence uploaded",
            {"filename": session.expected_filename, "sha256": saved["sha256"], "processingPath": "resumable-quarantine"},
            evidence,
            "EvidenceFile",
            evidence.id,
        )
        record_custody_event(
            session.case,
            "Netra vault",
            "Evidence encrypted",
            {"encryptedSha256": saved["encrypted_sha256"], "keyId": manifest_payload["keyId"], "version": "v2"},
            evidence,
            "EvidenceManifest",
            manifest_payload["id"],
        )
        log_access(actor, "evidence.queue", case=session.case, resource_type="EvidenceFile", resource_id=evidence.id)
        storage_provider.delete_bucket_object(quarantine_bucket, session.storage_path)
        append_job_event(job, "quarantine.committed", "Full evidence was validated, encrypted in V2 chunks, and removed from quarantine.")
        return saved, str(plaintext_path)
    except Exception:
        plaintext_path.unlink(missing_ok=True)
        raise


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
