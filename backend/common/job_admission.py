from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.db import transaction

from apps.forensics.models import (
    Case,
    CaseMembership,
    EvidenceFile,
    EvidenceManifest,
    Organization,
    ProcessingJob,
)
from common.audit import Actor, add_history, log_access
from common.custody import record_custody_event
from common.identifiers import validate_case_id
from common.jobs import initial_steps
from common.persistence import case_origin, is_validator_case
from common.queue_limits import lock_and_check_queue_capacity
from common.tenancy import netra_organization
from common.vault import build_manifest_payload


@transaction.atomic
def queue_uploaded_evidence(
    saved: dict,
    case_id: str,
    evidence_id: str,
    job_id: str,
    actor: Actor,
    *,
    idempotency_key: str | None = None,
) -> ProcessingJob:
    """Admit immutable evidence without importing worker/parser code."""

    case_id = validate_case_id(case_id)
    organization = (
        netra_organization()
        if not actor.organization_id
        else Organization.objects.get(pk=actor.organization_id)
    )
    lock_and_check_queue_capacity(organization.id, job_id=job_id)
    intake = saved.get("intake", {})
    case = Case.objects.filter(id=case_id, organization=organization).first()
    if not case and Case.objects.filter(id=case_id).exists():
        raise ValueError("The requested case is outside the authenticated organization.")
    if not case:
        case = Case.objects.create(
            id=case_id,
            organization=organization,
            display_reference=case_id,
            title=f"Queued evidence analysis: {saved['filename']}",
            investigator=intake.get("investigator") or actor.user,
            department=intake.get("department") or "Gujarat Cyber Crime Cell",
            priority=intake.get("priority") or "Standard",
            origin=case_origin(case_id, intake),
            is_test=is_validator_case(case_id, intake),
            opened_at=datetime.now(timezone.utc),
            source_location=intake.get("sourceLocation", ""),
            remarks=intake.get("remarks", ""),
            flags_json=intake.get("flags", []),
        )
    evidence, _ = EvidenceFile.objects.update_or_create(
        id=evidence_id,
        defaults={
            "case": case,
            "filename": saved["filename"],
            "stored_path": saved["stored_path"],
            "evidence_type": (saved.get("normalization") or {}).get("normalizedType")
            or EvidenceFile.EvidenceType.PCAP,
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
    public_saved = {
        key: value
        for key, value in saved.items()
        if key not in {"analysis_path", "v2_manifest"}
    }
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
    add_history(
        case,
        actor,
        "Evidence queued",
        f"{saved['filename']} encrypted and queued for async analysis.",
        saved["sha256"],
    )
    record_custody_event(
        case,
        actor,
        "Evidence uploaded",
        {
            "filename": saved["filename"],
            "sha256": saved["sha256"],
            "processingPath": "postgres-worker",
        },
        evidence,
        "EvidenceFile",
        evidence.id,
    )
    record_custody_event(
        case,
        "Netra vault",
        "Evidence encrypted",
        {
            "encryptedSha256": saved["encrypted_sha256"],
            "keyId": manifest_payload["keyId"],
        },
        evidence,
        "EvidenceManifest",
        manifest_payload["id"],
    )
    log_access(
        actor,
        "evidence.queue",
        case=case,
        resource_type="EvidenceFile",
        resource_id=evidence.id,
    )
    return job
