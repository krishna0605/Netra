from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID, uuid4

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.utils import timezone

from apps.forensics.models import Case, CaseMembership, EvidenceFile, EvidenceUploadSession, ProcessingJob, UserProfile
from common.audit import Actor, can_actor_access_case
from common.case_metadata import InvalidCaseFlags, server_case_identity, validated_case_flags
from common.hashing import sha256_text
from common.jobs import initial_steps
from common.storage_provider import storage_provider


PRE_FINAL_STATUSES = {
    EvidenceUploadSession.Status.CREATED,
    EvidenceUploadSession.Status.UPLOADING,
    EvidenceUploadSession.Status.UPLOADED,
}
ACTIVE_STATUSES = {
    *PRE_FINAL_STATUSES,
    EvidenceUploadSession.Status.FINALIZED,
    EvidenceUploadSession.Status.QUEUED,
    EvidenceUploadSession.Status.PROCESSING,
}
EXPECTED_EVIDENCE_TYPES = {
    "Auto-detect",
    *(value for value, _label in EvidenceFile.EvidenceType.choices),
}
CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
SAFE_OBJECT_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class UploadSessionProblem(RuntimeError):
    code: str
    message: str
    status: int = 400

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class QuarantineObjectMetadata:
    owner_id: str
    size_bytes: int
    content_type: str


def _text(value, *, maximum: int, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    if len(result) > maximum:
        raise UploadSessionProblem("invalid_upload_metadata", f"A metadata value exceeds the {maximum}-character limit.")
    return result


def _validated_external_user_id(actor: Actor) -> str:
    if not actor.django_user_id or not actor.external_id:
        raise UploadSessionProblem("direct_upload_identity_unavailable", "A verified Supabase identity is required for resumable upload.", 403)
    try:
        return str(UUID(actor.external_id))
    except (TypeError, ValueError) as exc:
        raise UploadSessionProblem("direct_upload_identity_invalid", "The authenticated identity cannot create a resumable upload.", 403) from exc


def _validated_filename(value) -> str:
    filename = _text(value, maximum=255)
    if not filename or filename in {".", ".."} or "\x00" in filename or "/" in filename or "\\" in filename:
        raise UploadSessionProblem("invalid_filename", "Provide a plain evidence filename without path components.")
    if Path(filename).name != filename:
        raise UploadSessionProblem("invalid_filename", "Provide a plain evidence filename without path components.")
    return filename


def _object_filename(filename: str) -> str:
    normalized = SAFE_OBJECT_COMPONENT.sub("_", filename).strip("._")
    if not normalized:
        normalized = "evidence.bin"
    return normalized[:180]


def _validated_size(value) -> int:
    if isinstance(value, bool):
        raise UploadSessionProblem("invalid_upload_size", "Evidence size must be an integer number of bytes.")
    try:
        size_bytes = int(value)
    except (TypeError, ValueError) as exc:
        raise UploadSessionProblem("invalid_upload_size", "Evidence size must be an integer number of bytes.") from exc
    maximum = settings.NETRA_DIRECT_UPLOAD_MAX_MB * 1024 * 1024
    if size_bytes < 1 or size_bytes > maximum:
        raise UploadSessionProblem(
            "upload_too_large" if size_bytes > maximum else "invalid_upload_size",
            f"This deployment accepts resumable evidence from 1 byte through {settings.NETRA_DIRECT_UPLOAD_MAX_MB} MiB.",
            413 if size_bytes > maximum else 400,
        )
    return size_bytes


def _intake_payload(payload: dict, actor: Actor, organization: str, evidence_type: str) -> dict:
    raw_flags = payload.get("flags") or []
    try:
        flags = validated_case_flags(raw_flags)
    except InvalidCaseFlags as exc:
        raise UploadSessionProblem("invalid_case_flags", str(exc)) from exc
    priority = _text(payload.get("priority"), maximum=32, default=Case.Priority.STANDARD)
    if priority not in {choice for choice, _label in Case.Priority.choices}:
        raise UploadSessionProblem("invalid_priority", "Priority must be Standard, Urgent, or Critical.")
    return {
        "investigator": actor.user,
        "department": organization,
        "selectedEvidenceType": evidence_type,
        "sourceLocation": _text(payload.get("sourceLocation"), maximum=255),
        "priority": priority,
        "remarks": _text(payload.get("remarks"), maximum=4000),
        "flags": flags,
        "sourceIp": _text(payload.get("sourceIp"), maximum=80),
        "destinationIp": _text(payload.get("destinationIp"), maximum=80),
        "protocol": _text(payload.get("protocol"), maximum=40).upper(),
        "port": _text(payload.get("port"), maximum=8),
        "durationSeconds": _text(payload.get("durationSeconds"), maximum=12),
        "packetLimit": _text(payload.get("packetLimit"), maximum=12),
        "bpfFilter": _text(payload.get("bpfFilter"), maximum=255),
    }


def _ensure_direct_upload_enabled() -> None:
    if not settings.NETRA_DIRECT_UPLOAD_ENABLED:
        raise UploadSessionProblem("direct_upload_disabled", "Resumable evidence upload is not enabled in this deployment profile.", 404)
    if settings.NETRA_STORAGE_PROVIDER != "supabase":
        raise UploadSessionProblem("direct_upload_storage_unavailable", "Resumable evidence storage is unavailable.", 503)


def create_upload_session(actor: Actor, payload: dict, raw_idempotency_key: str = "") -> tuple[EvidenceUploadSession, bool]:
    _ensure_direct_upload_enabled()
    external_user_id = _validated_external_user_id(actor)
    filename = _validated_filename(payload.get("filename"))
    size_bytes = _validated_size(payload.get("sizeBytes"))
    evidence_type = _text(payload.get("evidenceType"), maximum=64, default="Auto-detect")
    if evidence_type not in EXPECTED_EVIDENCE_TYPES:
        raise UploadSessionProblem("invalid_evidence_type", "Select Auto-detect or a supported evidence type.")
    content_type = _text(payload.get("contentType"), maximum=160, default="application/octet-stream") or "application/octet-stream"
    if "\r" in content_type or "\n" in content_type:
        raise UploadSessionProblem("invalid_content_type", "Evidence content type is invalid.")
    requested_case_id = _text(payload.get("caseId"), maximum=64)
    case_id = requested_case_id or f"CYB-GJ-{timezone.now().year}-{uuid4().hex[:8].upper()}"
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise UploadSessionProblem("invalid_case_id", "Case ID contains unsupported characters.")
    if len(raw_idempotency_key) > 128:
        raise UploadSessionProblem("invalid_idempotency_key", "Idempotency key is too long.")
    idempotency_key = sha256_text(f"{external_user_id}:{raw_idempotency_key}") if raw_idempotency_key else None

    user = get_user_model().objects.filter(pk=actor.django_user_id).first()
    if user is None:
        raise UploadSessionProblem("direct_upload_identity_unavailable", "The authenticated application profile is unavailable.", 403)
    investigator, organization = server_case_identity(actor)
    intake = _intake_payload(payload, actor, organization, evidence_type)
    intake["investigator"] = investigator

    if idempotency_key:
        existing = EvidenceUploadSession.objects.filter(idempotency_key=idempotency_key, user=user).first()
        if existing:
            if existing.expected_filename != filename or existing.expected_size_bytes != size_bytes or (requested_case_id and existing.case_id != requested_case_id):
                raise UploadSessionProblem("idempotency_conflict", "The idempotency key was already used with different upload details.", 409)
            return existing, True

    try:
        with transaction.atomic():
            now = timezone.now()
            EvidenceUploadSession.objects.select_for_update().filter(
                user=user,
                status__in=PRE_FINAL_STATUSES,
                expires_at__lte=now,
            ).update(status=EvidenceUploadSession.Status.EXPIRED, failure_code="upload_session_expired")
            active = EvidenceUploadSession.objects.select_for_update().filter(user=user, status__in=ACTIVE_STATUSES).first()
            if active:
                raise UploadSessionProblem(
                    "active_upload_exists",
                    f"Finish or cancel the active upload session {active.id} before starting another.",
                    409,
                )

            case = Case.objects.select_for_update().filter(pk=case_id).first()
            if case is not None and not can_actor_access_case(actor, case):
                raise UploadSessionProblem("case_not_found", "Case not found.", 404)
            if case is None:
                case = Case.objects.create(
                    id=case_id,
                    title=_text(payload.get("caseTitle"), maximum=255, default=f"Evidence intake: {filename}") or f"Evidence intake: {filename}",
                    investigator=investigator,
                    department=organization,
                    priority=intake["priority"],
                    origin=Case.Origin.OFFICER_UPLOAD,
                    opened_at=now,
                    source_location=intake["sourceLocation"],
                    remarks=intake["remarks"],
                    flags_json=intake["flags"],
                )
            CaseMembership.objects.update_or_create(
                case=case,
                user=user,
                defaults={"role": actor.role, "added_by": actor.user},
            )

            session_id = uuid4()
            storage_path = f"{external_user_id}/{session_id}/{_object_filename(filename)}"
            fingerprint = sha256_text(
                f"{external_user_id}:{case.id}:{filename}:{size_bytes}:{_text(payload.get('lastModified'), maximum=40)}"
            )
            session = EvidenceUploadSession.objects.create(
                id=session_id,
                user=user,
                external_user_id=external_user_id,
                organization=organization,
                case=case,
                expected_filename=filename,
                expected_size_bytes=size_bytes,
                expected_evidence_type=evidence_type,
                expected_content_type=content_type,
                storage_path=storage_path,
                expires_at=now + timedelta(seconds=settings.NETRA_UPLOAD_SESSION_TTL_SECONDS),
                fingerprint=fingerprint,
                intake_json=intake,
                idempotency_key=idempotency_key,
            )
            return session, False
    except IntegrityError as exc:
        raise UploadSessionProblem("active_upload_exists", "Another active upload session already exists for this user.", 409) from exc


def get_upload_session(actor: Actor, session_id) -> EvidenceUploadSession:
    _ensure_direct_upload_enabled()
    rows = EvidenceUploadSession.objects.select_related("case", "processing_job")
    if actor.role != UserProfile.Role.ADMIN:
        rows = rows.filter(user_id=actor.django_user_id)
    session = rows.filter(pk=session_id).first()
    if session is None:
        raise UploadSessionProblem("upload_session_not_found", "Upload session not found.", 404)
    if session.status in PRE_FINAL_STATUSES and session.expires_at <= timezone.now():
        session.status = EvidenceUploadSession.Status.EXPIRED
        session.failure_code = "upload_session_expired"
        session.save(update_fields=["status", "failure_code", "updated_at"])
    return session


def _quarantine_metadata(storage_path: str) -> QuarantineObjectMetadata | None:
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select owner_id, (metadata->>'size')::bigint, coalesce(metadata->>'mimetype', '')
                from storage.objects
                where bucket_id = %s and name = %s
                limit 1
                """,
                [settings.SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE, storage_path],
            )
            row = cursor.fetchone()
    except DatabaseError as exc:
        raise UploadSessionProblem("quarantine_metadata_unavailable", "Evidence upload metadata is temporarily unavailable.", 503) from exc
    if row is None:
        return None
    return QuarantineObjectMetadata(owner_id=str(row[0] or ""), size_bytes=int(row[1] or 0), content_type=str(row[2] or ""))


def _delete_quarantine_object(session: EvidenceUploadSession) -> None:
    try:
        storage_provider.delete(
            f"supabase://{settings.SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE}/{session.storage_path}"
        )
    except Exception:
        # Cleanup is retried by the orphan-cleanup command in the worker phase.
        pass


def finalize_upload_session(actor: Actor, session_id) -> EvidenceUploadSession:
    session = get_upload_session(actor, session_id)
    if session.status in {
        EvidenceUploadSession.Status.QUEUED,
        EvidenceUploadSession.Status.PROCESSING,
        EvidenceUploadSession.Status.COMPLETED,
    } or (session.status == EvidenceUploadSession.Status.FINALIZED and session.processing_job_id):
        return session
    if session.status == EvidenceUploadSession.Status.EXPIRED:
        raise UploadSessionProblem("upload_session_expired", "The upload session expired. Create a new session and resume with a new URL.", 410)
    if session.status in {EvidenceUploadSession.Status.FAILED, EvidenceUploadSession.Status.CANCELED}:
        raise UploadSessionProblem("upload_session_closed", "The upload session is closed.", 409)

    metadata = _quarantine_metadata(session.storage_path)
    if metadata is None:
        raise UploadSessionProblem("upload_not_complete", "The resumable upload is not complete yet.", 409)
    if metadata.owner_id != session.external_user_id:
        session.status = EvidenceUploadSession.Status.FAILED
        session.failure_code = "quarantine_owner_mismatch"
        session.save(update_fields=["status", "failure_code", "updated_at"])
        _delete_quarantine_object(session)
        raise UploadSessionProblem("quarantine_owner_mismatch", "The uploaded object failed ownership validation.", 422)
    if metadata.size_bytes != session.expected_size_bytes:
        session.status = EvidenceUploadSession.Status.FAILED
        session.failure_code = "quarantine_size_mismatch"
        session.actual_size_bytes = metadata.size_bytes
        session.save(update_fields=["status", "failure_code", "actual_size_bytes", "updated_at"])
        _delete_quarantine_object(session)
        raise UploadSessionProblem("quarantine_size_mismatch", "The uploaded object size does not match the authorized session.", 422)

    with transaction.atomic():
        session = EvidenceUploadSession.objects.select_for_update().select_related("case").get(pk=session.pk)
        if session.processing_job_id:
            return session
        active_jobs = ProcessingJob.objects.filter(
            case__department=session.organization,
            status__in=[ProcessingJob.Status.QUEUED, ProcessingJob.Status.RUNNING],
        ).count()
        if active_jobs >= settings.NETRA_MAX_QUEUED_ANALYSES_PER_ORG:
            raise UploadSessionProblem(
                "organization_queue_limit",
                "This organization has reached its active analysis limit. Retry finalization after an existing job completes.",
                429,
            )
        now = timezone.now()
        job_id = f"job-{uuid4().hex[:12]}"
        evidence_id = f"ev-{uuid4().hex[:12]}"
        job = ProcessingJob.objects.create(
            id=job_id,
            case=session.case,
            status=ProcessingJob.Status.QUEUED,
            step="uploaded",
            progress=5,
            steps=initial_steps("uploaded"),
            processing_path="postgres-worker",
            last_progress_at=now,
            max_attempts=settings.NETRA_WORKER_MAX_RETRIES,
            stats={
                "uploadSessionId": str(session.id),
                "evidenceId": evidence_id,
                "intake": session.intake_json,
                "actor": {
                    "user": actor.user,
                    "role": actor.role,
                    "djangoUserId": actor.django_user_id,
                    "email": actor.email,
                    "externalId": actor.external_id,
                },
            },
        )
        session.status = EvidenceUploadSession.Status.QUEUED
        session.actual_size_bytes = metadata.size_bytes
        session.actual_content_type = metadata.content_type[:160]
        session.finalized_at = now
        session.failure_code = ""
        session.processing_job = job
        session.save(
            update_fields=[
                "status",
                "actual_size_bytes",
                "actual_content_type",
                "finalized_at",
                "failure_code",
                "processing_job",
                "updated_at",
            ]
        )
        return session


def _tus_endpoint() -> str:
    parsed = urlparse(settings.SUPABASE_URL)
    project_ref = settings.SUPABASE_PROJECT_REF.strip()
    if not project_ref and parsed.hostname:
        project_ref = parsed.hostname.split(".", 1)[0]
    if not re.fullmatch(r"[a-z0-9-]+", project_ref):
        raise UploadSessionProblem("direct_upload_endpoint_unavailable", "The direct Storage endpoint is not configured.", 503)
    return f"https://{project_ref}.storage.supabase.co/storage/v1/upload/resumable"


def upload_session_payload(session: EvidenceUploadSession, *, idempotent_replay: bool = False) -> dict:
    return {
        "id": str(session.id),
        "caseId": session.case_id,
        "status": session.status,
        "filename": session.expected_filename,
        "expectedSizeBytes": session.expected_size_bytes,
        "actualSizeBytes": session.actual_size_bytes,
        "evidenceType": session.expected_evidence_type,
        "contentType": session.expected_content_type,
        "bucketName": settings.SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE,
        "objectName": session.storage_path,
        "fingerprint": session.fingerprint,
        "expiresAt": session.expires_at.isoformat(),
        "finalizedAt": session.finalized_at.isoformat() if session.finalized_at else None,
        "failureCode": session.failure_code,
        "jobId": session.processing_job_id or "",
        "idempotentReplay": idempotent_replay,
        "tus": {
            "endpoint": _tus_endpoint(),
            "chunkSizeBytes": settings.NETRA_UPLOAD_TUS_CHUNK_BYTES,
            "retryDelaysMs": [0, 3000, 5000, 10000, 20000],
            "upsert": False,
        },
    }
