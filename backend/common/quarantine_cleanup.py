from __future__ import annotations

import time
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.db import DatabaseError, connection
from django.db.models import Q
from django.utils import timezone

from apps.forensics.models import EvidenceUploadSession
from common.storage_provider import storage_provider


def cleanup_stale_temporary_files() -> int:
    root = settings.NETRA_TEMP_ROOT.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - settings.NETRA_QUARANTINE_ORPHAN_SECONDS
    removed = 0
    for candidate in root.rglob("*"):
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
            if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_mtime >= cutoff:
                continue
            candidate.unlink(missing_ok=True)
            removed += 1
        except (FileNotFoundError, OSError, ValueError):
            continue
    return removed


def cleanup_orphan_quarantine_objects(limit: int = 100) -> int:
    if settings.NETRA_STORAGE_PROVIDER != "supabase":
        return 0
    cutoff = timezone.now() - timedelta(seconds=settings.NETRA_QUARANTINE_ORPHAN_SECONDS)
    active_paths = set(
        EvidenceUploadSession.objects.filter(
            Q(
                status__in=[
                    EvidenceUploadSession.Status.CREATED,
                    EvidenceUploadSession.Status.UPLOADING,
                    EvidenceUploadSession.Status.UPLOADED,
                ],
                expires_at__gt=timezone.now(),
            )
            | Q(
                status__in=[
                    EvidenceUploadSession.Status.FINALIZED,
                    EvidenceUploadSession.Status.QUEUED,
                    EvidenceUploadSession.Status.PROCESSING,
                ]
            )
        ).values_list("storage_path", flat=True)
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select name
                from storage.objects
                where bucket_id = %s and created_at < %s
                order by created_at
                limit %s
                """,
                [settings.SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE, cutoff, limit],
            )
            candidates = [str(row[0]) for row in cursor.fetchall()]
    except DatabaseError:
        return 0
    removed = 0
    for object_name in candidates:
        if object_name in active_paths:
            continue
        try:
            storage_provider.delete_bucket_object(settings.SUPABASE_STORAGE_BUCKET_EVIDENCE_QUARANTINE, object_name)
            removed += 1
        except Exception:
            continue
    EvidenceUploadSession.objects.filter(
        status__in=[EvidenceUploadSession.Status.CREATED, EvidenceUploadSession.Status.UPLOADING],
        expires_at__lte=timezone.now(),
    ).update(status=EvidenceUploadSession.Status.EXPIRED, failure_code="upload_session_expired")
    return removed


def cleanup_worker_artifacts() -> dict[str, int]:
    return {
        "temporaryFiles": cleanup_stale_temporary_files(),
        "quarantineObjects": cleanup_orphan_quarantine_objects(),
    }
