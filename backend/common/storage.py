import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from django.conf import settings

from common.safe_paths import resolve_artifact_paths
from common.vault import validate_pcap_upload
from common.vault_v2 import ArtifactCryptoContext, encrypt_artifact_v2


STORAGE_FOLDERS = {
    "pcap": "pcaps",
    "capture_chunk": "capture_chunks",
    "report": "reports",
    "export": "exports",
    "log": "logs",
    "structured": "structured",
    "filtered_pcap": "filtered_pcaps",
}

ARTIFACT_EXTENSIONS = {
    "report": frozenset({".html", ".pdf"}),
    "export": frozenset({".csv", ".json", ".cef"}),
}

ARTIFACT_TYPES = {
    "pcap": "evidence",
    "capture_chunk": "capture-chunk",
    "report": "report",
    "export": "export",
    "log": "zeek-log",
    "structured": "structured-evidence",
    "filtered_pcap": "filtered-capture",
}


def _bucket_for_folder(folder_key: str) -> str:
    return {
        "pcap": settings.SUPABASE_STORAGE_BUCKET_EVIDENCE,
        "capture_chunk": settings.SUPABASE_STORAGE_BUCKET_CAPTURE_CHUNKS,
        "report": settings.SUPABASE_STORAGE_BUCKET_REPORTS,
        "export": settings.SUPABASE_STORAGE_BUCKET_EXPORTS,
        "log": settings.SUPABASE_STORAGE_BUCKET_ZEEK_LOGS,
        "structured": settings.SUPABASE_STORAGE_BUCKET_EVIDENCE,
        "filtered_pcap": settings.SUPABASE_STORAGE_BUCKET_EXPORTS,
    }[folder_key]


def _crypto_context(folder_key: str, artifact_id: str, case_id: str, filename: str) -> ArtifactCryptoContext:
    return ArtifactCryptoContext(
        artifact_id=artifact_id,
        artifact_type=ARTIFACT_TYPES[folder_key],
        case_id=case_id,
        original_filename=filename,
        target_bucket=_bucket_for_folder(folder_key),
    )


def ensure_storage_tree() -> None:
    for folder in STORAGE_FOLDERS.values():
        (settings.NETRA_STORAGE_ROOT / folder).mkdir(parents=True, exist_ok=True)


def _save_uploaded_artifact_v2(upload, folder_key: str, artifact_id: str, case_id: str, *, validate_pcap: bool) -> dict:
    """Persist one upload as bounded AES-GCM chunks and retain plaintext only for analysis."""
    if validate_pcap:
        validate_pcap_upload(upload)
    max_bytes = settings.NETRA_MAX_UPLOAD_MB * 1024 * 1024
    safe_name = Path(upload.name).name
    settings.NETRA_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    plaintext_path: Path | None = None
    try:
        with NamedTemporaryFile(
            delete=False,
            dir=settings.NETRA_TEMP_ROOT,
            suffix=Path(safe_name).suffix or ".evidence",
        ) as temporary:
            plaintext_path = Path(temporary.name)
            written = 0
            for chunk in upload.chunks():
                written += len(chunk)
                if written > max_bytes:
                    raise OverflowError(f"Upload exceeds NETRA_MAX_UPLOAD_MB={settings.NETRA_MAX_UPLOAD_MB}.")
                temporary.write(chunk)
        os.chmod(plaintext_path, 0o600)
        saved = encrypt_artifact_v2(plaintext_path, _crypto_context(folder_key, artifact_id, case_id, safe_name))
    except Exception:
        if plaintext_path is not None:
            plaintext_path.unlink(missing_ok=True)
        raise
    return {
        "filename": safe_name,
        "analysis_path": str(plaintext_path),
        **saved,
    }


def save_uploaded_file(
    upload,
    folder_key: str = "pcap",
    *,
    evidence_id: str | None = None,
    case_id: str | None = None,
) -> dict:
    ensure_storage_tree()
    max_bytes = settings.NETRA_MAX_UPLOAD_MB * 1024 * 1024
    if upload.size and upload.size > max_bytes:
        raise OverflowError(f"Upload exceeds NETRA_MAX_UPLOAD_MB={settings.NETRA_MAX_UPLOAD_MB}.")
    if folder_key not in STORAGE_FOLDERS:
        raise ValueError("Unknown durable artifact folder.")
    artifact_id = evidence_id or f"artifact-{uuid4().hex}"
    case_id = case_id or "local-artifact"
    if getattr(settings, "NETRA_DEPLOYMENT_ENV", "local") == "production" and case_id == "local-artifact":
        raise RuntimeError("Production artifact writes require an explicit case ID.")
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on":
        raise RuntimeError("Durable artifact writes require v2 encryption.")
    return _save_uploaded_artifact_v2(
        upload,
        folder_key,
        artifact_id,
        case_id,
        validate_pcap=folder_key not in {"log", "structured"},
    )


def write_text_artifact(content: str, folder_key: str, filename: str, *, case_id: str = "local-artifact", artifact_id: str | None = None) -> dict:
    ensure_storage_tree()
    if folder_key not in ARTIFACT_EXTENSIONS:
        raise ValueError("Text artifacts may only be written to an approved artifact folder.")
    paths = resolve_artifact_paths(
        settings.NETRA_STORAGE_ROOT,
        STORAGE_FOLDERS[folder_key],
        filename,
        allowed_extensions=ARTIFACT_EXTENSIONS[folder_key],
    )
    if getattr(settings, "NETRA_DEPLOYMENT_ENV", "local") == "production" and case_id == "local-artifact":
        raise RuntimeError("Production artifact writes require an explicit case ID.")
    plain_target: Path | None = None
    try:
        with NamedTemporaryFile(delete=False, dir=paths.folder, suffix=".tmp") as temporary:
            plain_target = Path(temporary.name)
            temporary.write(content.encode("utf-8"))
        os.chmod(plain_target, 0o600)
        saved = encrypt_artifact_v2(
            plain_target,
            _crypto_context(folder_key, artifact_id or Path(filename).stem, case_id, filename),
        )
    finally:
        if plain_target is not None:
            plain_target.unlink(missing_ok=True)
    return {
        "filename": filename,
        **saved,
    }


def write_binary_artifact(content: bytes, folder_key: str, filename: str, *, case_id: str = "local-artifact", artifact_id: str | None = None) -> dict:
    ensure_storage_tree()
    if folder_key not in ARTIFACT_EXTENSIONS:
        raise ValueError("Binary artifacts may only be written to an approved artifact folder.")
    paths = resolve_artifact_paths(
        settings.NETRA_STORAGE_ROOT,
        STORAGE_FOLDERS[folder_key],
        filename,
        allowed_extensions=ARTIFACT_EXTENSIONS[folder_key],
    )
    if getattr(settings, "NETRA_DEPLOYMENT_ENV", "local") == "production" and case_id == "local-artifact":
        raise RuntimeError("Production artifact writes require an explicit case ID.")
    plain_target: Path | None = None
    try:
        with NamedTemporaryFile(delete=False, dir=paths.folder, suffix=".tmp") as temporary:
            plain_target = Path(temporary.name)
            temporary.write(content)
        os.chmod(plain_target, 0o600)
        saved = encrypt_artifact_v2(
            plain_target,
            _crypto_context(folder_key, artifact_id or Path(filename).stem, case_id, filename),
        )
    finally:
        if plain_target is not None:
            plain_target.unlink(missing_ok=True)
    return {
        "filename": filename,
        **saved,
    }
