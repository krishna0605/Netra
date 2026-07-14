import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from django.conf import settings

from common.hashing import sha256_file
from common.storage_provider import storage_uri
from common.vault import encrypt_file, save_encrypted_upload, validate_pcap_upload
from common.vault_v2 import encrypt_evidence_v2


STORAGE_FOLDERS = {
    "pcap": "pcaps",
    "capture_chunk": "capture_chunks",
    "report": "reports",
    "export": "exports",
    "log": "logs",
    "structured": "structured",
    "filtered_pcap": "filtered_pcaps",
}


def ensure_storage_tree() -> None:
    for folder in STORAGE_FOLDERS.values():
        (settings.NETRA_STORAGE_ROOT / folder).mkdir(parents=True, exist_ok=True)


def _save_uploaded_evidence_v2(upload, evidence_id: str, case_id: str, *, validate_pcap: bool) -> dict:
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
        saved = encrypt_evidence_v2(plaintext_path, evidence_id, case_id)
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
    if (
        evidence_id
        and case_id
        and folder_key in {"pcap", "structured"}
        and settings.NETRA_STORAGE_PROVIDER == "supabase"
        and settings.NETRA_EVIDENCE_ENCRYPTION == "on"
    ):
        return _save_uploaded_evidence_v2(
            upload,
            evidence_id,
            case_id,
            validate_pcap=folder_key == "pcap",
        )
    folder = settings.NETRA_STORAGE_ROOT / STORAGE_FOLDERS[folder_key]
    safe_name = Path(upload.name).name
    stored_name = f"{uuid4().hex}-{safe_name}"
    saved = save_encrypted_upload(upload, folder, stored_name, validate_pcap=folder_key not in {"log", "structured"})
    saved["stored_path"] = storage_uri(saved["stored_path"])
    return {
        "filename": safe_name,
        **saved,
    }


def write_text_artifact(content: str, folder_key: str, filename: str) -> dict:
    ensure_storage_tree()
    folder = settings.NETRA_STORAGE_ROOT / STORAGE_FOLDERS[folder_key]
    plain_target = folder / filename
    encrypted_target = folder / f"{filename}.enc"
    plain_target.write_text(content, encoding="utf-8")
    plaintext_sha = sha256_file(plain_target)
    encrypt_file(plain_target, encrypted_target)
    plain_target.unlink(missing_ok=True)
    encrypted_size = encrypted_target.stat().st_size
    encrypted_sha = sha256_file(encrypted_target)
    return {
        "filename": filename,
        "stored_path": storage_uri(encrypted_target),
        "size_bytes": encrypted_size,
        "sha256": plaintext_sha,
        "encrypted_sha256": encrypted_sha,
    }


def write_binary_artifact(content: bytes, folder_key: str, filename: str) -> dict:
    ensure_storage_tree()
    folder = settings.NETRA_STORAGE_ROOT / STORAGE_FOLDERS[folder_key]
    plain_target = folder / filename
    encrypted_target = folder / f"{filename}.enc"
    plain_target.write_bytes(content)
    plaintext_sha = sha256_file(plain_target)
    encrypt_file(plain_target, encrypted_target)
    plain_target.unlink(missing_ok=True)
    encrypted_size = encrypted_target.stat().st_size
    encrypted_sha = sha256_file(encrypted_target)
    return {
        "filename": filename,
        "stored_path": storage_uri(encrypted_target),
        "size_bytes": encrypted_size,
        "sha256": plaintext_sha,
        "encrypted_sha256": encrypted_sha,
    }
