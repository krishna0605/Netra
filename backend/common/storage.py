from pathlib import Path
from uuid import uuid4

from django.conf import settings

from common.hashing import sha256_file
from common.storage_provider import storage_uri
from common.vault import encrypt_file, save_encrypted_upload


STORAGE_FOLDERS = {
    "pcap": "pcaps",
    "capture_chunk": "capture_chunks",
    "report": "reports",
    "export": "exports",
    "log": "logs",
    "filtered_pcap": "filtered_pcaps",
}


def ensure_storage_tree() -> None:
    for folder in STORAGE_FOLDERS.values():
        (settings.NETRA_STORAGE_ROOT / folder).mkdir(parents=True, exist_ok=True)


def save_uploaded_file(upload, folder_key: str = "pcap") -> dict:
    ensure_storage_tree()
    folder = settings.NETRA_STORAGE_ROOT / STORAGE_FOLDERS[folder_key]
    safe_name = Path(upload.name).name
    stored_name = f"{uuid4().hex}-{safe_name}"
    saved = save_encrypted_upload(upload, folder, stored_name)
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
