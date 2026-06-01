from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO

from cryptography.fernet import Fernet
from django.conf import settings

from common.hashing import sha256_file, sha256_text
from common.storage_provider import resolve_storage_path


PCAP_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


def fernet() -> Fernet:
    raw = settings.NETRA_EVIDENCE_KEY.encode("utf-8")
    key = base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])
    return Fernet(key)


def validate_pcap_upload(upload) -> None:
    safe_name = Path(upload.name).name
    if Path(safe_name).suffix.lower() not in PCAP_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng files are accepted.")
    max_bytes = settings.NETRA_MAX_UPLOAD_MB * 1024 * 1024
    if upload.size and upload.size > max_bytes:
        raise OverflowError(f"Upload exceeds NETRA_MAX_UPLOAD_MB={settings.NETRA_MAX_UPLOAD_MB}.")
    position = upload.tell() if hasattr(upload, "tell") else None
    head = upload.read(4)
    if position is not None:
        upload.seek(position)
    if head not in PCAP_MAGIC:
        raise ValueError("File does not look like a valid PCAP/PCAPNG capture.")


def encrypt_file(source: str | Path, target: str | Path) -> None:
    source_path = Path(source)
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on":
        shutil.copyfile(source_path, target_path)
        return
    target_path.write_bytes(fernet().encrypt(source_path.read_bytes()))


def decrypt_file(source: str | Path, target: str | Path) -> None:
    source_path = resolve_storage_path(source)
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on":
        shutil.copyfile(source_path, target_path)
        return
    target_path.write_bytes(fernet().decrypt(source_path.read_bytes()))


def read_encrypted_or_plain(source: str | Path) -> bytes:
    source_path = resolve_storage_path(source)
    content = source_path.read_bytes()
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on" or source_path.suffix != ".enc":
        return content
    return fernet().decrypt(content)


def temporary_decrypted_copy(encrypted_path: str | Path) -> str:
    suffix = ".pcap"
    with NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        temp_path = tmp.name
    decrypt_file(encrypted_path, temp_path)
    return temp_path


def build_manifest_payload(saved: dict, evidence_id: str, case_id: str) -> dict:
    payload = {
        "id": f"manifest-{evidence_id}",
        "caseId": case_id,
        "evidenceId": evidence_id,
        "originalFilename": saved["filename"],
        "storageUri": saved["stored_path"],
        "sizeBytes": saved["size_bytes"],
        "plaintextSha256": saved["plaintext_sha256"],
        "encryptedSha256": saved["encrypted_sha256"],
        "encryptionAlgorithm": "Fernet-AES128-CBC-HMAC" if settings.NETRA_EVIDENCE_ENCRYPTION == "on" else "none",
        "keyId": settings.NETRA_EVIDENCE_KEY_ID,
    }
    payload["manifestHash"] = sha256_text(json.dumps(payload, sort_keys=True))
    return payload


def save_encrypted_upload(upload: BinaryIO, folder: Path, stored_name: str) -> dict:
    validate_pcap_upload(upload)
    folder.mkdir(parents=True, exist_ok=True)
    plaintext_path = folder / f"{stored_name}.work"
    encrypted_path = folder / f"{stored_name}.enc"
    with plaintext_path.open("wb") as handle:
        for chunk in upload.chunks():
            handle.write(chunk)
    plaintext_sha = sha256_file(plaintext_path)
    encrypt_file(plaintext_path, encrypted_path)
    encrypted_sha = sha256_file(encrypted_path)
    return {
        "analysis_path": str(plaintext_path),
        "stored_path": str(encrypted_path),
        "size_bytes": plaintext_path.stat().st_size,
        "sha256": plaintext_sha,
        "plaintext_sha256": plaintext_sha,
        "encrypted_sha256": encrypted_sha,
    }
