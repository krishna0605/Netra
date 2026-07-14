from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO

from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings

from common.hashing import sha256_file, sha256_text
from common.storage_provider import storage_provider


PCAP_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


def _fernet_for_secret(secret: str) -> Fernet:
    raw = secret.encode("utf-8")
    key = base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])
    return Fernet(key)


def fernet() -> MultiFernet:
    # Encrypt with the active key and retain decrypt-only access to prior keys.
    secrets = [settings.NETRA_EVIDENCE_KEY, *settings.NETRA_EVIDENCE_PREVIOUS_KEYS]
    return MultiFernet([_fernet_for_secret(secret) for secret in dict.fromkeys(secrets) if secret])


def validate_pcap_upload(upload) -> None:
    safe_name = Path(upload.name).name
    max_bytes = settings.NETRA_MAX_UPLOAD_MB * 1024 * 1024
    if upload.size and upload.size > max_bytes:
        raise OverflowError(f"Upload exceeds NETRA_MAX_UPLOAD_MB={settings.NETRA_MAX_UPLOAD_MB}.")
    position = upload.tell() if hasattr(upload, "tell") else None
    head = upload.read(4)
    if position is not None:
        upload.seek(position)
    if head in PCAP_MAGIC:
        return
    if Path(safe_name).suffix.lower() not in PCAP_EXTENSIONS:
        raise ValueError("Only valid PCAP/PCAPNG capture files are accepted for PCAP analysis.")
    else:
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
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on":
        with storage_provider.open_encrypted(source, "rb") as handle:
            target_path.write_bytes(handle.read())
        return
    with storage_provider.open_encrypted(source, "rb") as handle:
        target_path.write_bytes(fernet().decrypt(handle.read()))


def read_encrypted_or_plain(source: str | Path) -> bytes:
    with storage_provider.open_encrypted(source, "rb") as handle:
        content = handle.read()
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on" or not str(source).endswith(".enc"):
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
    if saved.get("normalization"):
        payload["normalization"] = saved["normalization"]
    payload["manifestHash"] = sha256_text(json.dumps(payload, sort_keys=True))
    return payload


def save_encrypted_upload(upload: BinaryIO, folder: Path, stored_name: str, *, validate_pcap: bool = True) -> dict:
    if validate_pcap:
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
