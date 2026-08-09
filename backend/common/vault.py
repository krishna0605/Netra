from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from django.conf import settings

from common.hashing import sha256_text
from common.storage_provider import storage_provider
from common.vault_legacy import decrypt_legacy_file, legacy_fernet


PCAP_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}


def fernet():
    """Compatibility alias for legacy decrypt-only tests and migrations."""
    return legacy_fernet()


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
    raise RuntimeError("Legacy v1 encryption is disabled. Use encrypt_artifact_v2().")


def decrypt_file(source: str | Path, target: str | Path) -> None:
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if str(source).endswith("/manifest.v2.json"):
        from common.vault_v2 import decrypt_evidence_v2

        decrypt_evidence_v2(source, target_path)
        return
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on":
        with storage_provider.open_encrypted(source, "rb") as handle, target_path.open("wb") as output:
            os.chmod(target_path, 0o600)
            shutil.copyfileobj(handle, output, length=1024 * 1024)
        return
    decrypt_legacy_file(source, target_path)


def read_encrypted_or_plain(source: str | Path) -> bytes:
    """Read a deliberately small artifact, rejecting larger payloads before buffering."""

    maximum = settings.NETRA_MAX_INMEMORY_ARTIFACT_BYTES
    encrypted = settings.NETRA_EVIDENCE_ENCRYPTION == "on" and (
        str(source).endswith(".enc") or str(source).endswith("/manifest.v2.json")
    )
    if encrypted:
        temporary = Path(temporary_decrypted_copy(source))
        try:
            if temporary.stat().st_size > maximum:
                raise OverflowError("Artifact exceeds NETRA_MAX_INMEMORY_ARTIFACT_BYTES.")
            with temporary.open("rb") as handle:
                return handle.read(maximum + 1)
        finally:
            temporary.unlink(missing_ok=True)
    stat = storage_provider.stat(source)
    if stat.size_bytes > maximum:
        raise OverflowError("Artifact exceeds NETRA_MAX_INMEMORY_ARTIFACT_BYTES.")
    with storage_provider.open_encrypted(source, "rb") as handle:
        content = handle.read(maximum + 1)
    if len(content) > maximum:
        raise OverflowError("Artifact exceeds NETRA_MAX_INMEMORY_ARTIFACT_BYTES.")
    return content


def temporary_decrypted_copy(encrypted_path: str | Path) -> str:
    suffix = ".pcap"
    with NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        temp_path = tmp.name
    decrypt_file(encrypted_path, temp_path)
    return temp_path


class CleanupArtifactFile:
    """File wrapper that removes decrypted temporary data when the response closes."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._handle = self.path.open("rb")

    def __getattr__(self, name):
        return getattr(self._handle, name)

    def close(self) -> None:
        try:
            self._handle.close()
        finally:
            self.path.unlink(missing_ok=True)


def open_decrypted_artifact(source: str | Path) -> CleanupArtifactFile:
    return CleanupArtifactFile(temporary_decrypted_copy(source))


def build_manifest_payload(saved: dict, evidence_id: str, case_id: str) -> dict:
    encryption_algorithm = str(saved.get("encryption_algorithm") or "").strip()
    if settings.NETRA_EVIDENCE_ENCRYPTION == "on" and not encryption_algorithm:
        raise ValueError("Encrypted artifacts must declare their versioned encryption algorithm.")
    payload = {
        "id": f"manifest-{evidence_id}",
        "caseId": case_id,
        "evidenceId": evidence_id,
        "originalFilename": saved["filename"],
        "storageUri": saved["stored_path"],
        "sizeBytes": saved["size_bytes"],
        "plaintextSha256": saved["plaintext_sha256"],
        "encryptedSha256": saved["encrypted_sha256"],
        "encryptionAlgorithm": encryption_algorithm or "none",
        "keyId": saved.get("key_id") or settings.NETRA_EVIDENCE_KEY_ID,
    }
    if saved.get("normalization"):
        payload["normalization"] = saved["normalization"]
    payload["manifestHash"] = saved.get("manifest_hash") or sha256_text(json.dumps(payload, sort_keys=True))
    return payload


def save_encrypted_upload(*_args, **_kwargs) -> dict:
    raise RuntimeError("Legacy v1 upload encryption is disabled. Use the v2 artifact writer.")
