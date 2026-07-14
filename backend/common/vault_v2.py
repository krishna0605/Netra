from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

from common.storage_provider import storage_provider


V2_VERSION = "netra-evidence-v2"


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str, expected_length: int | None = None) -> bytes:
    decoded = base64.urlsafe_b64decode(value.encode("ascii"))
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("Encrypted evidence manifest contains an invalid nonce.")
    return decoded


def _derive_kek(secret: str, key_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"netra-evidence-kek-v2",
        info=f"{V2_VERSION}:{key_id}".encode("utf-8"),
    ).derive(secret.encode("utf-8"))


def _chunk_aad(evidence_id: str, chunk_index: int, key_id: str) -> bytes:
    return _canonical({"chunkIndex": chunk_index, "evidenceId": evidence_id, "keyVersion": key_id, "version": V2_VERSION})


def _wrap_aad(evidence_id: str, key_id: str) -> bytes:
    return _canonical({"evidenceId": evidence_id, "keyVersion": key_id, "purpose": "data-key-wrap", "version": V2_VERSION})


def _safe_delete(bucket: str, object_name: str) -> None:
    try:
        storage_provider.delete_bucket_object(bucket, object_name)
    except Exception:
        pass


def encrypt_evidence_v2(source_path: str | Path, evidence_id: str, case_id: str) -> dict:
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on":
        raise RuntimeError("Chunked evidence encryption requires NETRA_EVIDENCE_ENCRYPTION=on.")
    source = Path(source_path)
    bucket = settings.SUPABASE_STORAGE_BUCKET_EVIDENCE
    key_id = settings.NETRA_EVIDENCE_KEY_ID
    chunk_size = settings.NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES
    object_prefix = f"v2/{evidence_id}"
    manifest_object = f"{object_prefix}/manifest.v2.json"
    expected_chunks = (source.stat().st_size + chunk_size - 1) // chunk_size

    # A retry starts from a known clean prefix so a worker crash cannot mix two
    # encryption attempts under one immutable evidence ID.
    for index in range(expected_chunks):
        _safe_delete(bucket, f"{object_prefix}/chunk-{index:08d}.bin")
    _safe_delete(bucket, manifest_object)

    data_key = os.urandom(32)
    data_cipher = AESGCM(data_key)
    wrap_nonce = os.urandom(12)
    wrapped_key = AESGCM(_derive_kek(settings.NETRA_EVIDENCE_KEY, key_id)).encrypt(
        wrap_nonce,
        data_key,
        _wrap_aad(evidence_id, key_id),
    )
    plaintext_digest = hashlib.sha256()
    ciphertext_digest = hashlib.sha256()
    plaintext_size = 0
    ciphertext_size = 0
    chunks: list[dict] = []
    uploaded_objects: list[str] = []
    settings.NETRA_TEMP_ROOT.mkdir(parents=True, exist_ok=True)

    try:
        with source.open("rb") as source_handle:
            index = 0
            while True:
                plaintext = source_handle.read(chunk_size)
                if not plaintext:
                    break
                nonce = os.urandom(12)
                aad = _chunk_aad(evidence_id, index, key_id)
                ciphertext = data_cipher.encrypt(nonce, plaintext, aad)
                object_name = f"{object_prefix}/chunk-{index:08d}.bin"
                with NamedTemporaryFile(delete=False, dir=settings.NETRA_TEMP_ROOT, suffix=".v2chunk") as temporary:
                    temporary_path = Path(temporary.name)
                    temporary.write(ciphertext)
                os.chmod(temporary_path, 0o600)
                try:
                    storage_provider.upload_bucket_object(bucket, object_name, temporary_path, upsert=False)
                finally:
                    temporary_path.unlink(missing_ok=True)
                uploaded_objects.append(object_name)
                plaintext_digest.update(plaintext)
                ciphertext_digest.update(ciphertext)
                plaintext_size += len(plaintext)
                ciphertext_size += len(ciphertext)
                chunks.append(
                    {
                        "index": index,
                        "objectName": object_name,
                        "nonce": _b64(nonce),
                        "aadSha256": hashlib.sha256(aad).hexdigest(),
                        "plaintextSize": len(plaintext),
                        "ciphertextSize": len(ciphertext),
                        "ciphertextSha256": hashlib.sha256(ciphertext).hexdigest(),
                    }
                )
                index += 1

        manifest = {
            "version": V2_VERSION,
            "evidenceId": evidence_id,
            "caseId": case_id,
            "keyVersion": key_id,
            "encryptionAlgorithm": "AES-256-GCM-chunked",
            "keyWrapAlgorithm": "AES-256-GCM-HKDF-SHA256",
            "chunkSizeBytes": chunk_size,
            "plaintextSizeBytes": plaintext_size,
            "ciphertextSizeBytes": ciphertext_size,
            "plaintextSha256": plaintext_digest.hexdigest(),
            "ciphertextSha256": ciphertext_digest.hexdigest(),
            "wrappedDataKey": {"nonce": _b64(wrap_nonce), "ciphertext": _b64(wrapped_key)},
            "chunks": chunks,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        manifest["manifestSha256"] = hashlib.sha256(_canonical(manifest)).hexdigest()
        with NamedTemporaryFile(delete=False, dir=settings.NETRA_TEMP_ROOT, suffix=".v2manifest") as temporary:
            manifest_path = Path(temporary.name)
            temporary.write(_canonical(manifest))
        os.chmod(manifest_path, 0o600)
        try:
            manifest_uri = storage_provider.upload_bucket_object(bucket, manifest_object, manifest_path, upsert=False)
        finally:
            manifest_path.unlink(missing_ok=True)
        uploaded_objects.append(manifest_object)
        return {
            "stored_path": manifest_uri,
            "size_bytes": plaintext_size,
            "sha256": manifest["plaintextSha256"],
            "plaintext_sha256": manifest["plaintextSha256"],
            "encrypted_sha256": manifest["ciphertextSha256"],
            "encryption_algorithm": "AES-256-GCM-chunked-v2",
            "key_id": key_id,
            "v2_manifest": manifest,
        }
    except Exception:
        for object_name in reversed(uploaded_objects):
            _safe_delete(bucket, object_name)
        raise


def _manifest_from_uri(manifest_uri: str | Path) -> tuple[str, dict]:
    raw = str(manifest_uri)
    if not raw.startswith("supabase://"):
        raise ValueError("V2 evidence manifest must be stored in Supabase Storage.")
    bucket, separator, object_name = raw.removeprefix("supabase://").partition("/")
    if not separator or not bucket or not object_name:
        raise ValueError("V2 evidence manifest URI is invalid.")
    manifest = json.loads(storage_provider.read_bucket_object(bucket, object_name).decode("utf-8"))
    expected_hash = manifest.pop("manifestSha256", "")
    calculated_hash = hashlib.sha256(_canonical(manifest)).hexdigest()
    if not expected_hash or expected_hash != calculated_hash:
        raise ValueError("V2 evidence manifest integrity verification failed.")
    manifest["manifestSha256"] = expected_hash
    if manifest.get("version") != V2_VERSION:
        raise ValueError("Unsupported evidence encryption manifest version.")
    return bucket, manifest


def _unwrap_data_key(manifest: dict) -> bytes:
    evidence_id = str(manifest["evidenceId"])
    key_id = str(manifest["keyVersion"])
    wrapped = manifest["wrappedDataKey"]
    nonce = _unb64(str(wrapped["nonce"]), 12)
    ciphertext = _unb64(str(wrapped["ciphertext"]))
    for secret in dict.fromkeys([settings.NETRA_EVIDENCE_KEY, *settings.NETRA_EVIDENCE_PREVIOUS_KEYS]):
        if not secret:
            continue
        try:
            return AESGCM(_derive_kek(secret, key_id)).decrypt(nonce, ciphertext, _wrap_aad(evidence_id, key_id))
        except Exception:
            continue
    raise ValueError("No configured evidence key can unwrap the V2 data key.")


def decrypt_evidence_v2(manifest_uri: str | Path, target_path: str | Path) -> Path:
    bucket, manifest = _manifest_from_uri(manifest_uri)
    data_cipher = AESGCM(_unwrap_data_key(manifest))
    evidence_id = str(manifest["evidenceId"])
    key_id = str(manifest["keyVersion"])
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    plaintext_digest = hashlib.sha256()
    plaintext_size = 0
    try:
        with target.open("wb") as target_handle:
            os.chmod(target, 0o600)
            for expected_index, chunk in enumerate(manifest.get("chunks") or []):
                if int(chunk.get("index", -1)) != expected_index:
                    raise ValueError("V2 evidence chunks are out of sequence.")
                ciphertext = storage_provider.read_bucket_object(bucket, str(chunk["objectName"]))
                if hashlib.sha256(ciphertext).hexdigest() != chunk.get("ciphertextSha256"):
                    raise ValueError("V2 evidence chunk integrity verification failed.")
                aad = _chunk_aad(evidence_id, expected_index, key_id)
                if hashlib.sha256(aad).hexdigest() != chunk.get("aadSha256"):
                    raise ValueError("V2 evidence chunk authentication context is invalid.")
                plaintext = data_cipher.decrypt(_unb64(str(chunk["nonce"]), 12), ciphertext, aad)
                if len(plaintext) != int(chunk.get("plaintextSize", -1)):
                    raise ValueError("V2 evidence chunk size verification failed.")
                target_handle.write(plaintext)
                plaintext_digest.update(plaintext)
                plaintext_size += len(plaintext)
        if plaintext_size != int(manifest.get("plaintextSizeBytes", -1)):
            raise ValueError("V2 evidence plaintext size verification failed.")
        if plaintext_digest.hexdigest() != manifest.get("plaintextSha256"):
            raise ValueError("V2 evidence plaintext hash verification failed.")
        return target
    except Exception:
        target.unlink(missing_ok=True)
        raise


def verify_evidence_v2(manifest_uri: str | Path) -> dict:
    bucket, manifest = _manifest_from_uri(manifest_uri)
    ciphertext_digest = hashlib.sha256()
    for expected_index, chunk in enumerate(manifest.get("chunks") or []):
        if int(chunk.get("index", -1)) != expected_index:
            return {"verified": False, "manifestVerified": True, "chunksVerified": False}
        ciphertext = storage_provider.read_bucket_object(bucket, str(chunk["objectName"]))
        if hashlib.sha256(ciphertext).hexdigest() != chunk.get("ciphertextSha256"):
            return {"verified": False, "manifestVerified": True, "chunksVerified": False}
        ciphertext_digest.update(ciphertext)
    chunks_verified = ciphertext_digest.hexdigest() == manifest.get("ciphertextSha256")
    return {
        "verified": chunks_verified,
        "manifestVerified": True,
        "chunksVerified": chunks_verified,
        "encryptedStorageHash": ciphertext_digest.hexdigest(),
        "plaintextIdentityHash": manifest.get("plaintextSha256", ""),
        "manifestHash": manifest.get("manifestSha256", ""),
    }
