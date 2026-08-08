from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

from common.storage_provider import storage_provider


LEGACY_V2_VERSION = "netra-evidence-v2"
V2_VERSION = "netra-artifact-v2.1"
ALLOWED_ARTIFACT_TYPES = {
    "evidence",
    "capture-chunk",
    "analysis-chunk",
    "report",
    "export",
    "zeek-log",
    "integration-artifact",
    "structured-evidence",
    "filtered-capture",
}


@dataclass(frozen=True)
class ArtifactCryptoContext:
    artifact_id: str
    artifact_type: str
    case_id: str
    original_filename: str
    target_bucket: str


@dataclass(frozen=True)
class EncryptedArtifact:
    manifest_uri: str
    plaintext_size: int
    ciphertext_size: int
    plaintext_sha256: str
    ciphertext_sha256: str
    manifest_sha256: str
    key_id: str
    encryption_algorithm: str
    generation_id: str


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str, expected_length: int | None = None) -> bytes:
    decoded = base64.urlsafe_b64decode(value.encode("ascii"))
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("Encrypted artifact manifest contains invalid encoded key material.")
    return decoded


def _validate_context(context: ArtifactCryptoContext) -> None:
    if context.artifact_type not in ALLOWED_ARTIFACT_TYPES:
        raise ValueError("Unsupported encrypted artifact type.")
    for value in (context.artifact_id, context.case_id, context.target_bucket):
        if not value or any(character in value for character in {"/", "\\", "\x00"}):
            raise ValueError("Encrypted artifact context contains an invalid identifier.")


def _derive(secret: str, *, salt: bytes, context: ArtifactCryptoContext, key_id: str, purpose: str) -> bytes:
    info = _canonical(
        {
            "artifactId": context.artifact_id,
            "artifactType": context.artifact_type,
            "keyId": key_id,
            "purpose": purpose,
            "version": V2_VERSION,
        }
    )
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(secret.encode("utf-8"))


def _legacy_derive(secret: str, key_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"netra-evidence-kek-v2",
        info=f"{LEGACY_V2_VERSION}:{key_id}".encode("utf-8"),
    ).derive(secret.encode("utf-8"))


def _aad(context: ArtifactCryptoContext, index: int, key_id: str, generation_id: str) -> bytes:
    return _canonical(
        {
            "artifactId": context.artifact_id,
            "artifactType": context.artifact_type,
            "caseId": context.case_id,
            "chunkIndex": index,
            "generationId": generation_id,
            "keyId": key_id,
            "version": V2_VERSION,
        }
    )


def _wrap_aad(context: ArtifactCryptoContext, key_id: str, generation_id: str) -> bytes:
    return _canonical(
        {
            "artifactId": context.artifact_id,
            "artifactType": context.artifact_type,
            "caseId": context.case_id,
            "generationId": generation_id,
            "keyId": key_id,
            "purpose": "data-key-wrap",
            "version": V2_VERSION,
        }
    )


def _legacy_aad(evidence_id: str, index: int, key_id: str) -> bytes:
    return _canonical({"chunkIndex": index, "evidenceId": evidence_id, "keyVersion": key_id, "version": LEGACY_V2_VERSION})


def _legacy_wrap_aad(evidence_id: str, key_id: str) -> bytes:
    return _canonical({"evidenceId": evidence_id, "keyVersion": key_id, "purpose": "data-key-wrap", "version": LEGACY_V2_VERSION})


def _secrets() -> list[str]:
    return [item for item in dict.fromkeys([settings.NETRA_EVIDENCE_KEY, *settings.NETRA_EVIDENCE_PREVIOUS_KEYS]) if item]


def _saved(encrypted: EncryptedArtifact, manifest: dict) -> dict:
    return {
        "stored_path": encrypted.manifest_uri,
        "size_bytes": encrypted.plaintext_size,
        "sha256": encrypted.plaintext_sha256,
        "plaintext_sha256": encrypted.plaintext_sha256,
        "encrypted_sha256": encrypted.ciphertext_sha256,
        "encryption_algorithm": encrypted.encryption_algorithm,
        "key_id": encrypted.key_id,
        "manifest_hash": encrypted.manifest_sha256,
        "generation_id": encrypted.generation_id,
        "v2_manifest": manifest,
    }


def encrypt_artifact_v2(
    source_path: str | Path,
    context: ArtifactCryptoContext,
    *,
    generation_id: str | None = None,
) -> dict:
    if settings.NETRA_EVIDENCE_ENCRYPTION != "on":
        raise RuntimeError("V2 artifact encryption requires NETRA_EVIDENCE_ENCRYPTION=on.")
    _validate_context(context)
    source = Path(source_path)
    key_id = settings.NETRA_EVIDENCE_KEY_ID
    chunk_size = settings.NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES
    if not 1024 * 1024 <= chunk_size <= 16 * 1024 * 1024:
        raise RuntimeError("NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES must be between 1 MiB and 16 MiB.")
    generation_id = generation_id or uuid4().hex
    prefix = f"v2/{context.artifact_type}/{context.artifact_id}/{generation_id}"
    salt = os.urandom(32)
    data_key = os.urandom(32)
    wrap_key = _derive(settings.NETRA_EVIDENCE_KEY, salt=salt, context=context, key_id=key_id, purpose="data-key-wrap")
    auth_key = _derive(settings.NETRA_EVIDENCE_KEY, salt=salt, context=context, key_id=key_id, purpose="manifest-auth")
    wrap_nonce = os.urandom(12)
    wrapped_key = AESGCM(wrap_key).encrypt(wrap_nonce, data_key, _wrap_aad(context, key_id, generation_id))
    cipher = AESGCM(data_key)
    plain_hash = hashlib.sha256()
    encrypted_hash = hashlib.sha256()
    plain_size = 0
    encrypted_size = 0
    chunks: list[dict] = []
    uploaded: list[str] = []
    settings.NETRA_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as handle:
            index = 0
            while True:
                plaintext = handle.read(chunk_size)
                if not plaintext:
                    break
                nonce = os.urandom(12)
                aad = _aad(context, index, key_id, generation_id)
                ciphertext = cipher.encrypt(nonce, plaintext, aad)
                object_name = f"{prefix}/chunk-{index:08d}.bin"
                with NamedTemporaryFile(delete=False, dir=settings.NETRA_TEMP_ROOT, suffix=".v2chunk") as temporary:
                    temporary_path = Path(temporary.name)
                    temporary.write(ciphertext)
                os.chmod(temporary_path, 0o600)
                try:
                    storage_provider.upload_bucket_object(context.target_bucket, object_name, temporary_path, upsert=False)
                finally:
                    temporary_path.unlink(missing_ok=True)
                uploaded.append(object_name)
                plain_hash.update(plaintext)
                encrypted_hash.update(ciphertext)
                plain_size += len(plaintext)
                encrypted_size += len(ciphertext)
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
        core = {
            "version": V2_VERSION,
            "artifactId": context.artifact_id,
            "artifactType": context.artifact_type,
            "caseId": context.case_id,
            "generationId": generation_id,
            "originalFilename": Path(context.original_filename).name,
            "keyId": key_id,
            "kdf": {"algorithm": "HKDF-SHA256", "salt": _b64(salt)},
            "cipher": {"algorithm": "AES-256-GCM", "keyWrapAlgorithm": "AES-256-GCM-HKDF-SHA256"},
            "chunkSizeBytes": chunk_size,
            "plaintextSizeBytes": plain_size,
            "ciphertextSizeBytes": encrypted_size,
            "plaintextSha256": plain_hash.hexdigest(),
            "ciphertextSha256": encrypted_hash.hexdigest(),
            "wrappedDataKey": {"nonce": _b64(wrap_nonce), "ciphertext": _b64(wrapped_key)},
            "chunks": chunks,
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }
        manifest_sha = hashlib.sha256(_canonical(core)).hexdigest()
        authenticated = {**core, "manifestSha256": manifest_sha}
        manifest = {**authenticated, "manifestHmacSha256": hmac.new(auth_key, _canonical(authenticated), hashlib.sha256).hexdigest()}
        manifest_name = f"{prefix}/manifest.v2.json"
        with NamedTemporaryFile(delete=False, dir=settings.NETRA_TEMP_ROOT, suffix=".v2manifest") as temporary:
            manifest_path = Path(temporary.name)
            temporary.write(_canonical(manifest))
        os.chmod(manifest_path, 0o600)
        try:
            manifest_uri = storage_provider.upload_bucket_object(context.target_bucket, manifest_name, manifest_path, upsert=False)
        finally:
            manifest_path.unlink(missing_ok=True)
        uploaded.append(manifest_name)
        return _saved(
            EncryptedArtifact(
                manifest_uri=manifest_uri,
                plaintext_size=plain_size,
                ciphertext_size=encrypted_size,
                plaintext_sha256=core["plaintextSha256"],
                ciphertext_sha256=core["ciphertextSha256"],
                manifest_sha256=manifest_sha,
                key_id=key_id,
                encryption_algorithm="AES-256-GCM-chunked-v2.1",
                generation_id=generation_id,
            ),
            manifest,
        )
    except Exception:
        for object_name in reversed(uploaded):
            try:
                storage_provider.delete_bucket_object(context.target_bucket, object_name)
            except Exception:
                pass
        raise


def encrypt_evidence_v2(source_path: str | Path, evidence_id: str, case_id: str) -> dict:
    return encrypt_artifact_v2(
        source_path,
        ArtifactCryptoContext(
            artifact_id=evidence_id,
            artifact_type="evidence",
            case_id=case_id,
            original_filename=Path(source_path).name,
            target_bucket=settings.SUPABASE_STORAGE_BUCKET_EVIDENCE,
        ),
    )


def _load_manifest(uri: str | Path) -> tuple[str, dict]:
    bucket, object_name = storage_provider.parse_object_uri(uri)
    return bucket, json.loads(storage_provider.read_bucket_object(bucket, object_name).decode("utf-8"))


def _verify_new_manifest(manifest: dict) -> tuple[ArtifactCryptoContext, str]:
    received = dict(manifest)
    received_hmac = str(received.pop("manifestHmacSha256", ""))
    received_sha = str(received.pop("manifestSha256", ""))
    calculated_sha = hashlib.sha256(_canonical(received)).hexdigest()
    if not hmac.compare_digest(received_sha, calculated_sha):
        raise ValueError("V2 artifact manifest digest verification failed.")
    authenticated = {**received, "manifestSha256": received_sha}
    context = ArtifactCryptoContext(
        artifact_id=str(manifest["artifactId"]),
        artifact_type=str(manifest["artifactType"]),
        case_id=str(manifest["caseId"]),
        original_filename=str(manifest.get("originalFilename") or "artifact"),
        target_bucket="unused",
    )
    _validate_context(context)
    salt = _unb64(str(manifest["kdf"]["salt"]), 32)
    key_id = str(manifest["keyId"])
    for secret in _secrets():
        key = _derive(secret, salt=salt, context=context, key_id=key_id, purpose="manifest-auth")
        expected = hmac.new(key, _canonical(authenticated), hashlib.sha256).hexdigest()
        if hmac.compare_digest(received_hmac, expected):
            return context, secret
    raise ValueError("V2 artifact manifest authentication failed.")


def _new_data_key(manifest: dict, context: ArtifactCryptoContext, secret: str) -> bytes:
    salt = _unb64(str(manifest["kdf"]["salt"]), 32)
    key_id = str(manifest["keyId"])
    generation_id = str(manifest["generationId"])
    key = _derive(secret, salt=salt, context=context, key_id=key_id, purpose="data-key-wrap")
    wrapped = manifest["wrappedDataKey"]
    return AESGCM(key).decrypt(
        _unb64(str(wrapped["nonce"]), 12),
        _unb64(str(wrapped["ciphertext"])),
        _wrap_aad(context, key_id, generation_id),
    )


def _legacy_data_key(manifest: dict) -> bytes:
    evidence_id = str(manifest["evidenceId"])
    key_id = str(manifest["keyVersion"])
    wrapped = manifest["wrappedDataKey"]
    for secret in _secrets():
        try:
            return AESGCM(_legacy_derive(secret, key_id)).decrypt(
                _unb64(str(wrapped["nonce"]), 12),
                _unb64(str(wrapped["ciphertext"])),
                _legacy_wrap_aad(evidence_id, key_id),
            )
        except Exception:
            continue
    raise ValueError("No configured key can unwrap the legacy v2 data key.")


def _prepare_reader(manifest: dict):
    if manifest.get("version") == V2_VERSION:
        context, secret = _verify_new_manifest(manifest)
        key_id = str(manifest["keyId"])
        generation_id = str(manifest["generationId"])
        return _new_data_key(manifest, context, secret), lambda index: _aad(context, index, key_id, generation_id)
    if manifest.get("version") == LEGACY_V2_VERSION:
        received_hash = str(manifest.pop("manifestSha256", ""))
        calculated = hashlib.sha256(_canonical(manifest)).hexdigest()
        if not hmac.compare_digest(received_hash, calculated):
            raise ValueError("Legacy v2 evidence manifest integrity verification failed.")
        manifest["manifestSha256"] = received_hash
        evidence_id = str(manifest["evidenceId"])
        key_id = str(manifest["keyVersion"])
        return _legacy_data_key(manifest), lambda index: _legacy_aad(evidence_id, index, key_id)
    raise ValueError("Unsupported encrypted artifact manifest version.")


def decrypt_evidence_v2(manifest_uri: str | Path, target_path: str | Path) -> Path:
    bucket, manifest = _load_manifest(manifest_uri)
    data_key, aad_for = _prepare_reader(manifest)
    cipher = AESGCM(data_key)
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    try:
        with target.open("wb") as output:
            os.chmod(target, 0o600)
            for expected_index, chunk in enumerate(manifest.get("chunks") or []):
                if int(chunk.get("index", -1)) != expected_index:
                    raise ValueError("V2 artifact chunks are out of sequence.")
                ciphertext = storage_provider.read_bucket_object(
                    bucket, str(chunk["objectName"]),
                    expected_sha256=str(chunk.get("ciphertextSha256") or ""),
                    expected_size=int(chunk.get("ciphertextSize", -1)),
                )
                if not hmac.compare_digest(hashlib.sha256(ciphertext).hexdigest(), str(chunk.get("ciphertextSha256"))):
                    raise ValueError("V2 artifact chunk digest verification failed.")
                aad = aad_for(expected_index)
                if not hmac.compare_digest(hashlib.sha256(aad).hexdigest(), str(chunk.get("aadSha256"))):
                    raise ValueError("V2 artifact chunk authentication context is invalid.")
                plaintext = cipher.decrypt(_unb64(str(chunk["nonce"]), 12), ciphertext, aad)
                if len(plaintext) != int(chunk.get("plaintextSize", -1)):
                    raise ValueError("V2 artifact plaintext chunk size verification failed.")
                output.write(plaintext)
                digest.update(plaintext)
                size += len(plaintext)
        if size != int(manifest.get("plaintextSizeBytes", -1)):
            raise ValueError("V2 artifact plaintext size verification failed.")
        if not hmac.compare_digest(digest.hexdigest(), str(manifest.get("plaintextSha256"))):
            raise ValueError("V2 artifact plaintext digest verification failed.")
        return target
    except Exception:
        target.unlink(missing_ok=True)
        raise


def verify_evidence_v2(manifest_uri: str | Path) -> dict:
    bucket, manifest = _load_manifest(manifest_uri)
    _prepare_reader(manifest)
    digest = hashlib.sha256()
    for expected_index, chunk in enumerate(manifest.get("chunks") or []):
        if int(chunk.get("index", -1)) != expected_index:
            return {"verified": False, "manifestVerified": True, "chunksVerified": False}
        ciphertext = storage_provider.read_bucket_object(
            bucket, str(chunk["objectName"]),
            expected_sha256=str(chunk.get("ciphertextSha256") or ""),
            expected_size=int(chunk.get("ciphertextSize", -1)),
        )
        if not hmac.compare_digest(hashlib.sha256(ciphertext).hexdigest(), str(chunk.get("ciphertextSha256"))):
            return {"verified": False, "manifestVerified": True, "chunksVerified": False}
        digest.update(ciphertext)
    verified = hmac.compare_digest(digest.hexdigest(), str(manifest.get("ciphertextSha256")))
    return {
        "verified": verified,
        "manifestVerified": True,
        "chunksVerified": verified,
        "encryptedStorageHash": digest.hexdigest(),
        "plaintextIdentityHash": manifest.get("plaintextSha256", ""),
        "manifestHash": manifest.get("manifestSha256", ""),
    }
