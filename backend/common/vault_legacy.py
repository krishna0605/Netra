from __future__ import annotations

import base64
import hashlib
import hmac
import os
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.conf import settings

from common.storage_provider import storage_provider


def _legacy_fernet_for_secret(secret: str) -> Fernet:
    """Reproduce the historical v1 derivation exactly for decrypt-only use."""
    raw = secret.encode("utf-8")
    key = base64.urlsafe_b64encode(raw.ljust(32, b"0")[:32])
    return Fernet(key)


def legacy_fernet() -> MultiFernet:
    secrets = [settings.NETRA_EVIDENCE_KEY, *settings.NETRA_EVIDENCE_PREVIOUS_KEYS]
    readers = [_legacy_fernet_for_secret(secret) for secret in dict.fromkeys(secrets) if secret]
    if not readers:
        raise RuntimeError("No legacy evidence decryption key is configured.")
    return MultiFernet(readers)


def decrypt_legacy_file(source: str | Path, target: str | Path) -> Path:
    """Decrypt a legacy Fernet artifact without buffering ciphertext in memory."""
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(settings.NETRA_TEMP_ROOT)
    temporary_root.mkdir(parents=True, exist_ok=True)
    encoded_path: Path | None = None
    try:
        with NamedTemporaryFile(delete=False, dir=temporary_root, suffix=".fernet-encoded") as temporary:
            encoded_path = Path(temporary.name)
        os.chmod(encoded_path, 0o600)
        with storage_provider.open_encrypted(source, "rb") as encrypted, encoded_path.open("wb") as local_copy:
            shutil.copyfileobj(encrypted, local_copy, length=1024 * 1024)
        return stream_decrypt_legacy_path(encoded_path, target_path, temporary_root=temporary_root)
    except Exception:
        target_path.unlink(missing_ok=True)
        raise
    finally:
        if encoded_path is not None:
            encoded_path.unlink(missing_ok=True)


def _decode_fernet_token(encoded_path: Path, decoded_path: Path, chunk_size: int = 1024 * 1024) -> None:
    carry = b""
    with encoded_path.open("rb") as source, decoded_path.open("wb") as target:
        while True:
            block = source.read(chunk_size)
            if not block:
                break
            block = carry + b"".join(block.split())
            usable = len(block) - (len(block) % 4)
            if usable:
                target.write(base64.urlsafe_b64decode(block[:usable]))
            carry = block[usable:]
        if carry:
            target.write(base64.urlsafe_b64decode(carry))


def _key_parts(secret: str) -> tuple[bytes, bytes]:
    raw = secret.encode("utf-8")
    derived = raw.ljust(32, b"0")[:32]
    return derived[:16], derived[16:]


def _verified_key(decoded_path: Path, chunk_size: int = 1024 * 1024) -> tuple[bytes, bytes]:
    size = decoded_path.stat().st_size
    if size < 57:
        raise ValueError("Legacy Fernet artifact is truncated.")
    authenticated_size = size - 32
    with decoded_path.open("rb") as handle:
        version = handle.read(1)
        if version != b"\x80":
            raise ValueError("Legacy Fernet artifact has an invalid version marker.")
    for secret in dict.fromkeys([settings.NETRA_EVIDENCE_KEY, *settings.NETRA_EVIDENCE_PREVIOUS_KEYS]):
        if not secret:
            continue
        signing_key, encryption_key = _key_parts(secret)
        verifier = hmac.new(signing_key, digestmod=hashlib.sha256)
        with decoded_path.open("rb") as handle:
            remaining = authenticated_size
            while remaining:
                block = handle.read(min(chunk_size, remaining))
                if not block:
                    raise ValueError("Legacy Fernet artifact ended unexpectedly.")
                verifier.update(block)
                remaining -= len(block)
            signature = handle.read(32)
        if hmac.compare_digest(verifier.digest(), signature):
            return signing_key, encryption_key
    raise ValueError("No configured legacy evidence key can authenticate this artifact.")


def stream_decrypt_legacy_path(encoded_path: str | Path, target: str | Path, *, temporary_root: Path) -> Path:
    """Authenticate, then decrypt a Fernet token without holding the artifact in memory."""
    source = Path(encoded_path)
    destination = Path(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_root.mkdir(parents=True, exist_ok=True)
    decoded_path: Path | None = None
    try:
        with NamedTemporaryFile(delete=False, dir=temporary_root, suffix=".fernet-token") as temporary:
            decoded_path = Path(temporary.name)
        _decode_fernet_token(source, decoded_path)
        _, encryption_key = _verified_key(decoded_path)
        with decoded_path.open("rb") as decoded:
            decoded.seek(9)
            iv = decoded.read(16)
            ciphertext_bytes = decoded_path.stat().st_size - 25 - 32
            decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            with destination.open("wb") as plaintext:
                os.chmod(destination, 0o600)
                remaining = ciphertext_bytes
                while remaining:
                    block = decoded.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("Legacy Fernet ciphertext ended unexpectedly.")
                    remaining -= len(block)
                    plaintext.write(unpadder.update(decryptor.update(block)))
                plaintext.write(unpadder.update(decryptor.finalize()))
                plaintext.write(unpadder.finalize())
        return destination
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if decoded_path is not None:
            decoded_path.unlink(missing_ok=True)
