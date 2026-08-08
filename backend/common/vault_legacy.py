from __future__ import annotations

import base64
from pathlib import Path

from cryptography.fernet import Fernet, MultiFernet
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
    """Decrypt a legacy Fernet artifact. New writes must never call this module."""
    target_path = Path(target)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with storage_provider.open_encrypted(source, "rb") as handle:
            ciphertext = handle.read()
        target_path.write_bytes(legacy_fernet().decrypt(ciphertext))
        return target_path
    except Exception:
        target_path.unlink(missing_ok=True)
        raise

