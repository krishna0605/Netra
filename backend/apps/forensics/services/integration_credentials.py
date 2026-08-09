from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

from apps.forensics.models import IntegrationConnection, IntegrationCredential


VERSION = "netra-integration-secret-v1"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _context(connection: IntegrationConnection) -> bytes:
    return json.dumps(
        {
            "integrationId": connection.pk,
            "organizationId": str(connection.organization_id),
            "purpose": "webhook-hmac",
            "version": VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _key(secret: str, salt: bytes, context: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"netra-integration-credential\0" + context,
    ).derive(secret.encode("utf-8"))


def store_integration_secret(connection: IntegrationConnection, secret: str, *, label: str = "webhook-hmac") -> IntegrationCredential:
    value = (secret or "").strip()
    if not value or len(value) > 4096:
        raise ValueError("An integration secret between 1 and 4096 characters is required.")
    if not settings.NETRA_EVIDENCE_KEY or not settings.NETRA_EVIDENCE_KEY_ID:
        raise RuntimeError("Integration credential encryption is not configured.")
    context = _context(connection)
    salt = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key(settings.NETRA_EVIDENCE_KEY, salt, context)).encrypt(
        nonce,
        value.encode("utf-8"),
        context,
    )
    credential, _ = IntegrationCredential.objects.update_or_create(
        integration=connection,
        defaults={
            "secret_label": label,
            "secret_value": "",
            "secret_version": VERSION,
            "secret_key_id": settings.NETRA_EVIDENCE_KEY_ID,
            "secret_envelope": {
                "version": VERSION,
                "salt": _b64(salt),
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
            },
        },
    )
    return credential


def read_integration_secret(connection: IntegrationConnection) -> str:
    credential = getattr(connection, "credential", None)
    if credential is None:
        return ""
    envelope = credential.secret_envelope if isinstance(credential.secret_envelope, dict) else {}
    if envelope.get("version") != VERSION:
        if credential.secret_value and settings.NETRA_DEPLOYMENT_ENV != "production":
            return credential.secret_value
        raise RuntimeError("The integration credential requires encrypted migration.")
    context = _context(connection)
    secrets = [settings.NETRA_EVIDENCE_KEY, *getattr(settings, "NETRA_EVIDENCE_PREVIOUS_KEYS", [])]
    for secret in dict.fromkeys(value for value in secrets if value):
        try:
            plaintext = AESGCM(_key(secret, _unb64(envelope["salt"]), context)).decrypt(
                _unb64(envelope["nonce"]),
                _unb64(envelope["ciphertext"]),
                context,
            )
            return plaintext.decode("utf-8")
        except Exception:
            continue
    raise RuntimeError("The integration credential could not be decrypted.")

