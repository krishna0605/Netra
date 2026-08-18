"""Keep an issued password so an administrator can read it back later.

This exists because a closed unit issues every credential centrally and needs to
be able to tell an officer what theirs is. It is the operator's decision, and it
is recorded here rather than argued. What this module can do is make sure the
value is never at rest in the clear, is bound to the account it belongs to, and
cannot be read without leaving a trace.

What it costs, stated plainly so nobody has to rediscover it. An administrator
can already reset an officer's authenticator. A readable password on top of that
means an administrator can sign in as any officer, so the custody ledger and the
access log can no longer establish which of the two of them acted. Answering
that question is Netra's whole claim, and anything resting on it is weaker while
this is switched on.

The construction mirrors services/integration_credentials.py, which already
stores a small secret this way: AES-256-GCM under a key derived per record with
HKDF, and additional authenticated data binding the ciphertext to the profile
and organization it belongs to — so an envelope copied onto another row fails to
open rather than decrypting into the wrong account.
"""

from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from django.conf import settings

VERSION = "netra-held-credential-v1"


class CredentialVaultUnavailable(RuntimeError):
    """Raised when the deployment cannot encrypt, so nothing is stored in clear."""


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _context(*, profile_id: int, organization_id) -> bytes:
    """Bind the ciphertext to one profile in one organization.

    Copying an envelope onto another row yields an InvalidTag rather than another
    officer's password, which is the property worth having when the value is
    readable by design.
    """
    return json.dumps(
        {
            "profileId": int(profile_id),
            "organizationId": str(organization_id),
            "purpose": "held-credential",
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
        info=b"netra-held-credential\0" + context,
    ).derive(secret.encode("utf-8"))


def _configured() -> bool:
    return bool(
        getattr(settings, "NETRA_EVIDENCE_KEY", "") and getattr(settings, "NETRA_EVIDENCE_KEY_ID", "")
    )


def seal(*, password: str, profile_id: int, organization_id) -> dict:
    """Return an envelope for storage. Never returns the password in the clear."""
    value = (password or "").strip()
    if not value:
        raise ValueError("A password is required.")
    if not _configured():
        raise CredentialVaultUnavailable(
            "Holding credentials requires NETRA_EVIDENCE_KEY and NETRA_EVIDENCE_KEY_ID."
        )
    context = _context(profile_id=profile_id, organization_id=organization_id)
    salt = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key(settings.NETRA_EVIDENCE_KEY, salt, context)).encrypt(
        nonce, value.encode("utf-8"), context
    )
    return {
        "version": VERSION,
        "keyId": settings.NETRA_EVIDENCE_KEY_ID,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }


def open_envelope(envelope: dict | None, *, profile_id: int, organization_id) -> str:
    """Recover a held password, or "" when there is nothing to recover.

    Tries the current evidence key and then any previous ones, so rotating the
    key does not silently turn every held credential into an error an operator
    cannot tell apart from "none was ever set".
    """
    if not envelope or not isinstance(envelope, dict):
        return ""
    if not _configured():
        raise CredentialVaultUnavailable("Credential encryption is not configured.")
    try:
        salt = _unb64(envelope["salt"])
        nonce = _unb64(envelope["nonce"])
        ciphertext = _unb64(envelope["ciphertext"])
    except (KeyError, ValueError, TypeError) as problem:
        raise CredentialVaultUnavailable("The stored credential envelope is malformed.") from problem

    context = _context(profile_id=profile_id, organization_id=organization_id)
    secrets = [
        getattr(settings, "NETRA_EVIDENCE_KEY", ""),
        *getattr(settings, "NETRA_EVIDENCE_PREVIOUS_KEYS", []),
    ]
    for secret in [value for value in secrets if value]:
        try:
            return AESGCM(_key(secret, salt, context)).decrypt(nonce, ciphertext, context).decode("utf-8")
        except InvalidTag:
            continue
    raise CredentialVaultUnavailable("No configured evidence key opens this credential.")
