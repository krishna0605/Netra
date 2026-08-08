from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from django.conf import settings

from apps.forensics.models import Case, CustodyLedgerEvent
from common.custody import verify_case_ledger
from common.storage_provider import storage_provider


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _private_key() -> Ed25519PrivateKey:
    raw = base64.b64decode(settings.NETRA_CUSTODY_SIGNING_PRIVATE_KEY, validate=True)
    if len(raw) != 32:
        raise ValueError("Custody signing private key must decode to 32 raw Ed25519 bytes.")
    return Ed25519PrivateKey.from_private_bytes(raw)


def generate_signing_key() -> tuple[str, str]:
    """Return base64 private/public material for tests and offline operator tooling."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(private).decode("ascii"), base64.b64encode(public).decode("ascii")


def build_custody_anchor(case: Case, *, generated_at: datetime | None = None) -> dict:
    key_id = settings.NETRA_CUSTODY_SIGNING_KEY_ID.strip()
    if not key_id:
        raise ValueError("NETRA_CUSTODY_SIGNING_KEY_ID is required.")
    verification = verify_case_ledger(case)
    if not verification["verified"]:
        raise ValueError("Custody ledger verification failed; anchor was not created.")
    latest = CustodyLedgerEvent.objects.filter(case=case).order_by("-created_at", "-id").first()
    generated_at = generated_at or datetime.now(timezone.utc)
    payload = {
        "version": "netra-custody-anchor-v1",
        "organizationId": str(case.organization_id),
        "caseId": case.id,
        "eventCount": verification["eventCount"],
        "rootHash": verification["rootHash"],
        "latestEventId": latest.id if latest else "",
        "latestHash": verification["latestHash"],
        "generatedAt": generated_at.astimezone(timezone.utc).isoformat(),
        "signingKeyId": key_id,
    }
    key = _private_key()
    payload["publicKey"] = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    payload["signature"] = base64.b64encode(key.sign(_canonical(payload))).decode("ascii")
    return payload


def verify_anchor(anchor: dict) -> dict:
    expected = {
        "version", "organizationId", "caseId", "eventCount", "rootHash", "latestEventId",
        "latestHash", "generatedAt", "signingKeyId", "publicKey", "signature",
    }
    if set(anchor) != expected:
        raise ValueError("Custody anchor contains missing or unexpected fields.")
    unsigned = dict(anchor)
    signature = base64.b64decode(unsigned.pop("signature"), validate=True)
    public = base64.b64decode(unsigned["publicKey"], validate=True)
    Ed25519PublicKey.from_public_bytes(public).verify(signature, _canonical(unsigned))
    return anchor


def write_anchor(case: Case, destination: Path, *, upload: bool = False) -> str:
    anchor = build_custody_anchor(case)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("wb", delete=False, dir=destination.parent, suffix=".anchor") as handle:
        temporary = Path(handle.name)
        handle.write(_canonical(anchor))
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
    if not upload:
        return str(destination)
    date = anchor["generatedAt"][:10]
    object_name = (
        f"custody-anchors/{anchor['organizationId']}/{anchor['caseId']}/"
        f"{date}-{anchor['latestEventId']}-{anchor['latestHash']}.json"
    )
    return storage_provider.upload_bucket_object(
        settings.SUPABASE_STORAGE_BUCKET_EXPORTS, object_name, destination, upsert=False,
    )


def load_anchor(source: str | Path) -> dict:
    with storage_provider.open_encrypted(source, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))
