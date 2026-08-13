"""The administrator audit chain.

Every administrative change lands here, sealed to the one before it, so that
removing or altering an entry after the fact breaks every hash that follows.
This exists before any write endpoint does, deliberately: a trail added after
the operations it records already began is a trail that starts with a gap, and
the gap is exactly the period nobody can account for.

The pattern is the one common/custody.py already uses for evidence — append
under a lock on the parent row, chain each entry to its predecessor's hash —
because a second locking idiom for the same problem is a second thing to get
wrong. Two differences are deliberate and noted on the model.
"""

from __future__ import annotations

import json
from typing import Any

from django.db import transaction
from django.utils import timezone

from apps.forensics.models import AdminAuditEvent, Organization
from common.audit import Actor
from common.hashing import sha256_text


def _sealed_payload(
    *,
    organization_id: str,
    chain_index: int,
    recorded_at: str,
    actor_label: str,
    actor_email: str,
    actor_role: str,
    action: str,
    target_type: str,
    target_id: str,
    before: dict,
    after: dict,
    reason: str,
) -> dict[str, Any]:
    """Exactly the fields the hash covers.

    Anything omitted here can be edited afterwards without breaking the chain,
    so the list is the real definition of what this trail guarantees. It is
    built by one function used by both the append and the verify so the two can
    never drift — the failure mode where a chain verifies against a payload
    nobody actually recorded.
    """
    return {
        "organizationId": organization_id,
        "chainIndex": chain_index,
        "recordedAt": recorded_at,
        "actorLabel": actor_label,
        "actorEmail": actor_email,
        "actorRole": actor_role,
        "action": action,
        "targetType": target_type,
        "targetId": target_id,
        "before": before,
        "after": after,
        "reason": reason,
    }


def calculate_event_hash(previous_hash: str, payload: dict) -> str:
    return sha256_text(f"{previous_hash}{json.dumps(payload, sort_keys=True, separators=(',', ':'))}")


def _payload_for(row: AdminAuditEvent) -> dict[str, Any]:
    return _sealed_payload(
        organization_id=str(row.organization_id),
        chain_index=row.chain_index,
        recorded_at=row.recorded_at.isoformat(),
        actor_label=row.actor_label,
        actor_email=row.actor_email,
        actor_role=row.actor_role,
        action=row.action,
        target_type=row.target_type,
        target_id=row.target_id,
        before=row.before_json,
        after=row.after_json,
        reason=row.reason,
    )


@transaction.atomic
def record_admin_event(
    *,
    organization: Organization,
    actor: Actor,
    action: str,
    target_type: str = "",
    target_id: str = "",
    before: dict | None = None,
    after: dict | None = None,
    reason: str = "",
) -> AdminAuditEvent:
    """Append one sealed entry.

    The lock on the organization row is what makes the chain correct under
    concurrency. Without it two administrators acting at the same moment both
    read the same highest index and both try to write the next one; the unique
    constraint saves the chain from corruption, but the losing append is simply
    gone — an administrative change that happened and left no record. That is
    worse than a slow one, and it will never reproduce on a developer's laptop.

    Effective on PostgreSQL. SQLite serialises writes anyway, which is why the
    concurrency proof runs in the PostgreSQL job.
    """
    locked = Organization.objects.select_for_update().get(pk=organization.pk)
    previous = (
        AdminAuditEvent.objects.filter(organization=locked).order_by("-chain_index").first()
    )
    recorded_at = timezone.now()
    chain_index = (previous.chain_index + 1) if previous else 1

    event = AdminAuditEvent(
        organization=locked,
        chain_index=chain_index,
        recorded_at=recorded_at,
        actor_user_id=actor.django_user_id,
        actor_label=actor.user,
        actor_email=actor.email,
        actor_role=actor.role,
        action=action,
        target_type=target_type,
        target_id=target_id,
        before_json=before or {},
        after_json=after or {},
        reason=reason,
        previous_hash=previous.event_hash if previous else "",
    )
    event.event_hash = calculate_event_hash(event.previous_hash, _payload_for(event))
    event.save()
    return event


def verify_admin_chain(organization: Organization) -> dict[str, Any]:
    """Recompute the whole chain and report where it stops agreeing.

    Reports the first broken index rather than only a boolean. An auditor
    needs to know how much of the record is still trustworthy, and "everything
    after entry 214 is suspect" is a different finding from "the trail is
    unusable".
    """
    rows = list(AdminAuditEvent.objects.filter(organization=organization).order_by("chain_index"))
    previous_hash = ""
    failures: list[int] = []
    expected_index = 1

    for row in rows:
        if row.chain_index != expected_index:
            failures.append(row.chain_index)
        expected_index = row.chain_index + 1
        expected_hash = calculate_event_hash(previous_hash, _payload_for(row))
        if row.previous_hash != previous_hash or row.event_hash != expected_hash:
            failures.append(row.chain_index)
        previous_hash = row.event_hash

    ordered = sorted(set(failures))
    return {
        "verified": not ordered,
        "eventCount": len(rows),
        "rootHash": rows[0].event_hash if rows else "",
        "latestHash": rows[-1].event_hash if rows else "",
        "firstBrokenIndex": ordered[0] if ordered else None,
        "failures": ordered,
        "checkedAt": timezone.now().isoformat(),
    }


def admin_event_dict(row: AdminAuditEvent) -> dict[str, Any]:
    """Shape the administration console reads."""
    compact = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")) if value else ""
    return {
        "id": str(row.id),
        "chainIndex": row.chain_index,
        "at": row.recorded_at.isoformat(),
        "actor": row.actor_label,
        "action": row.action,
        "targetType": row.target_type,
        "targetId": row.target_id,
        "reason": row.reason,
        "before": compact(row.before_json),
        "after": compact(row.after_json),
        "previousHash": row.previous_hash,
        "eventHash": row.event_hash,
    }


def update_admin_event(*_args, **_kwargs) -> None:
    raise RuntimeError("Administrator audit events are append-only.")


def delete_admin_event(*_args, **_kwargs) -> None:
    raise RuntimeError("Administrator audit events are append-only.")
