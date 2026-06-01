from __future__ import annotations

import json
from uuid import uuid4

from apps.forensics.models import Case, CustodyLedgerEvent, EvidenceFile
from common.audit import Actor
from common.hashing import sha256_text


def canonical_payload(event: CustodyLedgerEvent | dict) -> dict:
    if isinstance(event, dict):
        return event
    return {
        "caseId": event.case_id,
        "evidenceId": event.evidence_file_id or "",
        "actorUser": event.actor_user,
        "actorLabel": event.actor_label,
        "actorRole": event.actor_role,
        "action": event.action,
        "resourceType": event.resource_type,
        "resourceId": event.resource_id,
        "details": event.details_json,
        "createdAt": event.created_at.isoformat(),
    }


def calculate_event_hash(previous_hash: str, payload: dict) -> str:
    return sha256_text(f"{previous_hash}{json.dumps(payload, sort_keys=True, separators=(',', ':'))}")


def record_custody_event(
    case: Case,
    actor: Actor | str,
    action: str,
    details: dict,
    evidence: EvidenceFile | None = None,
    resource_type: str = "",
    resource_id: str = "",
) -> CustodyLedgerEvent:
    previous = CustodyLedgerEvent.objects.filter(case=case).order_by("-created_at").first()
    actor_label = actor.user if isinstance(actor, Actor) else str(actor)
    actor_role = actor.role if isinstance(actor, Actor) else "System"
    event = CustodyLedgerEvent(
        id=f"cust-{uuid4().hex[:10]}",
        case=case,
        evidence_file=evidence,
        actor_user=actor_label,
        actor_label=actor_label,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details_json=details,
        previous_hash=previous.event_hash if previous else "",
        event_hash="pending",
    )
    payload = canonical_payload(
        {
            "caseId": case.id,
            "evidenceId": evidence.id if evidence else "",
            "actorUser": event.actor_user,
            "actorLabel": event.actor_label,
            "actorRole": event.actor_role,
            "action": action,
            "resourceType": resource_type,
            "resourceId": resource_id,
            "details": details,
        }
    )
    event.event_hash = calculate_event_hash(event.previous_hash, payload)
    event.save()
    return event


def verify_case_ledger(case: Case) -> dict:
    previous_hash = ""
    rows = list(CustodyLedgerEvent.objects.filter(case=case).order_by("created_at", "id"))
    failures = []
    for row in rows:
        payload = {
            "caseId": row.case_id,
            "evidenceId": row.evidence_file_id or "",
            "actorUser": row.actor_user,
            "actorLabel": row.actor_label,
            "actorRole": row.actor_role,
            "action": row.action,
            "resourceType": row.resource_type,
            "resourceId": row.resource_id,
            "details": row.details_json,
        }
        expected = calculate_event_hash(previous_hash, payload)
        if row.previous_hash != previous_hash or row.event_hash != expected:
            failures.append(row.id)
        previous_hash = row.event_hash
    return {
        "verified": not failures,
        "eventCount": len(rows),
        "rootHash": rows[0].event_hash if rows else "",
        "latestHash": rows[-1].event_hash if rows else "",
        "failures": failures,
    }


def custody_event_dict(row: CustodyLedgerEvent) -> dict:
    return {
        "id": row.id,
        "timestamp": row.created_at.isoformat(),
        "actor": row.actor_label,
        "role": row.actor_role,
        "action": row.action,
        "resourceType": row.resource_type,
        "resourceId": row.resource_id,
        "details": row.details_json,
        "previousHash": row.previous_hash,
        "eventHash": row.event_hash,
        "hashStatus": "recorded",
    }
