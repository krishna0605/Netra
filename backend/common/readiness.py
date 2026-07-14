from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import connection
from django.utils import timezone

from apps.forensics.models import (
    AccessLog,
    Alert,
    Case,
    CustodyLedgerEvent,
    DeadLetterEvent,
    EvidenceFile,
    Export,
    OperationalEvent,
    ProcessingJob,
    Report,
    RetentionRun,
    WorkerHeartbeat,
)
from common.custody import custody_event_dict, verify_case_ledger


def incident_readiness_payload() -> dict[str, Any]:
    now = timezone.now()
    window_start = now - timedelta(hours=24)
    dead_letters = DeadLetterEvent.objects.exclude(status=DeadLetterEvent.Status.RESOLVED)
    failed_jobs = ProcessingJob.objects.filter(status=ProcessingJob.Status.FAILED)
    denied_access = AccessLog.objects.filter(result="denied", created_at__gte=window_start)
    reports_ready = Report.objects.filter(status="ready")
    exports_ready = Export.objects.filter(status="ready")
    latest_retention = RetentionRun.objects.order_by("-started_at").first()
    worker_rows = list(WorkerHeartbeat.objects.order_by("worker_name", "-last_seen_at"))
    stale_workers = [
        row.worker_name
        for row in worker_rows
        if row.last_seen_at and (now - row.last_seen_at).total_seconds() > 90
    ]
    readiness_items = [
        _item("database", "ready", f"{len(connection.introspection.table_names())} tables visible."),
        _item("audit-logging", "ready" if AccessLog.objects.exists() else "partial", f"{AccessLog.objects.count()} access log row(s)."),
        _item("custody-ledger", "ready" if CustodyLedgerEvent.objects.exists() else "partial", f"{CustodyLedgerEvent.objects.count()} custody event(s)."),
        _item("evidence-storage", "ready" if EvidenceFile.objects.exists() else "partial", f"{EvidenceFile.objects.count()} evidence file row(s)."),
        _item("reporting", "ready" if reports_ready.exists() else "partial", f"{reports_ready.count()} ready report(s)."),
        _item("exports", "ready" if exports_ready.exists() else "partial", f"{exports_ready.count()} ready export(s)."),
        _item("dead-letter-operations", "ready" if not dead_letters.exists() else "attention", f"{dead_letters.count()} unresolved dead-letter event(s)."),
        _item("worker-heartbeats", "ready" if not stale_workers else "attention", f"{len(stale_workers)} stale/offline worker heartbeat(s)."),
        _item("retention-runs", "ready" if latest_retention else "partial", f"Latest run: {latest_retention.status if latest_retention else 'none'}."),
    ]
    blockers = [item for item in readiness_items if item["status"] == "attention"]
    status = "ready" if not blockers else "attention"
    return {
        "status": status,
        "checkedAt": now.isoformat(),
        "windowHours": 24,
        "summary": {
            "cases": Case.objects.count(),
            "openCases": Case.objects.filter(status=Case.Status.OPEN).count(),
            "evidenceFiles": EvidenceFile.objects.count(),
            "alerts": Alert.objects.count(),
            "failedJobs": failed_jobs.count(),
            "unresolvedDeadLetters": dead_letters.count(),
            "deniedAccessLast24h": denied_access.count(),
            "operationalEventsLast24h": OperationalEvent.objects.filter(created_at__gte=window_start).count(),
            "readyReports": reports_ready.count(),
            "readyExports": exports_ready.count(),
        },
        "checks": readiness_items,
        "recommendedActions": _incident_recommendations(readiness_items),
    }


def legal_review_checklist(case: Case) -> dict[str, Any]:
    evidence_files = list(case.evidence_files.order_by("created_at"))
    reports = list(case.reports.order_by("-created_at"))
    exports = list(case.exports.order_by("-created_at"))
    alerts = list(case.alerts.order_by("-created_at"))
    custody = verify_case_ledger(case)
    unresolved_alerts = [alert.id for alert in alerts if alert.status in {"new", "reviewing"}]
    items = [
        _item("case-created", "complete", f"Case {case.id} exists with status {case.status}."),
        _item("evidence-present", "complete" if evidence_files else "blocked", f"{len(evidence_files)} evidence file(s) linked."),
        _item("evidence-manifest", "complete" if all(hasattr(evidence, "manifest") for evidence in evidence_files) and evidence_files else "blocked", "Each evidence file should have a manifest with plaintext/encrypted hashes."),
        _item("custody-ledger-verified", "complete" if custody.get("verified") and custody.get("eventCount", 0) > 0 else "blocked", f"{custody.get('eventCount', 0)} custody event(s); latest hash {custody.get('latestHash', '')}."),
        _item("alert-review", "complete" if alerts and not unresolved_alerts else ("partial" if alerts else "not-applicable"), f"{len(unresolved_alerts)} unresolved alert(s)."),
        _item("report-generated", "complete" if reports else "partial", f"{len(reports)} report(s) generated."),
        _item("evidence-exported", "complete" if exports else "partial", f"{len(exports)} export artifact(s) generated."),
        _item("access-logged", "complete" if case.access_logs.exists() else "partial", f"{case.access_logs.count()} access log row(s) for this case."),
        _item("legal-hold", "complete" if case.legal_hold else "optional", case.legal_hold_reason or "No legal hold is active."),
    ]
    blockers = [item for item in items if item["status"] == "blocked"]
    partials = [item for item in items if item["status"] == "partial"]
    return {
        "caseId": case.id,
        "status": "blocked" if blockers else ("review-needed" if partials else "ready-for-legal-review"),
        "legalHold": case.legal_hold,
        "legalHoldReason": case.legal_hold_reason,
        "custodyVerification": custody,
        "items": items,
        "unresolvedAlertIds": unresolved_alerts,
        "recommendedActions": _legal_recommendations(items),
    }


def audit_export_payload(case: Case | None = None) -> dict[str, Any]:
    access_logs = AccessLog.objects.order_by("-created_at")
    custody_events = CustodyLedgerEvent.objects.order_by("created_at", "id")
    operational_events = OperationalEvent.objects.order_by("-created_at")
    dead_letters = DeadLetterEvent.objects.order_by("-created_at")
    if case:
        access_logs = access_logs.filter(case=case)
        custody_events = custody_events.filter(case=case)
        operational_events = operational_events.filter(case=case)
        dead_letters = dead_letters.filter(case_id=case.id)
    return {
        "generatedAt": timezone.now().isoformat(),
        "scope": {"caseId": case.id if case else "", "type": "case" if case else "system"},
        "case": _case_audit_dict(case) if case else None,
        "accessLogs": [_access_log(row) for row in access_logs[:500]],
        "custodyLedger": {
            "verification": verify_case_ledger(case) if case else None,
            "events": [custody_event_dict(row) for row in custody_events[:500]],
        },
        "operationalEvents": [_operational_event(row) for row in operational_events[:500]],
        "deadLetters": [_dead_letter(row) for row in dead_letters[:100]],
        "reports": [_artifact(row) for row in (case.reports.order_by("-created_at")[:100] if case else Report.objects.order_by("-created_at")[:100])],
        "exports": [_artifact(row) for row in (case.exports.order_by("-created_at")[:100] if case else Export.objects.order_by("-created_at")[:100])],
        "redaction": "Secrets, tokens, service-role keys, and raw PCAP payload bytes are not included.",
    }


def deployment_readiness_payload() -> dict[str, Any]:
    checks = [
        _deployment_check("debug-disabled", not settings.DEBUG, "Django debug mode is disabled.", "Set DJANGO_DEBUG=0 before shared deployment.", required=True),
        _deployment_check("secret-key-set", bool(getattr(settings, "SECRET_KEY", "")) and settings.SECRET_KEY != "netra-development-only-secret", "Django secret key is non-default.", "Set a strong DJANGO_SECRET_KEY.", required=True),
        _deployment_check("allowed-hosts-restricted", "*" not in getattr(settings, "ALLOWED_HOSTS", []), "Allowed hosts are explicit.", "Avoid wildcard DJANGO_ALLOWED_HOSTS.", required=True),
        _deployment_check("cors-restricted", "*" not in getattr(settings, "NETRA_FRONTEND_ORIGINS", []), "CORS origins are explicit.", "Set NETRA_FRONTEND_ORIGINS to the deployed frontend URL only.", required=True),
        _deployment_check("supabase-auth", getattr(settings, "NETRA_AUTH_PROVIDER", "") == "supabase", "Supabase Auth is active.", "Set NETRA_AUTH_PROVIDER=supabase.", required=True),
        _deployment_check(
            "supabase-data-plane",
            getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase" and getattr(settings, "NETRA_STORAGE_PROVIDER", "") == "supabase",
            "Supabase Postgres and Storage are active.",
            "Use Supabase mode for the deployed data plane.",
            required=True,
        ),
        _deployment_check("service-role-backend", bool(getattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "")), "Backend service-role key is configured.", "Set SUPABASE_SERVICE_ROLE_KEY only on the backend.", required=True),
        _deployment_check("dev-role-headers-disabled", not getattr(settings, "NETRA_DEV_ROLE_HEADERS", False), "Development role headers are disabled.", "Set NETRA_DEV_ROLE_HEADERS=0.", required=True),
        _deployment_check(
            "evidence-key-non-default",
            getattr(settings, "NETRA_EVIDENCE_KEY", "") not in {"", "netra-phase3-development-evidence-key"},
            "Evidence encryption key is non-default.",
            "Rotate NETRA_EVIDENCE_KEY and keep it out of source control.",
            required=True,
        ),
        _deployment_check("sensor-key-set", bool(getattr(settings, "NETRA_SENSOR_SHARED_KEY", "")) and settings.NETRA_SENSOR_SHARED_KEY != "netra-phase5-local-sensor-key", "Sensor shared key is non-default.", "Set a random NETRA_SENSOR_SHARED_KEY.", required=False),
        _deployment_check("webhook-secret-set", bool(getattr(settings, "NETRA_WEBHOOK_SIGNING_SECRET", "")), "Webhook signing secret is configured.", "Set NETRA_WEBHOOK_SIGNING_SECRET for SIEM delivery signing.", required=False),
        _deployment_check("queue-provider", getattr(settings, "NETRA_QUEUE_PROVIDER", "") == "postgres-row-lock", "PostgreSQL row locking is the durable queue provider.", "Set NETRA_QUEUE_PROVIDER=postgres-row-lock.", required=False),
        _deployment_check("search-provider", getattr(settings, "NETRA_SEARCH_PROVIDER", "") == "postgres", "Postgres search is active.", "Set NETRA_SEARCH_PROVIDER=postgres for Supabase mode.", required=False),
        _deployment_check(
            "https-plan",
            bool(getattr(settings, "NETRA_PUBLIC_BASE_URL", "").startswith("https://")) or not getattr(settings, "NETRA_REQUIRE_HTTPS", False),
            "HTTPS requirement is consistent with the public URL.",
            "Use an HTTPS public URL or disable NETRA_REQUIRE_HTTPS only for private demos.",
            required=False,
        ),
    ]
    required_failures = [item for item in checks if item["required"] and item["status"] != "pass"]
    warnings = [item for item in checks if not item["required"] and item["status"] != "pass"]
    status = "ready" if not required_failures and not warnings else ("blocked" if required_failures else "degraded")
    return {
        "status": status,
        "deploymentEnv": getattr(settings, "NETRA_DEPLOYMENT_ENV", "local"),
        "releaseId": getattr(settings, "NETRA_RELEASE_ID", "local-dev"),
        "publicBaseUrl": getattr(settings, "NETRA_PUBLIC_BASE_URL", "http://localhost:8080"),
        "checkedAt": timezone.now().isoformat(),
        "checks": checks,
        "requiredFailures": [item["name"] for item in required_failures],
        "warnings": [item["name"] for item in warnings],
        "recommendation": "Ready for deployment smoke tests." if status == "ready" else ("Fix required deployment checks before sharing Netra." if status == "blocked" else "Usable for supervised deployment after reviewing warnings."),
    }


def ml_model_status_payload() -> dict[str, Any]:
    model_dir = Path(settings.BASE_DIR).parent / "ml-services" / "anomaly-engine" / "models"
    metadata_path = model_dir / "anomaly-model.json"
    model_path = model_dir / "anomaly-model.pkl"
    if not metadata_path.exists() or not model_path.exists():
        return {
            "status": "fallback",
            "modelAvailable": False,
            "modelPath": str(model_path),
            "metadataPath": str(metadata_path),
            "detail": "No trained anomaly model artifact is present. Netra is using explainable scoring fallback.",
        }
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "degraded", "modelAvailable": False, "detail": f"Model metadata could not be read: {exc}"}
    return {
        "status": "trained-model",
        "modelAvailable": True,
        "modelPath": str(model_path),
        "metadataPath": str(metadata_path),
        "version": metadata.get("version", "unknown"),
        "modelType": metadata.get("modelType", "unknown"),
        "trainedAt": metadata.get("trainedAt", ""),
        "trainingRows": metadata.get("trainingRows", 0),
        "metrics": metadata.get("metrics", {}),
        "featureNames": metadata.get("featureNames", []),
        "limitations": metadata.get("limitations", []),
    }


def status_matrix_payload() -> dict[str, Any]:
    storage_ok = getattr(settings, "NETRA_STORAGE_PROVIDER", "") == "supabase" and bool(getattr(settings, "SUPABASE_SERVICE_ROLE_KEY", ""))
    ml_status = ml_model_status_payload()
    deployment = deployment_readiness_payload()
    rows = [
        _status("Supabase Storage", "Working / Validated" if storage_ok else "Blocked", "Private bucket access is configured through the backend service-role key." if storage_ok else "Storage needs a valid backend service-role key and bucket bootstrap.", ["storage-health", "upload-artifact"]),
        _status("PCAP upload UI", "Working / Validated", "Officer upload flow is implemented and remains the primary workflow.", ["frontend-build"]),
        _status("Evidence normalization", "Working / Validated", "Upload preflight detects PCAP/log/TLS/DNS/mixed evidence and blocks mismatched evidence types before storage.", ["evidence/normalize-preview", "upload-type-guard"]),
        _status("PCAP upload analysis", "Working / Validated", "Authenticated validator covers upload-to-analysis when SUPABASE_TEST_EMAIL/PASSWORD are set.", ["netra:validate:supabase"]),
        _status("tshark parsing", "Working / Validated", "Packet tool health and analysis validators exercise tshark parsing.", ["packet-tools", "netra:validate:dpi"]),
        _status("Zeek analysis", "Working / Validated", "Zeek is integrated in the analysis path with tolerant failure messaging.", ["packet-tools", "zeek-summary"]),
        _status("Threat detection", "Working / Validated for demo", "Rule/behavior detection has a benchmark corpus and precision/recall report.", ["netra:validate:detection"]),
        _status("AI anomaly detection", "Working / Validated ML prototype" if ml_status["modelAvailable"] else "Working fallback / model not trained", "Trained model artifact is active." if ml_status["modelAvailable"] else "Explainable scoring works; run npm run netra:benchmark:ml to train the optional model.", ["netra:benchmark:ml"]),
        _status("Payload inspection / DPI", "Working metadata-DPI / Validated", "Protocol-specific metadata clues are validated without claiming TLS decryption.", ["netra:validate:dpi"]),
        _status("Suspicious Activity page", "Working / Validated", "Page merges alerts, anomalies, and suspicious flows with empty states.", ["frontend-build", "case-data"]),
        _status("Traffic Evidence page", "Working / Validated", "Packets, sessions, protocols, payload clues, and graph tabs are case-scoped.", ["frontend-build", "case-data"]),
        _status("Reports / exports", "Working / Validated", "HTML, JSON, CSV, and CEF flows are included in Supabase validation when credentials are set.", ["netra:validate:supabase", "netra:validate:siem"]),
        _status("Custody ledger / integrity", "Working / Validated", "Ledger, manifests, artifact hashes, legal hold, and verification are validated.", ["netra:validate:legal"]),
        _status("Legal review checklist", "Working / Validated", "Checklist is included in Evidence Report and report artifacts.", ["netra:validate:legal"]),
        _status("Supabase Realtime", "Working / Validated", "Low-volume operational tables are published and polling fallback remains available.", ["system/realtime"]),
        _status("Supabase PGMQ", "Working / Validated", "Queue send/read/archive probe validates PGMQ without Kafka.", ["system/kafka", "netra:validate:workers"]),
        _status("Kafka / Elasticsearch", "Removed From Supabase Mode", "Supabase mode uses PGMQ and Postgres search; production compose excludes both.", ["netra:validate:production"]),
        _status("Sensor capture", "Advanced / Validated", "Sensor registration, heartbeat, chunk upload, and finalization have a dedicated validator.", ["netra:validate:sensor"]),
        _status("Replay PCAP", "Advanced / Validated", "Replay is a demo/testing tool and has finalization validation.", ["netra:validate:replay"]),
        _status("SIEM integration", "Working basic SIEM / Validated", "Webhook success/failure and CEF export are validated as basic integrations.", ["netra:validate:siem"]),
        _status("Production deployment profile", "Production-Gated / Validated", "Production compose and release checklist exist; real production env must pass readiness.", ["netra:validate:production"]),
        _status("Production readiness", "Private pilot ready; public production gated" if deployment["status"] != "blocked" else "Production-Gated", deployment["recommendation"], ["system/deployment-readiness"]),
    ]
    return {
        "generatedAt": timezone.now().isoformat(),
        "statusLanguage": {
            "Working / Validated": "Feature works end-to-end and has repeatable validation.",
            "Advanced / Validated": "Feature works but remains technical/operator-facing.",
            "Production-Gated": "Implemented but requires production secrets/security review.",
            "Removed From Supabase Mode": "Intentionally not required in the Supabase architecture.",
        },
        "results": rows,
        "summary": {
            "total": len(rows),
            "validated": sum(1 for row in rows if "Validated" in row["targetStatus"] or row["targetStatus"] == "Removed From Supabase Mode"),
            "gated": sum(1 for row in rows if "Gated" in row["targetStatus"]),
        },
    }


def _item(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _deployment_check(name: str, passed: bool, ok: str, fix: str, required: bool) -> dict[str, Any]:
    return {"name": name, "status": "pass" if passed else "fail", "required": required, "detail": ok if passed else fix}


def _status(area: str, target_status: str, detail: str, validation: list[str]) -> dict[str, Any]:
    return {"area": area, "targetStatus": target_status, "detail": detail, "validation": validation}


def _incident_recommendations(items: list[dict[str, str]]) -> list[str]:
    recommendations = []
    for item in items:
        if item["status"] == "attention":
            recommendations.append(f"Review {item['name']}: {item['detail']}")
    if not recommendations:
        recommendations.append("No immediate operational blockers detected. Continue routine backup, retention, and custody verification checks.")
    return recommendations


def _legal_recommendations(items: list[dict[str, str]]) -> list[str]:
    actions = []
    for item in items:
        if item["status"] in {"blocked", "partial"}:
            actions.append(f"Complete {item['name']}: {item['detail']}")
    if not actions:
        actions.append("Case package is ready for supervisor/legal review. Export the audit bundle and preserve the latest custody hash.")
    return actions


def _case_audit_dict(case: Case | None) -> dict[str, Any]:
    if not case:
        return {}
    return {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "investigator": case.investigator,
        "department": case.department,
        "legalHold": case.legal_hold,
        "legalHoldReason": case.legal_hold_reason,
        "createdAt": case.created_at.isoformat(),
        "updatedAt": case.updated_at.isoformat(),
    }


def _access_log(row: AccessLog) -> dict[str, Any]:
    return {
        "timestamp": row.created_at.isoformat(),
        "user": row.user_label,
        "role": row.role,
        "action": row.action,
        "result": row.result,
        "resourceType": row.resource_type,
        "resourceId": row.resource_id,
        "caseId": row.case_id or "",
    }


def _operational_event(row: OperationalEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "timestamp": row.created_at.isoformat(),
        "eventType": row.event_type,
        "caseId": row.case_id or "",
        "captureJobId": row.capture_job_id or "",
        "payload": row.payload_json,
    }


def _dead_letter(row: DeadLetterEvent) -> dict[str, Any]:
    return {
        "id": row.id,
        "timestamp": row.created_at.isoformat(),
        "topic": row.topic,
        "workerName": row.worker_name,
        "jobId": row.job_id,
        "caseId": row.case_id,
        "status": row.status,
        "retryCount": row.retry_count,
        "error": row.error_message[:500],
    }


def _artifact(row: Report | Export) -> dict[str, Any]:
    return {
        "id": row.id,
        "caseId": row.case_id,
        "type": getattr(row, "language", None) or getattr(row, "export_type", ""),
        "sha256": row.sha256,
        "status": row.status,
        "createdAt": row.created_at.isoformat(),
    }
