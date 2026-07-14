from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from django.db import transaction
from django.utils.dateparse import parse_datetime

from apps.forensics.models import Alert, AnomalyRecord, Case, CaseMembership, DetectionMatch, EvidenceFile, EvidenceManifest, Export, ProcessingJob, Report, SessionSummary, ZeekLogSummary
from common.audit import Actor, add_history, log_access
from common.case_workspace import refresh_case_workspace_snapshot
from common.custody import record_custody_event
from common.indexing import index_analysis
from common.jobs import completed_steps
from common.vault import build_manifest_payload


VALIDATOR_CASE_PREFIXES = (
    "CYB-GJ-PHASE",
    "CYB-GJ-SUPABASE",
    "CYB-GJ-READY",
    "CYB-GJ-NORMALIZATION",
    "CYB-GJ-TEST",
)


def is_validator_case(case_id: str, intake: dict[str, Any] | None = None) -> bool:
    intake = intake or {}
    origin = str(intake.get("origin", "")).lower()
    if origin in {"validator", "system_test"}:
        return True
    if any(case_id.startswith(prefix) for prefix in VALIDATOR_CASE_PREFIXES):
        return True
    investigator = str(intake.get("investigator", "")).lower()
    return "validator" in investigator or "readiness" in investigator


def case_origin(case_id: str, intake: dict[str, Any] | None = None, default: str = Case.Origin.OFFICER_UPLOAD) -> str:
    intake = intake or {}
    explicit = intake.get("origin")
    if explicit in {choice[0] for choice in Case.Origin.choices}:
        return explicit
    return Case.Origin.VALIDATOR if is_validator_case(case_id, intake) else default


def analysis_for_case(case_id: str | None = None) -> dict[str, Any] | None:
    jobs = ProcessingJob.objects.filter(status=ProcessingJob.Status.COMPLETED).order_by("-updated_at")
    if case_id:
        jobs = jobs.filter(case_id=case_id)
    job = jobs.first()
    if not job:
        return None
    analysis = job.stats.get("analysis")
    if isinstance(analysis, dict):
        return analysis
    return None


def latest_job_for_case(case_id: str | None = None) -> ProcessingJob | None:
    jobs = ProcessingJob.objects.order_by("-updated_at")
    if case_id:
        jobs = jobs.filter(case_id=case_id)
    return jobs.first()


@transaction.atomic
def persist_analysis(analysis: dict[str, Any], saved: dict[str, Any], actor: Actor) -> ProcessingJob:
    case_data = analysis["case"]
    evidence_data = analysis["evidence"]
    intake = saved.get("intake", {})
    case, _ = Case.objects.update_or_create(
        id=analysis["caseId"],
        defaults={
            "title": case_data.get("title", f"Real PCAP analysis: {saved['filename']}"),
            "investigator": intake.get("investigator") or case_data.get("investigator", actor.user),
            "department": intake.get("department") or "Gujarat Cyber Crime Cell",
            "priority": intake.get("priority") or "Standard",
            "origin": case_origin(analysis["caseId"], intake),
            "is_test": is_validator_case(analysis["caseId"], intake),
            "opened_at": _dt(case_data.get("openedAt")) or datetime.now(timezone.utc),
            "closed_at": _dt(case_data.get("closedAt")),
            "source_location": intake.get("sourceLocation", ""),
            "remarks": intake.get("remarks", ""),
            "flags_json": intake.get("flags", []),
            "status": case_data.get("status", Case.Status.REVIEWING),
            "report_status": case_data.get("reportStatus", "ready"),
        },
    )
    evidence, _ = EvidenceFile.objects.update_or_create(
        id=analysis["evidenceId"],
        defaults={
            "case": case,
            "filename": evidence_data.get("filename", saved["filename"]),
            "stored_path": saved["stored_path"],
            "evidence_type": (saved.get("normalization") or {}).get("normalizedType") or intake.get("evidenceType") or EvidenceFile.EvidenceType.PCAP,
            "size_bytes": saved["size_bytes"],
            "sha256": saved["sha256"],
            "captured_at": _dt(evidence_data.get("capturedAt")),
            "uploaded_by": actor.user,
            "status": EvidenceFile.Status.VERIFIED,
            "retention_expires_at": datetime.now(timezone.utc) + timedelta(days=90),
        },
    )
    if actor.django_user_id:
        CaseMembership.objects.update_or_create(case=case, user_id=actor.django_user_id, defaults={"role": actor.role, "added_by": "upload"})
    manifest_payload = build_manifest_payload(saved, evidence.id, case.id)
    EvidenceManifest.objects.update_or_create(
        id=manifest_payload["id"],
        defaults={
            "case": case,
            "evidence_file": evidence,
            "plaintext_sha256": manifest_payload["plaintextSha256"],
            "encrypted_sha256": manifest_payload["encryptedSha256"],
            "storage_uri": manifest_payload["storageUri"],
            "original_filename": manifest_payload["originalFilename"],
            "size_bytes": manifest_payload["sizeBytes"],
            "encryption_algorithm": manifest_payload["encryptionAlgorithm"],
            "key_id": manifest_payload["keyId"],
            "manifest_json": manifest_payload,
            "manifest_hash": manifest_payload["manifestHash"],
        },
    )
    indexed = index_analysis(analysis)
    existing_job = ProcessingJob.objects.filter(id=analysis["jobId"]).first()
    job, _ = ProcessingJob.objects.update_or_create(
        id=analysis["jobId"],
        defaults={
            "case": case,
            "evidence_file": evidence,
            "status": ProcessingJob.Status.COMPLETED,
            "step": "completed",
            "progress": 100,
            "steps": completed_steps(),
            "events": (list(existing_job.events if existing_job else []) + [
                {"timestamp": analysis.get("createdAt"), "event": "uploaded", "detail": "Evidence uploaded and hashed."},
                {"timestamp": analysis.get("createdAt"), "event": "analysis.completed", "detail": "tshark, Zeek, detection, anomaly, and indexing completed."},
            ])[-100:],
            "started_at": existing_job.started_at if existing_job and existing_job.started_at else _dt(analysis.get("createdAt")),
            "completed_at": datetime.now(timezone.utc),
            "lease_owner": "",
            "lease_expires_at": None,
            "heartbeat_at": datetime.now(timezone.utc),
            "next_attempt_at": None,
            "error_code": "",
            "error_message": "",
            "stats": {"summary": analysis.get("summary", {}), "analysis": analysis, "indexed": indexed, "normalization": saved.get("normalization", {})},
            "processing_path": analysis.get("processingPath", "sync-fallback"),
            "fallback_reason": analysis.get("fallbackReason", ""),
            "last_progress_at": datetime.now(timezone.utc),
            "completed_chunk_count": analysis.get("completedChunks", existing_job.completed_chunk_count if existing_job else 0),
            "expected_chunk_count": analysis.get("expectedChunks", existing_job.expected_chunk_count if existing_job else 0),
            "completeness_status": analysis.get("searchCompleteness", "complete"),
        },
    )
    _replace_records(case, analysis, evidence)
    add_history(case, actor, "Evidence analyzed", f"{saved['filename']} analyzed, persisted, and indexed.", saved["sha256"])
    record_custody_event(case, actor, "Evidence uploaded", {"filename": saved["filename"], "sha256": saved["sha256"]}, evidence, "EvidenceFile", evidence.id)
    record_custody_event(case, "Netra vault", "Evidence encrypted", {"encryptedSha256": saved.get("encrypted_sha256", ""), "keyId": manifest_payload["keyId"]}, evidence, "EvidenceManifest", manifest_payload["id"])
    record_custody_event(case, "Netra analysis engine", "Analysis completed", {"jobId": analysis["jobId"], "summary": analysis.get("summary", {})}, evidence, "ProcessingJob", analysis["jobId"])
    log_access(actor, "evidence.upload", case=case, resource_type="EvidenceFile", resource_id=evidence.id)
    refresh_case_workspace_snapshot(case, job=job, analysis=analysis)
    return job


def _replace_records(case: Case, analysis: dict[str, Any], evidence: EvidenceFile) -> None:
    SessionSummary.objects.filter(case=case).delete()
    Alert.objects.filter(case=case).delete()
    DetectionMatch.objects.filter(case=case).delete()
    AnomalyRecord.objects.filter(case=case).delete()
    ZeekLogSummary.objects.filter(case=case).delete()

    SessionSummary.objects.bulk_create([
        SessionSummary(
            id=f"{analysis['jobId']}-{row['id']}"[:80],
            case=case,
            source=row.get("source", ""),
            destination=row.get("destination", ""),
            protocol=row.get("protocol", ""),
            start_time=_dt(row.get("startTime")),
            end_time=_dt(row.get("endTime")),
            bytes_sent=row.get("bytesSent", 0),
            bytes_received=row.get("bytesReceived", 0),
            packet_count=row.get("packetCount", 0),
            risk_score=row.get("riskScore", 0),
            related_alert_ids=row.get("relatedAlertIds", []),
        )
        for row in analysis.get("sessions", [])
    ])
    Alert.objects.bulk_create([
        Alert(
            id=f"{analysis['jobId']}-{row['id']}"[:80],
            case=case,
            severity=row.get("severity", "low"),
            attack_class=row.get("attackClass", ""),
            alert_type=row.get("type", ""),
            source_ip=row.get("sourceIp", ""),
            destination=row.get("destination", ""),
            protocol=row.get("protocol", ""),
            event_timestamp=_dt(row.get("timestamp")),
            confidence=row.get("confidence", 0),
            status=row.get("status", "new"),
            rule_id=row.get("ruleId", ""),
            evidence_packet_ids=row.get("evidencePacketIds", []),
            evidence_session_ids=row.get("evidenceSessionIds", []),
            explanation=row.get("explanation", ""),
            recommended_action=row.get("recommendedAction", ""),
        )
        for row in analysis.get("alerts", [])
    ])
    DetectionMatch.objects.bulk_create([
        DetectionMatch(
            id=f"{analysis['jobId']}-{row['id']}"[:80],
            case=case,
            rule_id=row.get("ruleId", ""),
            rule_name=row.get("ruleName", ""),
            category=row.get("category", ""),
            attack_class=row.get("attackClass", ""),
            matched_entity=row.get("matchedEntity", ""),
            confidence=row.get("confidence", 0),
            status=row.get("status", "new"),
            evidence_packet_ids=row.get("evidencePacketIds", []),
            evidence_session_ids=row.get("evidenceSessionIds", []),
            explanation=row.get("explanation", ""),
            recommended_action=row.get("recommendedAction", ""),
        )
        for row in analysis.get("detectionMatches", [])
    ])
    AnomalyRecord.objects.bulk_create([
        AnomalyRecord(
            id=f"{analysis['jobId']}-{row['id']}"[:80],
            case=case,
            entity=row.get("entity", ""),
            behaviour=row.get("behaviour", ""),
            baseline=row.get("baseline", ""),
            observed=row.get("observed", ""),
            deviation=row.get("deviation", ""),
            confidence=row.get("confidence", 0),
            hypothesis=row.get("hypothesis", ""),
            top_features=row.get("topFeatures", []),
            recommended_action=row.get("recommendedAction", ""),
        )
        for row in analysis.get("anomalies", [])
    ])
    zeek = analysis.get("zeek", {})
    ZeekLogSummary.objects.create(
        id=f"{analysis['jobId']}-zeek",
        case=case,
        evidence_file=evidence,
        job_id=analysis["jobId"],
        status=zeek.get("status", "not-run"),
        log_dir=zeek.get("logDir", ""),
        logs=zeek.get("logs", []),
        summary=zeek.get("summary", {}),
        top_services=zeek.get("topServices", []),
        top_dns_queries=zeek.get("topDnsQueries", []),
        top_external_hosts=zeek.get("topExternalHosts", []),
    )


def update_analysis_alert_status(match_or_alert_id: str, status: str, actor: Actor) -> dict[str, Any] | None:
    for job in ProcessingJob.objects.filter(status=ProcessingJob.Status.COMPLETED).order_by("-updated_at"):
        analysis = job.stats.get("analysis")
        if not isinstance(analysis, dict):
            continue
        changed = False
        for key in ("alerts", "detectionMatches"):
            for row in analysis.get(key, []):
                if row.get("id") == match_or_alert_id or row.get("ruleId") == match_or_alert_id:
                    row["status"] = status
                    changed = True
        if changed:
            job.stats["analysis"] = analysis
            job.save(update_fields=["stats", "updated_at"])
            case = job.case
            Alert.objects.filter(case=case, id__endswith=match_or_alert_id).update(status=status)
            DetectionMatch.objects.filter(case=case, id__endswith=match_or_alert_id).update(status=status)
            add_history(case, actor, "Finding status changed", f"{match_or_alert_id} marked {status}.")
            record_custody_event(case, actor, "Finding status changed", {"findingId": match_or_alert_id, "status": status}, resource_type="Finding", resource_id=match_or_alert_id)
            log_access(actor, "finding.status", case=case, resource_type="Finding", resource_id=match_or_alert_id)
            refresh_case_workspace_snapshot(case, job=job, analysis=analysis)
            return {"id": match_or_alert_id, "status": status, "caseId": case.id}
    return None


def record_report(case_id: str, artifact: dict[str, Any], language: str, actor: Actor) -> None:
    case = Case.objects.filter(id=case_id).first()
    if not case:
        return
    Report.objects.update_or_create(id=artifact["filename"], defaults={"case": case, "language": language, "generated_by": actor.user, "stored_path": artifact["stored_path"], "sha256": artifact["sha256"], "status": "ready"})
    add_history(case, actor, "Report generated", f"{artifact['filename']} generated.", artifact["sha256"])
    record_custody_event(case, actor, "Report generated", {"filename": artifact["filename"], "sha256": artifact["sha256"], "encryptedSha256": artifact.get("encrypted_sha256", "")}, resource_type="Report", resource_id=artifact["filename"])
    log_access(actor, "report.generate", case=case, resource_type="Report", resource_id=artifact["filename"])
    refresh_case_workspace_snapshot(case)


def record_export(case_id: str, export_id: str, export_type: str, artifact: dict[str, Any], actor: Actor) -> None:
    case = Case.objects.filter(id=case_id).first()
    if not case:
        return
    Export.objects.update_or_create(id=export_id, defaults={"case": case, "export_type": export_type, "requested_by": actor.user, "stored_path": artifact["stored_path"], "sha256": artifact["sha256"], "status": "ready"})
    add_history(case, actor, "Evidence export generated", f"{artifact['filename']} generated.", artifact["sha256"])
    record_custody_event(case, actor, "Evidence export generated", {"filename": artifact["filename"], "sha256": artifact["sha256"], "encryptedSha256": artifact.get("encrypted_sha256", "")}, resource_type="Export", resource_id=export_id)
    log_access(actor, "export.generate", case=case, resource_type="Export", resource_id=export_id)
    refresh_case_workspace_snapshot(case)


def _dt(value: str | None):
    if not value:
        return None
    parsed = parse_datetime(value)
    return parsed or None
