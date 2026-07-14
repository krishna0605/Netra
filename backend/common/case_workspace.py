from __future__ import annotations

from copy import deepcopy
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from django.utils import timezone
from django.core.cache import cache

from apps.forensics.models import (
    Alert,
    AnomalyRecord,
    Case,
    CaseAnalysisSnapshot,
    CustodyLedgerEvent,
    ProcessingJob,
    Report,
    SessionSummary,
)
from common.custody import custody_event_dict, verify_case_ledger


SNAPSHOT_SCHEMA_VERSION = "case-workspace-v1"
NO_DATA_FOUND = "No data found in this evidence file."
CASE_LIST_CACHE_VERSION_KEY = "netra:cases:list-version"


def case_list_cache_version() -> str:
    return str(cache.get(CASE_LIST_CACHE_VERSION_KEY) or "1")


def bump_case_list_cache_version() -> None:
    cache.set(CASE_LIST_CACHE_VERSION_KEY, str(timezone.now().timestamp()), timeout=None)


def analysis_status_for_case(case: Case) -> dict[str, Any]:
    jobs = sorted(case.processing_jobs.all(), key=lambda row: (row.created_at, row.updated_at), reverse=True)
    sessions = sorted(case.upload_sessions.all(), key=lambda row: (row.created_at, row.updated_at), reverse=True)
    evidence_files = sorted(case.evidence_files.all(), key=lambda row: (row.created_at, row.updated_at), reverse=True)
    job = jobs[0] if jobs else None
    session = sessions[0] if sessions else None

    if job is not None:
        state = job.status
        progress = max(0, min(100, job.progress or 0))
        step = job.step or job.status
        error = job.error_message or ""
    elif session is not None:
        state = {
            "created": "accepted",
            "uploading": "uploading",
            "uploaded": "finalizing",
            "finalized": "finalizing",
            "queued": "queued",
            "processing": "running",
            "completed": "completed",
            "failed": "failed",
            "canceled": "canceled",
            "expired": "expired",
        }.get(session.status, "accepted")
        progress = 100 if state == "completed" else 0
        step = session.status
        error = session.failure_code or ""
    elif evidence_files:
        state = "completed" if evidence_files[0].status == "verified" else "no-evidence"
        progress = 100 if state == "completed" else 0
        step = evidence_files[0].status
        error = ""
    else:
        state = "no-evidence"
        progress = 0
        step = "waiting_for_evidence"
        error = ""

    latest_evidence_verified = bool(evidence_files and evidence_files[0].status == "verified")
    report_eligible = bool(job and job.status == ProcessingJob.Status.COMPLETED and latest_evidence_verified and hasattr(case, "analysis_snapshot"))
    if report_eligible:
        blocked_reason = ""
    elif state in {"failed", "canceled", "expired"}:
        blocked_reason = "Resolve the evidence processing failure before generating a report."
    elif state == "no-evidence":
        blocked_reason = "Add and analyze evidence before generating a report."
    else:
        blocked_reason = "Report generation becomes available after analysis completes."

    return {
        "uploadSessionId": str(session.id) if session else "",
        "jobId": job.id if job else "",
        "state": state,
        "progress": progress,
        "step": step,
        "steps": job.steps if job else [],
        "error": error,
        "lastProgressAt": job.last_progress_at.isoformat() if job and job.last_progress_at else None,
        "startedAt": job.started_at.isoformat() if job and job.started_at else None,
        "completedAt": job.completed_at.isoformat() if job and job.completed_at else None,
        "reportEligible": report_eligible,
        "reportBlockedReason": blocked_reason,
    }


def _with_runtime_status(case: Case, payload: dict[str, Any]) -> dict[str, Any]:
    output = deepcopy(payload)
    status = analysis_status_for_case(case)
    output["routeRef"] = str(case.route_ref)
    output["analysisStatus"] = status
    output["reportEligible"] = status["reportEligible"]
    output["reportBlockedReason"] = status["reportBlockedReason"]
    workspace_case = output.get("workspace", {}).get("case")
    if isinstance(workspace_case, dict):
        workspace_case.update({
            "routeRef": str(case.route_ref),
            "status": case.status,
            "reportStatus": case.report_status,
            "analysisStatus": status,
            "reportEligible": status["reportEligible"],
            "reportBlockedReason": status["reportBlockedReason"],
        })
    return output


def workspace_for_case(case: Case) -> dict[str, Any]:
    cache_key = f"netra:case-workspace:{case.id}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return _with_runtime_status(case, cached)
    snapshot = getattr(case, "analysis_snapshot", None)
    if snapshot and snapshot.snapshot_json:
        payload = {
            "caseId": case.id,
            "snapshotVersion": snapshot.schema_version,
            "generatedAt": snapshot.generated_at.isoformat(),
            "source": "case_analysis_snapshot",
            "dataCompleteness": snapshot.snapshot_json.get("dataCompleteness", "complete"),
            "workspace": snapshot.snapshot_json,
        }
        cache.set(cache_key, payload, timeout=60)
        return _with_runtime_status(case, payload)
    job = ProcessingJob.objects.filter(case=case, status=ProcessingJob.Status.COMPLETED).order_by("-updated_at").first()
    snapshot = refresh_case_workspace_snapshot(case, job=job)
    payload = {
        "caseId": case.id,
        "snapshotVersion": snapshot.schema_version,
        "generatedAt": snapshot.generated_at.isoformat(),
        "source": "generated-on-read",
        "dataCompleteness": snapshot.snapshot_json.get("dataCompleteness", "complete"),
        "workspace": snapshot.snapshot_json,
    }
    cache.set(cache_key, payload, timeout=60)
    return _with_runtime_status(case, payload)


def refresh_case_workspace_snapshot(case: Case, job: ProcessingJob | None = None, analysis: dict[str, Any] | None = None) -> CaseAnalysisSnapshot:
    if job is None:
        job = ProcessingJob.objects.filter(case=case, status=ProcessingJob.Status.COMPLETED).order_by("-updated_at").first()
    if analysis is None and job is not None:
        raw = job.stats.get("analysis") if isinstance(job.stats, dict) else None
        analysis = raw if isinstance(raw, dict) else {}
    snapshot_json = build_case_workspace_snapshot(case, job=job, analysis=analysis or {})
    snapshot, _ = CaseAnalysisSnapshot.objects.update_or_create(
        case=case,
        defaults={
            "processing_job": job,
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "snapshot_json": snapshot_json,
            "generated_at": timezone.now(),
        },
    )
    cache.delete(f"netra:case-workspace:{case.id}")
    cache.delete(f"netra:case-workspace-response:{case.id}")
    bump_case_list_cache_version()
    return snapshot


def build_case_workspace_snapshot(case: Case, job: ProcessingJob | None, analysis: dict[str, Any]) -> dict[str, Any]:
    packets = _as_list(analysis.get("packets"))
    sessions = _as_list(analysis.get("sessions")) or _session_rows(case)
    alerts = _as_list(analysis.get("alerts")) or _alert_rows(case)
    anomalies = _as_list(analysis.get("anomalies")) or _anomaly_rows(case)
    decoded_protocols = _as_list(analysis.get("decodedProtocols"))
    payload_clues = _as_list(analysis.get("payloadFindings"))
    graph_data = analysis.get("graph") if isinstance(analysis.get("graph"), dict) else {"nodes": [], "edges": []}
    reports = [_report_payload(report) for report in Report.objects.filter(case=case).order_by("-created_at")[:50]]
    custody_rows = [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("-created_at", "-id")[:20]]
    custody_verification = verify_case_ledger(case) if CustodyLedgerEvent.objects.filter(case=case).exists() else {"verified": False, "eventCount": 0, "latestHash": ""}
    timeline = _timeline(analysis, packets, alerts, anomalies, custody_rows)
    protocol_chart = _chart(analysis.get("protocolChartData")) or _count_chart(packets, "protocol") or _count_chart(sessions, "protocol")
    summary = analysis.get("summary") if isinstance(analysis.get("summary"), dict) else {}
    alert_count = len(alerts)
    anomaly_count = len(anomalies)
    packet_count = int(summary.get("packets") or len(packets) or sum(_to_int(row.get("packetCount")) for row in sessions))
    session_count = int(summary.get("sessions") or len(sessions))
    available_tabs = {
        "overview": True,
        "suspiciousActivity": bool(alerts or anomalies),
        "trafficEvidence": bool(packets or sessions or decoded_protocols or payload_clues or graph_data.get("edges")),
        "timeline": bool(timeline),
        "reports": True,
        "custody": bool(case.evidence_files.exists() or custody_rows),
    }
    return {
        "dataCompleteness": analysis.get("searchCompleteness") or (job.completeness_status if job else "complete"),
        "case": _case_payload(case, analysis, reports),
        "evidence": _evidence_payload(case),
        "summary": {
            "packets": packet_count,
            "observedPackets": summary.get("observedPackets", packet_count),
            "indexedPackets": summary.get("indexedPackets", packet_count),
            "packetMetadataLimit": summary.get("packetMetadataLimit", 5000),
            "searchCompleteness": summary.get("searchCompleteness") or analysis.get("searchCompleteness", "complete"),
            "sessions": session_count,
            "protocolsDecoded": int(summary.get("protocolsDecoded") or len(decoded_protocols) or len(protocol_chart)),
            "payloadFindings": int(summary.get("payloadFindings") or len(payload_clues)),
            "alerts": int(summary.get("alerts") or alert_count),
            "anomalies": int(summary.get("anomalies") or anomaly_count),
            "topAttackClass": analysis.get("topAttackClass") or summary.get("topAttackClass") or _top_attack(alerts),
            "riskLevel": analysis.get("riskLevel") or summary.get("riskLevel") or _risk_level(alerts),
            "toolStatus": summary.get("toolStatus", {}),
            "zeek": _compact_zeek(analysis.get("zeek") or summary.get("zeek")),
        },
        "charts": {
            "severity": _count_chart(alerts, "severity"),
            "attackClasses": _count_chart(alerts, "attackClass"),
            "protocols": protocol_chart,
            "topSources": _count_chart(packets, "sourceIp") or _count_chart(sessions, "source"),
            "topDestinations": _count_chart(packets, "destinationIp") or _count_chart(sessions, "destination"),
            "timeline": timeline,
            "packetSessionSummary": {"packets": packet_count, "sessions": session_count, "alerts": alert_count, "anomalies": anomaly_count},
            "evidenceVerified": bool((analysis.get("evidence") or {}).get("manifestHash") or case.evidence_files.exists()),
            "dataQuality": _data_quality(packets, sessions, summary),
        },
        "suspiciousActivity": {
            "alerts": alerts[:100],
            "anomalies": anomalies[:100],
            "trafficPattern": timeline,
            "explanation": _activity_explanation(alerts, anomalies),
        },
        "trafficEvidence": {
            "packetsPreview": [_packet_preview(row) for row in packets[:50]],
            "sessionsPreview": [_session_preview(row) for row in sessions[:25]],
            "protocols": decoded_protocols or _protocol_rows(protocol_chart, sessions),
            "payloadClues": payload_clues[:50],
            "communicationMap": _compact_graph(graph_data),
        },
        "reports": {
            "latestReport": reports[0] if reports else None,
            "items": reports,
        },
        "custody": {
            "status": "verified" if custody_verification.get("verified") else "pending",
            "verification": custody_verification,
            "eventCount": custody_verification.get("eventCount", len(custody_rows)),
            "latestHash": custody_verification.get("latestHash", ""),
            "eventsPreview": custody_rows,
        },
        "availableTabs": available_tabs,
        "dataMessages": _data_messages(available_tabs),
        "generatedFrom": {
            "jobId": job.id if job else "",
            "analysisCreatedAt": analysis.get("createdAt", ""),
            "schemaVersion": SNAPSHOT_SCHEMA_VERSION,
        },
    }


def _case_payload(case: Case, analysis: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    evidence = case.evidence_files.order_by("-created_at").first()
    links = [
        {"id": link.id, "caseId": link.target_case_id, "caseTitle": link.target_case.title, "relationType": link.relation_type, "notes": link.notes}
        for link in case.outgoing_links.select_related("target_case").order_by("-created_at")[:20]
    ]
    history = [
        {"id": f"hist-{event.id}", "timestamp": event.created_at.isoformat(), "actor": event.actor_name, "action": event.action, "details": event.details}
        for event in case.history.order_by("-created_at")[:20]
    ]
    return {
        "id": case.id,
        "routeRef": str(case.route_ref),
        "title": case.title,
        "investigator": case.investigator,
        "department": case.department,
        "status": case.status,
        "priority": case.priority,
        "origin": case.origin,
        "isTest": case.is_test,
        "openedAt": case.opened_at.isoformat() if case.opened_at else case.created_at.isoformat(),
        "closedAt": case.closed_at.isoformat() if case.closed_at else "",
        "sourceLocation": case.source_location,
        "remarks": case.remarks,
        "flags": case.flags_json if isinstance(case.flags_json, list) else [],
        "linkedCases": links,
        "evidenceFileId": evidence.id if evidence else "",
        "evidenceFilename": evidence.filename if evidence else "",
        "alertIds": [alert.get("id") for alert in _as_list(analysis.get("alerts"))],
        "notes": [event["details"] for event in history[:8]],
        "history": history,
        "createdAt": case.created_at.isoformat(),
        "reportStatus": case.report_status,
        "riskLevel": analysis.get("riskLevel", "low"),
        "topAttackClass": analysis.get("topAttackClass", "Normal Baseline"),
        "alertCount": len(_as_list(analysis.get("alerts"))),
        "packetCount": (analysis.get("summary") or {}).get("packets", len(_as_list(analysis.get("packets")))),
        "sessionCount": (analysis.get("summary") or {}).get("sessions", len(_as_list(analysis.get("sessions")))),
        "latestReportId": reports[0]["id"] if reports else "",
        "latestReportDownloadUrl": reports[0]["downloadUrl"] if reports else "",
        "updatedAt": case.updated_at.isoformat(),
    }


def _evidence_payload(case: Case) -> dict[str, Any] | None:
    evidence = case.evidence_files.order_by("-created_at").first()
    if not evidence:
        return None
    manifest = getattr(evidence, "manifest", None)
    return {
        "id": evidence.id,
        "filename": evidence.filename,
        "size": f"{round(evidence.size_bytes / (1024 * 1024), 2)} MB",
        "sha256": evidence.sha256,
        "plaintextSha256": manifest.plaintext_sha256 if manifest else evidence.sha256,
        "encryptedSha256": manifest.encrypted_sha256 if manifest else "",
        "manifestHash": manifest.manifest_hash if manifest else "",
        "keyId": manifest.key_id if manifest else "",
        "uploadedAt": evidence.created_at.isoformat(),
        "capturedAt": evidence.captured_at.isoformat() if evidence.captured_at else evidence.created_at.isoformat(),
        "investigator": evidence.uploaded_by,
        "status": evidence.status,
    }


def _compact_zeek(zeek: Any) -> dict[str, Any] | None:
    if not isinstance(zeek, dict):
        return None
    logs = zeek.get("logs")
    log_summary = []
    if isinstance(logs, dict):
        for name, rows in list(logs.items())[:12]:
            log_summary.append({"name": name, "count": len(rows) if isinstance(rows, list) else 0})
    return {
        "status": zeek.get("status") or ("available" if log_summary else "not_available"),
        "logSummary": log_summary,
        "warning": zeek.get("warning") or zeek.get("error") or "",
    }


def _packet_preview(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "timestamp": row.get("timestamp"),
        "sourceIp": row.get("sourceIp"),
        "destinationIp": row.get("destinationIp"),
        "sourcePort": row.get("sourcePort"),
        "destinationPort": row.get("destinationPort"),
        "protocol": row.get("protocol"),
        "size": row.get("size"),
        "severity": row.get("severity"),
        "riskScore": row.get("riskScore"),
        "sessionId": row.get("sessionId"),
        "relatedAlertId": row.get("relatedAlertId"),
        "decodedSummary": row.get("decodedSummary"),
        "dnsQuery": row.get("dnsQuery"),
        "httpHost": row.get("httpHost"),
        "sni": row.get("sni"),
    }


def _session_preview(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "source": row.get("source"),
        "destination": row.get("destination"),
        "protocol": row.get("protocol"),
        "startTime": row.get("startTime"),
        "endTime": row.get("endTime"),
        "duration": row.get("duration"),
        "packetCount": row.get("packetCount"),
        "bytesSent": row.get("bytesSent"),
        "bytesReceived": row.get("bytesReceived"),
        "riskScore": row.get("riskScore"),
        "relatedAlertIds": row.get("relatedAlertIds", []),
    }


def _alert_rows(case: Case) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "severity": row.severity,
            "attackClass": row.attack_class,
            "type": row.alert_type,
            "sourceIp": row.source_ip,
            "destination": row.destination,
            "protocol": row.protocol,
            "timestamp": row.event_timestamp.isoformat() if row.event_timestamp else row.created_at.isoformat(),
            "confidence": row.confidence,
            "status": row.status,
            "ruleId": row.rule_id,
            "evidencePacketIds": row.evidence_packet_ids,
            "evidenceSessionIds": row.evidence_session_ids,
            "explanation": row.explanation,
            "recommendedAction": row.recommended_action,
        }
        for row in Alert.objects.filter(case=case).order_by("-created_at")[:500]
    ]


def _anomaly_rows(case: Case) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "entity": row.entity,
            "behaviour": row.behaviour,
            "baseline": row.baseline,
            "observed": row.observed,
            "deviation": row.deviation,
            "confidence": row.confidence,
            "hypothesis": row.hypothesis,
            "topFeatures": row.top_features,
            "recommendedAction": row.recommended_action,
            "modelVersion": row.model_version,
        }
        for row in AnomalyRecord.objects.filter(case=case).order_by("-created_at")[:500]
    ]


def _session_rows(case: Case) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "source": row.source,
            "destination": row.destination,
            "protocol": row.protocol,
            "startTime": row.start_time.isoformat() if row.start_time else "",
            "endTime": row.end_time.isoformat() if row.end_time else "",
            "duration": f"{round(row.duration_ms / 1000, 2)}s" if row.duration_ms else "",
            "bytesSent": row.bytes_sent,
            "bytesReceived": row.bytes_received,
            "packetCount": row.packet_count,
            "riskScore": row.risk_score,
            "relatedAlertIds": row.related_alert_ids,
        }
        for row in SessionSummary.objects.filter(case=case).order_by("-risk_score", "-packet_count")[:500]
    ]


def _report_payload(report: Report) -> dict[str, Any]:
    filename = report.id.removesuffix(".enc")
    return {
        "id": report.id,
        "caseId": report.case_id,
        "caseTitle": report.case.title if report.case_id else "",
        "caseStatus": report.case.status if report.case_id else "",
        "openedAt": report.case.opened_at.isoformat() if report.case_id and report.case.opened_at else report.case.created_at.isoformat() if report.case_id else "",
        "closedAt": report.case.closed_at.isoformat() if report.case_id and report.case.closed_at else "",
        "title": f"{report.case_id} forensic report" if report.case_id else filename,
        "language": report.language,
        "format": "PDF" if filename.lower().endswith(".pdf") else "HTML",
        "status": report.status,
        "generatedBy": report.generated_by,
        "generatedAt": report.created_at.isoformat(),
        "sha256": report.sha256,
        "filename": filename,
        "downloadUrl": f"/api/reports/{report.id}/download",
    }


def _count_chart(rows: list[dict[str, Any]], key: str, limit: int = 8) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for row in rows:
        value = str(row.get(key) or "").strip()
        if value:
            counts[value] += 1
    return [{"name": name, "value": count} for name, count in counts.most_common(limit)]


def _chart(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows = []
    for item in value:
        if isinstance(item, dict) and ("name" in item or "protocol" in item):
            rows.append({"name": str(item.get("name") or item.get("protocol")), "value": _to_int(item.get("value") or item.get("count") or item.get("packetCount"))})
    return rows


def _timeline(analysis: dict[str, Any], packets: list[dict[str, Any]], alerts: list[dict[str, Any]], anomalies: list[dict[str, Any]], custody_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    existing = _as_list(analysis.get("trafficTimeline"))
    if existing:
        return existing[:48]
    buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {"time": "", "alerts": 0, "packets": 0, "anomalies": 0, "mb": 0})
    for packet in packets[:1000]:
        label = _time_label(packet.get("timestamp"))
        if not label:
            continue
        buckets[label]["time"] = label
        buckets[label]["packets"] += 1
        buckets[label]["mb"] += round(_to_int(packet.get("size")) / (1024 * 1024), 4)
    for alert in alerts:
        label = _time_label(alert.get("timestamp"))
        if not label:
            continue
        buckets[label]["time"] = label
        buckets[label]["alerts"] += 1
    for anomaly in anomalies:
        label = _time_label(anomaly.get("timestamp") or anomaly.get("createdAt"))
        if not label:
            continue
        buckets[label]["time"] = label
        buckets[label]["anomalies"] += 1
    if not buckets:
        for event in custody_rows:
            label = _time_label(event.get("timestamp"))
            if not label:
                continue
            buckets[label]["time"] = label
            buckets[label]["events"] = buckets[label].get("events", 0) + 1
    return [buckets[key] for key in sorted(buckets.keys())[:48]]


def _compact_graph(graph_data: dict[str, Any]) -> dict[str, Any]:
    edges = _as_list(graph_data.get("edges"))[:100]
    nodes = _as_list(graph_data.get("nodes"))[:100]
    return {"nodes": nodes, "edges": edges}


def _protocol_rows(protocol_chart: list[dict[str, Any]], sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    session_counts = Counter(str(row.get("protocol") or "unknown") for row in sessions if row.get("protocol"))
    return [
        {
            "protocol": row["name"],
            "packetCount": row["value"],
            "sessionCount": session_counts.get(row["name"], 0),
            "suspiciousCount": 0,
            "status": "metadata-only",
            "topDestination": "",
            "detail": "Protocol summary derived from stored packet/session metadata.",
        }
        for row in protocol_chart
    ]


def _data_quality(packets: list[dict[str, Any]], sessions: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    if packets:
        if summary.get("searchCompleteness") == "truncated-search-index":
            return "Sampled packet metadata"
        return "Full packet metadata"
    if sessions:
        return "Session-derived chart"
    return NO_DATA_FOUND


def _data_messages(available_tabs: dict[str, bool]) -> dict[str, str]:
    return {
        "overview": NO_DATA_FOUND,
        "suspiciousActivity": "No suspicious activity found in this evidence file." if not available_tabs["suspiciousActivity"] else "",
        "trafficEvidence": NO_DATA_FOUND if not available_tabs["trafficEvidence"] else "",
        "timeline": "No timeline data found in this evidence file." if not available_tabs["timeline"] else "",
        "anomalyReview": "No unusual behavioral patterns were detected in this evidence file.",
        "chart": NO_DATA_FOUND,
        "custody": "No custody events found for this case yet.",
    }


def _activity_explanation(alerts: list[dict[str, Any]], anomalies: list[dict[str, Any]]) -> str:
    if alerts:
        top = alerts[0]
        return top.get("explanation") or f"Netra found {len(alerts)} suspicious activity item(s). Review the highest severity alerts first."
    if anomalies:
        return f"Netra found {len(anomalies)} unusual behavior pattern(s). Review the top contributing features before drawing conclusions."
    return "No suspicious activity found in this evidence file."


def _top_attack(alerts: list[dict[str, Any]]) -> str:
    chart = _count_chart(alerts, "attackClass", 1)
    return chart[0]["name"] if chart else "Normal Baseline"


def _risk_level(alerts: list[dict[str, Any]]) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest = "low"
    for alert in alerts:
        severity = str(alert.get("severity") or "low").lower()
        if rank.get(severity, 0) > rank.get(highest, 0):
            highest = severity
    return highest


def _time_label(value: Any) -> str:
    if not value:
        return ""
    text = str(value)
    if "T" in text and len(text) >= 16:
        return text[11:16]
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%H:%M")
    except ValueError:
        return text[:16]


def _to_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []
