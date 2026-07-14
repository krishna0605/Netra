from __future__ import annotations

import json
from uuid import uuid4

from apps.forensics.models import Case, CustodyLedgerEvent
from common.analysis import build_alert_csv, build_evidence_bundle, build_report_html, empty_analysis
from common.audit import Actor
from common.custody import custody_event_dict, verify_case_ledger
from common.persistence import record_export, record_report
from common.pdf_report import build_report_pdf
from common.readiness import legal_review_checklist
from common.storage import write_binary_artifact, write_text_artifact


def report_analysis_from_snapshot(case: Case) -> dict:
    snapshot = getattr(case, "analysis_snapshot", None)
    workspace = snapshot.snapshot_json if snapshot and isinstance(snapshot.snapshot_json, dict) else {}
    if not workspace:
        return {}
    summary = workspace.get("summary") if isinstance(workspace.get("summary"), dict) else {}
    suspicious = workspace.get("suspiciousActivity") if isinstance(workspace.get("suspiciousActivity"), dict) else {}
    traffic = workspace.get("trafficEvidence") if isinstance(workspace.get("trafficEvidence"), dict) else {}
    return {
        "caseId": case.id,
        "case": workspace.get("case") or {},
        "evidence": workspace.get("evidence") or {},
        "summary": summary,
        "topAttackClass": summary.get("topAttackClass", "Normal Baseline"),
        "riskLevel": summary.get("riskLevel", "low"),
        "toolStatus": summary.get("toolStatus", {}),
        "zeek": summary.get("zeek") or {},
        "alerts": suspicious.get("alerts") or [],
        "anomalies": suspicious.get("anomalies") or [],
        "detectionMatches": suspicious.get("detectionMatches") or [],
        "trafficTimeline": suspicious.get("trafficPattern") or [],
        "packets": traffic.get("packetsPreview") or [],
        "sessions": traffic.get("sessionsPreview") or [],
        "decodedProtocols": traffic.get("protocols") or [],
        "payloadFindings": traffic.get("payloadClues") or [],
        "graph": traffic.get("communicationMap") or {"nodes": [], "edges": []},
    }


def _artifact_analysis(case_id: str, analysis: dict, case: Case | None = None) -> dict:
    if not analysis:
        analysis = empty_analysis()
        analysis["caseId"] = case_id
    enriched = json.loads(json.dumps(analysis))
    case = case or Case.objects.filter(id=case_id).first()
    if not case:
        return enriched
    evidence = case.evidence_files.select_related("manifest").order_by("-created_at").first()
    if evidence:
        manifest = getattr(evidence, "manifest", None)
        enriched["evidence"] = {
            **(enriched.get("evidence") or {}),
            "id": evidence.id,
            "filename": evidence.filename,
            "sha256": evidence.sha256,
            "status": evidence.status,
            "storedPath": evidence.stored_path,
            "uploadedAt": evidence.created_at.isoformat(),
            "capturedAt": evidence.captured_at.isoformat() if evidence.captured_at else evidence.created_at.isoformat(),
        }
        if manifest:
            enriched["evidence"].update(
                {
                    "plaintextSha256": manifest.plaintext_sha256,
                    "encryptedSha256": manifest.encrypted_sha256,
                    "manifestHash": manifest.manifest_hash,
                    "keyId": manifest.key_id,
                    "encryptionAlgorithm": manifest.encryption_algorithm,
                    "storageUri": manifest.storage_uri,
                    "manifest": manifest.manifest_json,
                }
            )
            if manifest.manifest_json.get("normalization") and not enriched.get("normalization"):
                enriched["normalization"] = manifest.manifest_json["normalization"]
                enriched["evidence"]["normalization"] = manifest.manifest_json["normalization"]
    enriched["custodyLedger"] = {
        "verification": verify_case_ledger(case),
        "events": [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("created_at", "id")],
    }
    return enriched


def generate_report_artifact(case_id: str, language: str, analysis: dict, actor: Actor, filename: str | None = None) -> dict:
    case = Case.objects.filter(id=case_id).first()
    analysis = _artifact_analysis(case_id, analysis, case)
    custody = (analysis.get("custodyLedger") or {}).get("verification", {})
    legal = legal_review_checklist(case) if case else {"status": "unavailable", "items": []}
    legal_items = "".join(
        f"<li><strong>{item['name']}</strong>: {item['status']} - {item['detail']}</li>"
        for item in legal.get("items", [])
    )
    html = build_report_html(analysis, language).replace(
        "</body>",
        f"<section><h2>Custody Ledger</h2><p>Verified: {custody.get('verified')} | Events: {custody.get('eventCount')} | Latest hash: {custody.get('latestHash','')}</p></section>"
        f"<section><h2>Legal Review Checklist</h2><p>Status: {legal.get('status')}</p><ul>{legal_items}</ul></section></body>",
    )
    artifact = write_text_artifact(html, "report", filename or f"{case_id}-{language}.html")
    record_report(case_id, artifact, language, actor)
    return {"id": artifact["filename"], **artifact}


def generate_pdf_report_artifact(case_id: str, language: str, analysis: dict, actor: Actor, filename: str | None = None) -> dict:
    case = Case.objects.filter(id=case_id).first()
    enriched = _artifact_analysis(case_id, analysis, case)
    custody = (enriched.get("custodyLedger") or {}).get("verification", {})
    legal = legal_review_checklist(case) if case else {"status": "unavailable", "items": []}
    pdf_bytes = build_report_pdf(enriched, language, legal, custody)
    artifact = write_binary_artifact(pdf_bytes, "report", filename or f"{case_id}-{language}.pdf")
    record_report(case_id, artifact, f"{language}-pdf", actor)
    return {"id": artifact["filename"], "format": "pdf", **artifact}


def generate_export_artifact(case_id: str, export_type: str, analysis: dict, actor: Actor, export_id: str | None = None) -> dict:
    export_id = export_id or f"exp-{uuid4().hex[:8]}"
    normalized_type = (export_type or "json").lower()
    analysis = _artifact_analysis(case_id, analysis)
    if "csv" in normalized_type or "alert" in normalized_type:
        filename = f"{export_id}-alerts.csv"
        content = build_alert_csv(analysis)
    else:
        filename = f"{export_id}-evidence.json"
        bundle = json.loads(build_evidence_bundle(analysis))
        content = json.dumps(bundle, indent=2)
    artifact = write_text_artifact(content, "export", filename)
    record_export(case_id, export_id, normalized_type, artifact, actor)
    return {"id": export_id, "type": normalized_type, **artifact}
