from __future__ import annotations

import json
import re
from uuid import uuid4

from django.template.loader import render_to_string

from apps.forensics.models import Case, CustodyLedgerEvent
from common.analysis_contract import empty_analysis
from common.audit import Actor
from common.custody import custody_event_dict, verify_case_ledger
from common.persistence import record_export, record_report
from common.pdf_report import build_report_pdf
from common.readiness import legal_review_checklist
from common.safe_paths import generated_artifact_filename, validate_artifact_filename
from common.storage import write_binary_artifact, write_text_artifact


REPORT_BODY_MARKER = "</body>"
_SERVER_REPORT_ID = re.compile(r"^rpt-[0-9a-f]{32}\.(?:html|pdf)$")


def _report_filename(report_id: str | None, suffix: str) -> str:
    if report_id is None:
        return generated_artifact_filename("rpt", suffix)
    filename = validate_artifact_filename(report_id, allowed_extensions=frozenset({suffix}))
    if not _SERVER_REPORT_ID.fullmatch(filename):
        raise ValueError("Queued report ID is not a server-generated report identifier.")
    return filename


def _render_report_supplement(custody: dict, legal: dict) -> str:
    return render_to_string(
        "forensics/report_supplement.html",
        {
            "custody": {
                "verified": bool(custody.get("verified")),
                "event_count": int(custody.get("eventCount") or 0),
                "latest_hash": str(custody.get("latestHash") or ""),
            },
            "legal": {
                "status": str(legal.get("status") or "unavailable"),
                "items": [
                    {
                        "name": str(item.get("name") or ""),
                        "status": str(item.get("status") or ""),
                        "detail": str(item.get("detail") or ""),
                    }
                    for item in (legal.get("items") or [])
                    if isinstance(item, dict)
                ],
            },
        },
    )


def _insert_report_supplement(report_html: str, supplement: str) -> str:
    if report_html.count(REPORT_BODY_MARKER) != 1:
        raise ValueError("Generated report must contain exactly one closing body tag.")
    return report_html.replace(REPORT_BODY_MARKER, f"{supplement}\n{REPORT_BODY_MARKER}", 1)


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
        "events": [custody_event_dict(row) for row in CustodyLedgerEvent.objects.filter(case=case).order_by("chain_index")],
    }
    return enriched


def generate_report_artifact(
    case_id: str,
    language: str,
    analysis: dict,
    actor: Actor,
    *,
    report_id: str | None = None,
) -> dict:
    case = Case.objects.filter(id=case_id).first()
    analysis = _artifact_analysis(case_id, analysis, case)
    custody = (analysis.get("custodyLedger") or {}).get("verification", {})
    legal = legal_review_checklist(case) if case else {"status": "unavailable", "items": []}
    from common.report_rendering import build_report_html
    html = _insert_report_supplement(build_report_html(analysis, language), _render_report_supplement(custody, legal))
    artifact = write_text_artifact(
        html,
        "report",
        _report_filename(report_id, ".html"),
        case_id=case_id,
        artifact_id=report_id,
    )
    record_report(case_id, artifact, language, actor, case=case)
    return {"id": artifact["filename"], **artifact}


def generate_pdf_report_artifact(
    case_id: str,
    language: str,
    analysis: dict,
    actor: Actor,
    *,
    report_id: str | None = None,
) -> dict:
    case = Case.objects.filter(id=case_id).first()
    enriched = _artifact_analysis(case_id, analysis, case)
    custody = (enriched.get("custodyLedger") or {}).get("verification", {})
    legal = legal_review_checklist(case) if case else {"status": "unavailable", "items": []}
    pdf_bytes = build_report_pdf(enriched, language, legal, custody)
    artifact = write_binary_artifact(
        pdf_bytes,
        "report",
        _report_filename(report_id, ".pdf"),
        case_id=case_id,
        artifact_id=report_id,
    )
    record_report(case_id, artifact, f"{language}-pdf", actor, case=case)
    return {"id": artifact["filename"], "format": "pdf", **artifact}


def generate_export_artifact(case_id: str, export_type: str, analysis: dict, actor: Actor, export_id: str | None = None) -> dict:
    from common.report_rendering import build_alert_csv, build_evidence_bundle

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
    artifact = write_text_artifact(content, "export", filename, case_id=case_id, artifact_id=export_id)
    record_export(case_id, export_id, normalized_type, artifact, actor)
    return {"id": export_id, "type": normalized_type, **artifact}
