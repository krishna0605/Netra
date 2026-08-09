from __future__ import annotations

import csv
import html
import json
from io import StringIO
from typing import Any


def build_report_html(analysis: dict[str, Any], language: str = "en") -> str:
    evidence = analysis.get("evidence") or {}
    summary = analysis.get("summary", {})
    alerts = analysis.get("alerts", [])[:10]
    anomalies = analysis.get("anomalies", [])[:5]
    custody = analysis.get("chainOfCustody", [])
    ledger = analysis.get("custodyLedger", {}).get("verification", {})
    zeek = analysis.get("zeek", {})
    normalization = analysis.get("normalization") or evidence.get("normalization") or {}
    rows = "".join(
        f"<tr><td>{html.escape(alert['severity'])}</td><td>{html.escape(alert['attackClass'])}</td>"
        f"<td>{html.escape(alert['sourceIp'])}</td><td>{html.escape(alert['destination'])}</td>"
        f"<td>{alert['confidence']}%</td></tr>"
        for alert in alerts
    )
    anomaly_items = "".join(
        f"<li><strong>{html.escape(item['entity'])}</strong>: {html.escape(item['observed'])} "
        f"vs {html.escape(item['baseline'])} ({item['confidence']}%)</li>"
        for item in anomalies
    )
    custody_items = "".join(
        f"<li>{html.escape(item['timestamp'])} - {html.escape(item['action'])} - "
        f"{html.escape(item['hash'])}</li>"
        for item in custody
    )
    zeek_summary = ", ".join(f"{key}: {value}" for key, value in (zeek.get("summary") or {}).items())
    return f"""<!doctype html>
<html lang="{html.escape(language)}">
<head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Netra forensic report {html.escape(analysis.get('caseId', ''))}</title>
<style>body{{font-family:Arial,sans-serif;line-height:1.5;margin:32px;color:#17202a}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd;padding:8px;text-align:left}}section{{margin:24px 0}}code{{word-break:break-all}}</style></head>
<body>
<h1>Forensic Network Investigation Report</h1>
<p><strong>Case:</strong> {html.escape(analysis.get('caseId', ''))} | <strong>Top class:</strong> {html.escape(analysis.get('topAttackClass', 'Normal Baseline'))} | <strong>Risk:</strong> {html.escape(analysis.get('riskLevel', 'low'))}</p>
<section><h2>Evidence Metadata</h2><p>File: {html.escape(evidence.get('filename', ''))}<br>Plain SHA-256: <code>{html.escape(evidence.get('plaintextSha256') or evidence.get('sha256', ''))}</code><br>Encrypted SHA-256: <code>{html.escape(evidence.get('encryptedSha256', ''))}</code><br>Manifest hash: <code>{html.escape(evidence.get('manifestHash', ''))}</code><br>Key ID: {html.escape(evidence.get('keyId', ''))}<br>Uploaded: {html.escape(evidence.get('uploadedAt', ''))}</p></section>
<section><h2>Evidence Normalization</h2><p>Selected type: {html.escape(str(normalization.get('selectedType', '')))}<br>Detected type: {html.escape(str(normalization.get('detectedType', '')))}<br>Normalized type: {html.escape(str(normalization.get('normalizedType', '')))}<br>Confidence: {html.escape(str(normalization.get('confidence', '')))}%<br>Parser used: {html.escape(str(normalization.get('parser', '')))}<br>Signals: {html.escape(', '.join(normalization.get('signals') or normalization.get('features', {}).get('sampleSignals', [])))}</p></section>
<section><h2>Packet Capture Summary</h2><p>Packets: {summary.get('packets', 0)} | Sessions: {summary.get('sessions', 0)} | Alerts: {summary.get('alerts', 0)} | Anomalies: {summary.get('anomalies', 0)}</p></section>
<section><h2>Tooling Status</h2><p>{html.escape(json.dumps(analysis.get('toolStatus', {})))}</p></section>
<section><h2>Zeek Evidence</h2><p>Status: {html.escape(zeek.get('status', 'unknown'))}<br>{html.escape(zeek_summary)}<br>Logs: {html.escape(', '.join(zeek.get('logs', [])))}</p></section>
<section><h2>Alerts and Attack Classification</h2><table><thead><tr><th>Severity</th><th>Class</th><th>Source</th><th>Destination</th><th>Confidence</th></tr></thead><tbody>{rows}</tbody></table></section>
<section><h2>AI-assisted Anomaly Summary</h2><ul>{anomaly_items or '<li>No high-confidence anomaly recorded.</li>'}</ul></section>
<section><h2>Chain of Custody</h2><ul>{custody_items}</ul></section>
<section><h2>Tamper-Evident Ledger</h2><p>Verified: {html.escape(str(ledger.get('verified', False)))} | Events: {ledger.get('eventCount', 0)} | Latest hash: <code>{html.escape(ledger.get('latestHash', ''))}</code></p></section>
<section><h2>Recommended Next Steps</h2><ol><li>Correlate alerts with endpoint, authentication, and server logs.</li><li>Preserve original PCAP and generated artifacts by hash.</li><li>Escalate confirmed high-risk findings to case investigators.</li></ol></section>
</body></html>"""


def build_evidence_bundle(analysis: dict[str, Any]) -> str:
    return json.dumps(
        {
            "caseId": analysis.get("caseId"),
            "evidence": analysis.get("evidence"),
            "summary": analysis.get("summary"),
            "topAttackClass": analysis.get("topAttackClass"),
            "riskLevel": analysis.get("riskLevel"),
            "alerts": analysis.get("alerts", []),
            "anomalies": analysis.get("anomalies", []),
            "sessions": analysis.get("sessions", []),
            "decodedProtocols": analysis.get("decodedProtocols", []),
            "payloadFindings": analysis.get("payloadFindings", []),
            "detectionMatches": analysis.get("detectionMatches", []),
            "features": analysis.get("features", {}),
            "normalization": analysis.get("normalization", {}),
            "toolStatus": analysis.get("toolStatus", {}),
            "graph": analysis.get("graph", {}),
            "zeek": analysis.get("zeek", {}),
            "chainOfCustody": analysis.get("chainOfCustody", []),
            "custodyLedger": analysis.get("custodyLedger", {}),
        },
        indent=2,
    )


def build_alert_csv(analysis: dict[str, Any]) -> str:
    handle = StringIO()
    writer = csv.DictWriter(
        handle,
        fieldnames=[
            "id",
            "severity",
            "attackClass",
            "type",
            "sourceIp",
            "destination",
            "protocol",
            "confidence",
            "status",
        ],
    )
    writer.writeheader()
    for alert in analysis.get("alerts", []):
        writer.writerow({key: alert.get(key, "") for key in writer.fieldnames})
    return handle.getvalue()
