from __future__ import annotations

from typing import Any

from common.search import index_document, search_documents


INDEXES = {
    "packets": "netra-packets-v1",
    "sessions": "netra-sessions-v1",
    "protocols": "netra-protocols-v1",
    "payloads": "netra-payloads-v1",
    "alerts": "netra-alert-search-v1",
    "zeek": "netra-zeek-v1",
}


def index_analysis(analysis: dict[str, Any]) -> dict[str, int]:
    case_id = analysis.get("caseId", "")
    evidence_id = analysis.get("evidenceId", "")
    job_id = analysis.get("jobId", "")
    counts = {key: 0 for key in INDEXES}
    for packet in analysis.get("packets", []):
        doc = packet | {"caseId": case_id, "evidenceId": evidence_id, "jobId": job_id}
        if index_document(INDEXES["packets"], f"{case_id}-{packet['id']}", doc):
            counts["packets"] += 1
    for session in analysis.get("sessions", []):
        doc = session | {"caseId": case_id, "evidenceId": evidence_id, "jobId": job_id}
        if index_document(INDEXES["sessions"], f"{case_id}-{session['id']}", doc):
            counts["sessions"] += 1
    for protocol in analysis.get("decodedProtocols", []):
        doc = protocol | {"caseId": case_id, "evidenceId": evidence_id, "jobId": job_id}
        if index_document(INDEXES["protocols"], f"{case_id}-{protocol['protocol']}", doc):
            counts["protocols"] += 1
    for payload in analysis.get("payloadFindings", []):
        doc = payload | {"caseId": case_id, "evidenceId": evidence_id, "jobId": job_id}
        if index_document(INDEXES["payloads"], f"{case_id}-{payload['id']}", doc):
            counts["payloads"] += 1
    for alert in analysis.get("alerts", []):
        doc = alert | {"caseId": case_id, "evidenceId": evidence_id, "jobId": job_id}
        if index_document(INDEXES["alerts"], f"{case_id}-{alert['id']}", doc):
            counts["alerts"] += 1
    zeek = analysis.get("zeek", {})
    for log_name, rows in (zeek.get("records") or {}).items():
        for index, row in enumerate(rows[:200]):
            doc = row | {"caseId": case_id, "evidenceId": evidence_id, "jobId": job_id, "zeekLogType": log_name}
            if index_document(INDEXES["zeek"], f"{case_id}-{job_id}-{log_name}-{index}", doc):
                counts["zeek"] += 1
    return counts


def search_index(kind: str, case_id: str = "", query_text: str = "", fallback: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], str]:
    index = INDEXES.get(kind, INDEXES["packets"])
    filters = []
    if case_id:
        filters.append({"term": {"caseId.keyword": case_id}})
    if query_text:
        query = {"bool": {"must": [{"query_string": {"query": f"*{query_text}*", "fields": ["*"], "default_operator": "AND"}}], "filter": filters}}
    else:
        query = {"bool": {"must": [{"match_all": {}}], "filter": filters}}
    rows = search_documents(index, query, fallback or [])
    if fallback is not None and rows == fallback:
        return rows, "fallback"
    return rows, "elasticsearch"
