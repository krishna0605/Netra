from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from common.search import get_elasticsearch_client, index_documents, search_documents


ALIASES = {
    "packets": "netra-packets",
    "sessions": "netra-sessions",
    "protocols": "netra-protocols",
    "payloads": "netra-payloads",
    "alerts": "netra-alerts",
    "zeek": "netra-zeek",
    "live-packets": "netra-live-packets",
}

HIGH_VOLUME = {"packets", "protocols", "payloads", "zeek", "live-packets"}

MAPPINGS = {
    "properties": {
        "caseId": {"type": "keyword"},
        "evidenceId": {"type": "keyword"},
        "jobId": {"type": "keyword"},
        "sensorId": {"type": "keyword"},
        "captureJobId": {"type": "keyword"},
        "captureChunkId": {"type": "keyword"},
        "sessionId": {"type": "keyword"},
        "sourceIp": {"type": "ip", "ignore_malformed": True},
        "destinationIp": {"type": "ip", "ignore_malformed": True},
        "sourcePort": {"type": "integer", "ignore_malformed": True},
        "destinationPort": {"type": "integer", "ignore_malformed": True},
        "protocol": {"type": "keyword"},
        "attackClass": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "riskScore": {"type": "integer", "ignore_malformed": True},
        "timestamp": {"type": "date", "ignore_malformed": True},
        "provisional": {"type": "boolean"},
        "zeekLogType": {"type": "keyword"},
        "decodedSummary": {"type": "text"},
    }
}


def dated_index(kind: str) -> str:
    return f"{ALIASES[kind]}-v2-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"


def ensure_write_index(kind: str) -> str:
    index = dated_index(kind)
    alias = ALIASES[kind]
    client = get_elasticsearch_client()
    if not client.indices.exists(index=index):
        client.indices.create(index=index, mappings=MAPPINGS, aliases={alias: {}})
    return index


def bootstrap_search_resources() -> dict[str, list[str]]:
    client = get_elasticsearch_client()
    created, reused, failed = [], [], []
    for name, days in (("netra-high-volume-30d", 30), ("netra-investigation-90d", 90)):
        try:
            client.ilm.put_lifecycle(name=name, policy={"phases": {"hot": {"actions": {}}, "delete": {"min_age": f"{days}d", "actions": {"delete": {}}}}})
            created.append(f"ilm:{name}")
        except Exception as exc:
            failed.append(f"ilm:{name}:{exc}")
    for kind, alias in ALIASES.items():
        try:
            template_name = f"{alias}-template"
            policy = "netra-high-volume-30d" if kind in HIGH_VOLUME else "netra-investigation-90d"
            client.indices.put_index_template(
                name=template_name,
                index_patterns=[f"{alias}-v2-*"],
                template={"settings": {"index.lifecycle.name": policy}, "mappings": MAPPINGS},
                priority=200,
            )
            created.append(f"template:{template_name}")
            index = dated_index(kind)
            if client.indices.exists(index=index):
                reused.append(index)
            else:
                ensure_write_index(kind)
                created.append(index)
        except Exception as exc:
            failed.append(f"{kind}:{exc}")
    return {"created": created, "reused": reused, "failed": failed}


def _batch(kind: str, rows: list[tuple[str, dict[str, Any]]]) -> int:
    if not rows:
        return 0
    try:
        index = ensure_write_index(kind)
    except Exception:
        return 0
    return len(rows) if index_documents(index, rows) else 0


def index_analysis(analysis: dict[str, Any]) -> dict[str, int]:
    case_id = analysis.get("caseId", "")
    evidence_id = analysis.get("evidenceId", "")
    job_id = analysis.get("jobId", "")
    shared = {"caseId": case_id, "evidenceId": evidence_id, "jobId": job_id}
    packets = [(f"{case_id}-{row['id']}", row | shared) for row in analysis.get("packets", [])]
    sessions = [(f"{case_id}-{row['id']}", row | shared) for row in analysis.get("sessions", [])]
    protocols = [(f"{case_id}-{row['protocol']}", row | shared) for row in analysis.get("decodedProtocols", [])]
    payloads = [(f"{case_id}-{row['id']}", row | shared) for row in analysis.get("payloadFindings", [])]
    alerts = [(f"{case_id}-{row['id']}", row | shared) for row in analysis.get("alerts", [])]
    zeek_rows = []
    for log_name, rows in (analysis.get("zeek", {}).get("records") or {}).items():
        zeek_rows.extend((f"{case_id}-{job_id}-{log_name}-{index}", row | shared | {"zeekLogType": log_name}) for index, row in enumerate(rows[:200]))
    return {
        "packets": _batch("packets", packets),
        "sessions": _batch("sessions", sessions),
        "protocols": _batch("protocols", protocols),
        "payloads": _batch("payloads", payloads),
        "alerts": _batch("alerts", alerts),
        "zeek": _batch("zeek", zeek_rows),
    }


def index_live_packets(documents: list[tuple[str, dict[str, Any]]]) -> int:
    return _batch("live-packets", documents)


def search_index(kind: str, case_id: str = "", query_text: str = "", fallback: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], str]:
    from django.conf import settings

    if getattr(settings, "NETRA_SEARCH_PROVIDER", "elasticsearch") == "postgres" or getattr(settings, "NETRA_DATABASE_PROVIDER", "") == "supabase":
        rows = fallback or []
        if query_text:
            needle = query_text.lower()
            rows = [row for row in rows if needle in " ".join(str(value).lower() for value in row.values())]
        return rows, "postgres"
    index = ALIASES.get(kind, ALIASES["packets"])
    filters = []
    if case_id:
        filters.append({"term": {"caseId": case_id}})
    if query_text:
        query = {"bool": {"must": [{"query_string": {"query": f"*{query_text}*", "fields": ["*"], "default_operator": "AND"}}], "filter": filters}}
    else:
        query = {"bool": {"must": [{"match_all": {}}], "filter": filters}}
    rows = search_documents(index, query, fallback or [])
    if fallback is not None and rows == fallback:
        return rows, "fallback"
    return rows, "elasticsearch"
