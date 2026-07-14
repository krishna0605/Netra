from __future__ import annotations

import csv
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO, StringIO
from pathlib import Path, PurePosixPath
from typing import Any

from common.analysis import MAX_PACKETS, _apply_intake_filters, _packet_from_row, assemble_analysis


TEXT_SUFFIXES = {".log", ".txt", ".csv", ".json", ".ndjson"}
FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "event_time", "datetime", "@timestamp", "ts"),
    "sourceIp": ("src_ip", "source_ip", "source", "src", "client_ip", "origin_ip"),
    "destinationIp": ("dst_ip", "destination_ip", "destination", "dst", "server_ip", "resolver_ip"),
    "sourcePort": ("src_port", "source_port", "sport", "client_port"),
    "destinationPort": ("dst_port", "destination_port", "dport", "server_port", "port"),
    "protocol": ("protocol", "proto", "transport", "network_protocol"),
    "action": ("action", "disposition", "decision", "verdict", "result"),
    "domain": ("qname", "query_name", "query", "domain", "dns_query", "hostname"),
    "sni": ("sni", "server_name", "tls_server_name"),
    "tlsVersion": ("tls_version", "version", "ssl_version"),
    "cipher": ("cipher", "cipher_suite", "tls_cipher"),
    "size": ("bytes", "size", "length", "bytes_sent", "response_bytes"),
    "recordType": ("record_type", "event_type", "log_type", "type", "category"),
}


def analyze_structured_evidence(path: str | Path, case_id: str, evidence_id: str, job_id: str, saved: dict[str, Any]) -> dict[str, Any]:
    source = Path(path)
    records, rejected, source_files = _load_records(source, saved["filename"])
    canonical = [_canonical_record(record, saved.get("normalization", {}).get("normalizedType", "Mixed Evidence")) for record in records]
    canonical = [record for record in canonical if record]
    if not canonical:
        raise ValueError("Structured evidence contains no analyzable network records.")
    packets = [_packet_from_structured(record, index + 1) for index, record in enumerate(canonical)]
    packets = _apply_intake_filters(packets, saved.get("intake", {}))
    record_types = Counter(record["recordType"] for record in canonical)
    actions = Counter(record["action"] for record in canonical if record.get("action"))
    domains = Counter(record["domain"] for record in canonical if record.get("domain"))
    sni_values = Counter(record["sni"] for record in canonical if record.get("sni"))
    summary = {
        "recordCount": len(records),
        "acceptedCount": len(canonical),
        "rejectedCount": rejected + (len(records) - len(canonical)),
        "indexedCount": len(packets),
        "recordTypes": dict(record_types),
        "actions": dict(actions),
        "topDomains": [value for value, _ in domains.most_common(10)],
        "topServerNames": [value for value, _ in sni_values.most_common(10)],
        "sourceFiles": source_files,
        "limitations": "Structured records are normalized into network-event metadata. Original encrypted evidence remains authoritative; payload contents are not inferred.",
    }
    return assemble_analysis(
        packets,
        len(records),
        case_id,
        evidence_id,
        job_id,
        saved,
        source_label=saved.get("normalization", {}).get("normalizedType", "Structured"),
        search_completeness="truncated-search-index" if len(canonical) > len(packets) else "complete",
        structured_summary=summary,
    )


def _load_records(path: Path, filename: str) -> tuple[list[dict[str, Any]], int, list[str]]:
    content = path.read_bytes()
    suffix = Path(filename).suffix.lower()
    if suffix != ".zip":
        records, rejected = _parse_document(content, suffix)
        return records, rejected, [Path(filename).name]

    records: list[dict[str, Any]] = []
    rejected = 0
    source_files: list[str] = []
    with zipfile.ZipFile(BytesIO(content)) as archive:
        members = [member for member in archive.infolist() if not member.is_dir()]
        if len(members) > 100:
            raise ValueError("Mixed-evidence archive contains more than 100 files.")
        total_uncompressed = sum(member.file_size for member in members)
        if total_uncompressed > 100 * 1024 * 1024 or (content and total_uncompressed > len(content) * 100):
            raise ValueError("Mixed-evidence archive exceeds the safe expansion limit.")
        for member in members:
            member_path = PurePosixPath(member.filename)
            if member.flag_bits & 0x1 or member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError("Mixed-evidence archive contains an unsafe member.")
            member_suffix = member_path.suffix.lower()
            if member_suffix not in TEXT_SUFFIXES:
                rejected += 1
                continue
            parsed, failed = _parse_document(archive.read(member), member_suffix)
            records.extend(parsed)
            rejected += failed
            source_files.append(member_path.as_posix())
    if not records:
        raise ValueError("Mixed-evidence archive contains no supported structured records.")
    return records, rejected, source_files


def _parse_document(content: bytes, suffix: str) -> tuple[list[dict[str, Any]], int]:
    text = content.decode("utf-8-sig", errors="replace")
    if suffix == ".csv":
        return [dict(row) for row in csv.DictReader(StringIO(text))], 0
    if suffix == ".json":
        payload = json.loads(text)
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)], sum(1 for row in payload if not isinstance(row, dict))
        if isinstance(payload, dict):
            for key in ("records", "events", "logs", "results"):
                if isinstance(payload.get(key), list):
                    rows = payload[key]
                    return [row for row in rows if isinstance(row, dict)], sum(1 for row in rows if not isinstance(row, dict))
            return [payload], 0
        return [], 1
    records = []
    rejected = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                rejected += 1
                continue
            if isinstance(row, dict):
                records.append(row)
            else:
                rejected += 1
            continue
        pairs = re.findall(r"([A-Za-z_@][A-Za-z0-9_.@-]*)=(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))", line)
        normalized = {key: quoted or single or plain for key, quoted, single, plain in pairs}
        if normalized:
            records.append(normalized)
        else:
            rejected += 1
    return records, rejected


def _canonical_record(record: dict[str, Any], selected_type: str) -> dict[str, Any] | None:
    flat = _flatten(record)
    canonical = {name: _first(flat, aliases) for name, aliases in FIELD_ALIASES.items()}
    record_type = _classify_record(canonical, selected_type)
    canonical["recordType"] = record_type
    canonical["protocol"] = _protocol(canonical, record_type)
    canonical["destinationPort"] = _integer(canonical.get("destinationPort")) or _default_port(canonical["protocol"])
    canonical["sourcePort"] = _integer(canonical.get("sourcePort"))
    canonical["size"] = max(0, _integer(canonical.get("size")))
    canonical["timestamp"] = _epoch(canonical.get("timestamp"))
    canonical["sourceIp"] = str(canonical.get("sourceIp") or "unknown")[:255]
    canonical["destinationIp"] = str(canonical.get("destinationIp") or canonical.get("domain") or canonical.get("sni") or "unknown")[:255]
    for key in ("action", "domain", "sni", "tlsVersion", "cipher"):
        canonical[key] = str(canonical.get(key) or "")[:255]
    if canonical["sourceIp"] == "unknown" and canonical["destinationIp"] == "unknown":
        return None
    return canonical


def _packet_from_structured(record: dict[str, Any], index: int) -> dict[str, Any]:
    protocol = record["protocol"]
    row = {
        "number": str(index), "time_epoch": record["timestamp"], "ip_src": record["sourceIp"], "ipv6_src": "",
        "ip_dst": record["destinationIp"], "ipv6_dst": "", "tcp_srcport": str(record["sourcePort"]) if protocol != "DNS" else "",
        "udp_srcport": str(record["sourcePort"]) if protocol == "DNS" else "", "tcp_dstport": str(record["destinationPort"]) if protocol != "DNS" else "",
        "udp_dstport": str(record["destinationPort"]) if protocol == "DNS" else "", "protocol": protocol, "size": str(record["size"]),
        "flags": "", "dns_query": record["domain"] if record["recordType"] == "DNS Logs" else "", "sni": record["sni"],
        "http_host": "", "http_method": "", "http_uri": "", "http_user_agent": "", "http_content_type": "",
        "dns_query_type": "", "smtp_command": "", "smtp_response_code": "", "ftp_command": "", "ftp_argument": "",
        "ftp_response_code": "", "tls_version": record["tlsVersion"], "tls_cipher_suite": record["cipher"], "icmp_type": "",
        "icmp_code": "", "expert_message": "", "info": f"{record['recordType']} {record['action']}".strip(),
    }
    packet = _packet_from_row(row, index)
    packet["recordType"] = record["recordType"]
    packet["action"] = record["action"]
    if record["action"].lower() in {"deny", "denied", "drop", "dropped", "blocked", "reject", "rejected"}:
        packet["riskScore"] = max(packet["riskScore"], 65)
        packet["severity"] = "medium"
        packet["decodedSummary"] = f"Firewall action {record['action']} recorded in structured evidence."
    return packet


def _flatten(record: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in record.items():
        normalized = str(key).strip().lower()
        output[normalized] = value
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                output[f"{normalized}.{str(nested_key).strip().lower()}"] = nested_value
                output.setdefault(str(nested_key).strip().lower(), nested_value)
    return output


def _first(record: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for alias in aliases:
        value = record.get(alias.lower())
        if value not in (None, ""):
            return value
    return ""


def _classify_record(record: dict[str, Any], selected_type: str) -> str:
    if selected_type != "Mixed Evidence":
        return selected_type
    if record.get("sni") or record.get("tlsVersion") or record.get("cipher"):
        return "TLS Metadata"
    if record.get("domain"):
        return "DNS Logs"
    return "Firewall Logs"


def _protocol(record: dict[str, Any], record_type: str) -> str:
    value = str(record.get("protocol") or "").upper()
    if record_type == "DNS Logs":
        return "DNS"
    if record_type == "TLS Metadata":
        return "TLS"
    return value if value in {"TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "SMB"} else "TCP"


def _default_port(protocol: str) -> int:
    return {"DNS": 53, "TLS": 443, "HTTPS": 443, "HTTP": 80, "SSH": 22, "FTP": 21, "SMTP": 25, "SMB": 445}.get(protocol, 0)


def _integer(value: Any) -> int:
    try:
        return int(float(str(value or "0").replace(",", "")))
    except (TypeError, ValueError):
        return 0


def _epoch(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return str(datetime.now(timezone.utc).timestamp())
    try:
        return str(float(raw))
    except ValueError:
        pass
    try:
        return str(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return str(datetime.now(timezone.utc).timestamp())
