import csv
import html
import json
import shlex
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from django.conf import settings

from common.pcap import available_packet_tools
from common.storage import ensure_storage_tree
from netra_ml.features import extract_features
from netra_ml.scoring import score_anomalies


LATEST_ANALYSIS = "latest-analysis.json"
MAX_PACKETS = 5000
SENSITIVE_PORTS = {21, 22, 23, 25, 80, 1099, 135, 139, 443, 445, 1098, 3306, 3389, 3632, 5900, 6667, 8009, 8080}

def analysis_path(filename: str = LATEST_ANALYSIS) -> Path:
    ensure_storage_tree()
    return settings.NETRA_STORAGE_ROOT / "logs" / filename


def load_latest_analysis() -> dict[str, Any]:
    path = analysis_path()
    if not path.exists():
        return empty_analysis()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return empty_analysis()


def save_analysis(analysis: dict[str, Any]) -> None:
    by_job = analysis_path(f"{analysis['jobId']}.analysis.json")
    latest = analysis_path()
    content = json.dumps(analysis, indent=2)
    by_job.write_text(content, encoding="utf-8")
    latest.write_text(content, encoding="utf-8")


def empty_analysis() -> dict[str, Any]:
    return {
        "caseId": "",
        "jobId": "",
        "evidenceId": "",
        "createdAt": "",
        "riskLevel": "low",
        "topAttackClass": "Normal Baseline",
        "detectedAttackClasses": [],
        "toolStatus": available_packet_tools(),
        "zeek": _empty_zeek("not-run"),
        "features": {"hosts": [], "services": [], "dns": [], "timing": [], "zeek": [], "summary": {}},
        "chainOfCustody": [],
        "evidence": None,
        "case": None,
        "packets": [],
        "sessions": [],
        "decodedProtocols": [],
        "payloadFindings": [],
        "alerts": [],
        "detectionMatches": [],
        "anomalies": [],
        "trafficTimeline": [],
        "protocolChartData": [],
        "graph": {"nodes": [], "edges": []},
        "summary": {
            "packets": 0,
            "sessions": 0,
            "protocolsDecoded": 0,
            "payloadFindings": 0,
            "alerts": 0,
            "anomalies": 0,
            "topAttackClass": "Normal Baseline",
            "riskLevel": "low",
            "toolStatus": available_packet_tools(),
            "zeek": _empty_zeek("not-run"),
        },
    }


def analyze_pcap(pcap_path: str | Path, case_id: str, evidence_id: str, job_id: str, saved: dict[str, Any]) -> dict[str, Any]:
    source_path = Path(pcap_path)
    filtered_path: Path | None = None
    try:
        source_packet_count = _count_observed_packets(source_path)
        bpf_filter = str(saved.get("intake", {}).get("bpfFilter") or "").strip()
        analysis_path = source_path
        if bpf_filter:
            filtered_path = apply_offline_bpf(source_path, bpf_filter)
            analysis_path = filtered_path
        observed_packet_count = _count_observed_packets(analysis_path)
        rows = _read_packets_with_tshark(analysis_path)
        observed_packet_count = observed_packet_count if observed_packet_count is not None else len(rows)
        packets = [_packet_from_row(row, index + 1) for index, row in enumerate(rows)]
        packets = _apply_intake_filters(packets, saved.get("intake", {}))
        active_filters = [
            name for name in ("sourceIp", "destinationIp", "protocol", "port", "durationSeconds", "packetLimit")
            if str(saved.get("intake", {}).get(name) or "").strip()
        ]
        search_completeness = "filtered-view" if bpf_filter or active_filters else ("truncated-search-index" if observed_packet_count > len(packets) else "complete")
        zeek = run_zeek_analysis(analysis_path, job_id)
        return assemble_analysis(
            packets,
            observed_packet_count,
            case_id,
            evidence_id,
            job_id,
            saved,
            zeek=zeek,
            source_label="PCAP",
            search_completeness=search_completeness,
            filter_summary={
                "fullInputScanned": True,
                "bpfApplied": bool(bpf_filter),
                "sourcePacketCount": source_packet_count,
                "bpfPacketCount": observed_packet_count,
                "parsedPacketCount": len(rows),
                "returnedPacketCount": len(packets),
                "activeFilters": (["bpfFilter"] if bpf_filter else []) + active_filters,
            },
        )
    finally:
        if filtered_path:
            filtered_path.unlink(missing_ok=True)


def _bpf_tokens(expression: str) -> list[str]:
    if not expression or len(expression) > 255 or any(ord(character) < 32 for character in expression):
        raise ValueError("BPF filter must contain 1 to 255 printable characters.")
    try:
        tokens = shlex.split(expression, posix=True)
    except ValueError as exc:
        raise ValueError("BPF filter contains invalid quoting.") from exc
    if not tokens or len(tokens) > 64:
        raise ValueError("BPF filter is empty or too complex.")
    return tokens


def validate_bpf_expression(expression: str) -> None:
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise RuntimeError("Offline BPF filtering requires tcpdump in the analysis image.")
    result = subprocess.run([tcpdump, "-d", *_bpf_tokens(expression)], check=False, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise ValueError("BPF filter syntax is invalid.")


def apply_offline_bpf(path: Path, expression: str) -> Path:
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise RuntimeError("Offline BPF filtering requires tcpdump in the analysis image.")
    with NamedTemporaryFile(delete=False, suffix=".pcap") as handle:
        target = Path(handle.name)
    result = subprocess.run(
        [tcpdump, "-nn", "-r", str(path), "-w", str(target), *_bpf_tokens(expression)],
        check=False,
        capture_output=True,
        text=True,
        timeout=settings.NETRA_SYNC_FALLBACK_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        target.unlink(missing_ok=True)
        raise ValueError("BPF filter could not be applied to this capture.")
    return target


def assemble_analysis(
    packets: list[dict[str, Any]],
    observed_record_count: int,
    case_id: str,
    evidence_id: str,
    job_id: str,
    saved: dict[str, Any],
    *,
    zeek: dict[str, Any] | None = None,
    source_label: str = "PCAP",
    search_completeness: str = "complete",
    structured_summary: dict[str, Any] | None = None,
    filter_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    indexed_packet_count = len(packets)
    sessions = _build_sessions(packets)
    zeek = zeek or _empty_zeek("not-applicable")
    features = extract_features(packets=packets, sessions=sessions, zeek=zeek, filename=saved["filename"])
    normalization = saved.get("normalization") or {
        "selectedType": "PCAP",
        "detectedType": "PCAP",
        "normalizedType": "PCAP",
        "valid": True,
        "confidence": 99,
        "parser": "pcap",
        "signals": ["legacy-pcap-upload"],
    }
    features.setdefault("summary", {}).update(
        {
            "evidenceType": normalization.get("normalizedType", "PCAP"),
            "evidenceParser": normalization.get("parser", "pcap"),
            "normalizationConfidence": normalization.get("confidence", 0),
            "normalizationSignals": normalization.get("signals") or normalization.get("features", {}).get("sampleSignals", []),
        }
    )
    if structured_summary:
        features["structuredEvidence"] = structured_summary
        features["summary"].update(
            {
                "structuredRecordCount": structured_summary.get("recordCount", observed_record_count),
                "structuredRejectedCount": structured_summary.get("rejectedCount", 0),
            }
        )
    alerts, detection_matches = _build_detections(packets, sessions, features, zeek, saved["filename"])
    payload_findings = _build_payload_findings(packets, alerts)
    decoded_protocols = _build_protocols(packets, sessions, zeek)
    anomalies = score_anomalies(features=features, sessions=sessions, alerts=alerts, filename=saved["filename"])
    traffic_timeline = _build_timeline(packets, alerts)
    protocol_chart = [{"name": name, "value": count} for name, count in Counter(packet["protocol"] for packet in packets).most_common()]
    graph = _build_graph(sessions, alerts, features)
    now = datetime.now(timezone.utc).isoformat()
    top_attack_class = _top_attack_class(alerts)
    risk_level = _risk_level(alerts, anomalies, top_attack_class)
    detected_classes = list(dict.fromkeys(alert["attackClass"] for alert in alerts)) or ([top_attack_class] if top_attack_class != "Normal Baseline" else [])
    tool_status = available_packet_tools()
    chain_of_custody = _chain_of_custody(now, case_id, evidence_id, saved, zeek)

    analysis = {
        "caseId": case_id,
        "jobId": job_id,
        "evidenceId": evidence_id,
        "createdAt": now,
        "riskLevel": risk_level,
        "topAttackClass": top_attack_class,
        "detectedAttackClasses": detected_classes,
        "toolStatus": tool_status,
        "zeek": zeek,
        "normalization": normalization,
        "features": features,
        "chainOfCustody": chain_of_custody,
        "evidence": {
            "id": evidence_id,
            "filename": saved["filename"],
            "size": _format_bytes(saved["size_bytes"]),
            "sha256": saved["sha256"],
            "plaintextSha256": saved.get("plaintext_sha256", saved["sha256"]),
            "encryptedSha256": saved.get("encrypted_sha256", ""),
            "keyId": settings.NETRA_EVIDENCE_KEY_ID,
            "storageUri": saved.get("stored_path", ""),
            "uploadedAt": now,
            "capturedAt": packets[0]["timestamp"] if packets else now,
            "investigator": saved.get("intake", {}).get("investigator") or f"Uploaded {source_label}",
            "status": "verified" if packets else "failed",
            "evidenceType": normalization.get("normalizedType", "PCAP"),
            "normalization": normalization,
            "intake": saved.get("intake", {}),
        },
        "case": {
            "id": case_id,
            "title": f"{top_attack_class}: {saved['filename']}",
            "investigator": saved.get("intake", {}).get("investigator") or f"Uploaded {source_label}",
            "status": "reviewing" if alerts else "open",
            "evidenceFileId": evidence_id,
            "alertIds": [alert["id"] for alert in alerts],
            "notes": [
                f"Parsed {len(packets)} indexed network metadata row(s) and reconstructed {len(sessions)} sessions from {source_label} evidence.",
                f"Top classification: {top_attack_class}. Zeek status: {zeek['status']}.",
                f"Search completeness: {search_completeness}. Observed records: {observed_record_count}; indexed network metadata rows: {indexed_packet_count}.",
            ],
            "history": [
                {
                    "id": f"hist-{job_id}-upload",
                    "timestamp": now,
                    "actor": "Netra analysis engine",
                    "action": "Evidence uploaded and hashed",
                    "details": f"{saved['filename']} stored with SHA-256 {saved['sha256']}.",
                },
                {
                    "id": f"hist-{job_id}-analysis",
                    "timestamp": now,
                    "actor": "Netra analysis engine",
                    "action": f"{source_label} analyzed",
                    "details": f"Netra parsed {observed_record_count} record(s), reconstructed sessions, and generated {len(alerts)} alert(s).",
                },
            ],
            "createdAt": now,
            "reportStatus": "ready",
        },
        "packets": packets,
        "sessions": sessions,
        "decodedProtocols": decoded_protocols,
        "payloadFindings": payload_findings,
        "alerts": alerts,
        "detectionMatches": detection_matches,
        "anomalies": anomalies,
        "trafficTimeline": traffic_timeline,
        "protocolChartData": protocol_chart,
        "graph": graph,
        "structuredEvidence": structured_summary or {},
        "filterExecution": filter_summary or {},
        "searchCompleteness": search_completeness,
        "observedPackets": observed_record_count,
        "indexedPackets": indexed_packet_count,
        "packetMetadataLimit": MAX_PACKETS,
        "summary": {
            "packets": len(packets),
            "observedPackets": observed_record_count,
            "indexedPackets": indexed_packet_count,
            "packetMetadataLimit": MAX_PACKETS,
            "searchCompleteness": search_completeness,
            "sessions": len(sessions),
            "protocolsDecoded": len(decoded_protocols),
            "payloadFindings": len(payload_findings),
            "alerts": len(alerts),
            "anomalies": len(anomalies),
            "topAttackClass": top_attack_class,
            "detectedAttackClasses": detected_classes,
            "riskLevel": risk_level,
            "toolStatus": tool_status,
            "zeek": {"status": zeek["status"], "summary": zeek["summary"], "logs": zeek["logs"]},
            "filterExecution": filter_summary or {},
        },
    }
    save_analysis(analysis)
    return analysis


def _apply_intake_filters(packets: list[dict[str, Any]], intake: dict[str, Any]) -> list[dict[str, Any]]:
    source_ip = str(intake.get("sourceIp") or "").strip().lower()
    destination_ip = str(intake.get("destinationIp") or "").strip().lower()
    protocol = str(intake.get("protocol") or "").strip().upper()
    port = _int(str(intake.get("port") or ""))
    packet_limit = _int(str(intake.get("packetLimit") or ""))
    duration_seconds = _int(str(intake.get("durationSeconds") or ""))

    filtered = [
        packet
        for packet in packets
        if (not source_ip or source_ip == str(packet.get("sourceIp", "")).lower())
        and (not destination_ip or destination_ip == str(packet.get("destinationIp", "")).lower())
        and (
            not protocol
            or protocol == str(packet.get("protocol", "")).upper()
            or protocol == str(packet.get("transportProtocol", "")).upper()
        )
        and (not port or port in {int(packet.get("sourcePort") or 0), int(packet.get("destinationPort") or 0)})
    ]
    if duration_seconds and filtered:
        try:
            start = datetime.fromisoformat(filtered[0]["timestamp"])
            filtered = [
                packet
                for packet in filtered
                if (datetime.fromisoformat(packet["timestamp"]) - start).total_seconds() <= duration_seconds
            ]
        except Exception:
            pass
    result_limit = max(1, min(MAX_PACKETS, packet_limit or MAX_PACKETS))
    return filtered[:result_limit]


def run_zeek_analysis(pcap_path: Path, job_id: str) -> dict[str, Any]:
    zeek_bin = shutil.which("zeek") or "/usr/local/zeek/bin/zeek"
    if not Path(zeek_bin).exists() and shutil.which("zeek") is None:
        return _empty_zeek("unavailable", "Zeek binary was not found.")
    output_dir = settings.NETRA_STORAGE_ROOT / "zeek" / job_id
    output_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([zeek_bin, "-C", "-r", str(pcap_path)], cwd=output_dir, capture_output=True, text=True, timeout=120, check=False)
    logs = sorted(path.name for path in output_dir.glob("*.log"))
    parsed = {name: _parse_zeek_log(output_dir / name) for name in logs}
    summary = _summarize_zeek(parsed)
    status = "parsed" if logs else "failed"
    error = "" if result.returncode == 0 or logs else (result.stderr.strip() or "Zeek did not produce logs.")
    return {
        "status": status,
        "logDir": str(output_dir),
        "logs": logs,
        "summary": summary,
        "topServices": _top_zeek_services(parsed.get("conn.log", [])),
        "topDnsQueries": _top_values(parsed.get("dns.log", []), "query"),
        "topExternalHosts": _top_external_hosts(parsed.get("conn.log", [])),
        "records": {name: rows[:50] for name, rows in parsed.items()},
        "error": error,
    }


def _empty_zeek(status: str, error: str = "") -> dict[str, Any]:
    return {
        "status": status,
        "logDir": "",
        "logs": [],
        "summary": {"connections": 0, "dnsQueries": 0, "httpRequests": 0, "tlsSessions": 0, "sshSessions": 0, "notices": 0, "weirdEvents": 0},
        "topServices": [],
        "topDnsQueries": [],
        "topExternalHosts": [],
        "records": {},
        "error": error,
    }


def _parse_zeek_log(path: Path) -> list[dict[str, str]]:
    fields: list[str] = []
    rows: list[dict[str, str]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if not line or line.startswith("#") or not fields:
                continue
            values = line.split("\t")
            values += [""] * (len(fields) - len(values))
            rows.append(dict(zip(fields, values[: len(fields)])))
    except Exception:
        return []
    return rows


def _summarize_zeek(parsed: dict[str, list[dict[str, str]]]) -> dict[str, int]:
    return {
        "connections": len(parsed.get("conn.log", [])),
        "dnsQueries": len(parsed.get("dns.log", [])),
        "httpRequests": len(parsed.get("http.log", [])),
        "tlsSessions": len(parsed.get("ssl.log", [])) + len(parsed.get("x509.log", [])),
        "sshSessions": len(parsed.get("ssh.log", [])),
        "notices": len(parsed.get("notice.log", [])),
        "weirdEvents": len(parsed.get("weird.log", [])),
    }


def _top_zeek_services(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts = Counter((row.get("service") or row.get("proto") or "unknown").split(",")[0] for row in rows)
    return [{"service": service, "count": count} for service, count in counts.most_common(8) if service and service != "-"]


def _top_values(rows: list[dict[str, str]], field: str) -> list[dict[str, Any]]:
    counts = Counter(row.get(field, "") for row in rows if row.get(field, "") not in {"", "-"})
    return [{"value": value, "count": count} for value, count in counts.most_common(8)]


def _top_external_hosts(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts = Counter(row.get("id.resp_h", "") for row in rows if row.get("id.resp_h", "") not in {"", "-"})
    return [{"host": host, "count": count} for host, count in counts.most_common(8)]


def _read_packets_with_tshark(path: Path) -> list[dict[str, str]]:
    command = [
        "tshark", "-r", str(path), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
        "-e", "tcp.srcport", "-e", "udp.srcport", "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "_ws.col.Protocol",
        "-e", "frame.len", "-e", "tcp.flags", "-e", "dns.qry.name", "-e", "tls.handshake.extensions_server_name",
        "-e", "http.host", "-e", "http.request.method", "-e", "http.request.uri", "-e", "http.user_agent",
        "-e", "http.content_type", "-e", "dns.qry.type", "-e", "smtp.req.command", "-e", "smtp.response.code",
        "-e", "ftp.request.command", "-e", "ftp.request.arg", "-e", "ftp.response.code", "-e", "tls.handshake.version",
        "-e", "tls.handshake.ciphersuite", "-e", "icmp.type", "-e", "icmp.code", "-e", "_ws.expert.message",
        "-e", "_ws.col.Info",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=settings.NETRA_SYNC_FALLBACK_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "tshark could not parse the PCAP")
    fields = [
        "number", "time_epoch", "ip_src", "ipv6_src", "ip_dst", "ipv6_dst", "tcp_srcport", "udp_srcport",
        "tcp_dstport", "udp_dstport", "protocol", "size", "flags", "dns_query", "sni", "http_host",
        "http_method", "http_uri", "http_user_agent", "http_content_type", "dns_query_type", "smtp_command",
        "smtp_response_code", "ftp_command", "ftp_argument", "ftp_response_code", "tls_version", "tls_cipher_suite",
        "icmp_type", "icmp_code", "expert_message", "info",
    ]
    rows = []
    for line in result.stdout.splitlines():
        values = line.split("\t")
        values += [""] * (len(fields) - len(values))
        rows.append(dict(zip(fields, values[: len(fields)])))
    return rows


def _packet_from_row(row: dict[str, str], index: int) -> dict[str, Any]:
    source = row["ip_src"] or row["ipv6_src"] or "unknown"
    destination = row["ip_dst"] or row["ipv6_dst"] or row["dns_query"] or row["sni"] or row["http_host"] or "unknown"
    source_port = _int(row["tcp_srcport"] or row["udp_srcport"])
    destination_port = _int(row["tcp_dstport"] or row["udp_dstport"])
    transport_protocol = (
        "TCP"
        if row["tcp_srcport"] or row["tcp_dstport"]
        else "UDP"
        if row["udp_srcport"] or row["udp_dstport"]
        else (row["protocol"] or "UNKNOWN").upper()
    )
    protocol = _normalize_protocol(row["protocol"], destination_port, source_port)
    size = _int(row["size"])
    risk, severity, reason = _score_packet(protocol, destination_port, size, row)
    session_id = _session_id(source, destination, source_port, destination_port, protocol)
    preview = row["dns_query"] or row["sni"] or row["http_host"] or row["info"] or "metadata only"
    dpi = _dpi_metadata(row, protocol, source_port, destination_port, size)
    return {
        "id": f"pkt-{index:05d}",
        "timestamp": _format_time(row["time_epoch"]),
        "sourceIp": source,
        "destinationIp": destination,
        "sourcePort": source_port,
        "destinationPort": destination_port,
        "protocol": protocol,
        "transportProtocol": transport_protocol,
        "size": size,
        "flags": row["flags"] or "-",
        "sessionId": session_id,
        "riskScore": risk,
        "severity": severity,
        "hexPreview": _hex_preview(preview),
        "asciiPreview": preview[:160],
        "dnsQuery": row["dns_query"],
        "sni": row["sni"],
        "httpHost": row["http_host"],
        "dpi": dpi,
        "decodedSummary": _dpi_summary(protocol, dpi, reason),
        "relatedAlertId": None,
    }


def _count_observed_packets(path: Path) -> int | None:
    capinfos = shutil.which("capinfos")
    if not capinfos:
        return None
    result = subprocess.run([capinfos, "-M", "-c", str(path)], check=False, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if "Number of packets" not in line:
            continue
        value = line.split(":", 1)[-1].strip().lower().replace(",", "")
        parts = value.split()
        if not parts:
            continue
        try:
            count = float(parts[0])
        except ValueError:
            digits = "".join(ch for ch in value if ch.isdigit())
            return int(digits) if digits else None
        suffix = parts[1] if len(parts) > 1 else ""
        if suffix.startswith("k"):
            count *= 1_000
        elif suffix.startswith("m"):
            count *= 1_000_000
        return int(count)
    return None


def _dpi_metadata(row: dict[str, str], protocol: str, source_port: int, destination_port: int, size: int) -> dict[str, Any]:
    return {
        "httpMethod": row.get("http_method", ""),
        "httpUri": row.get("http_uri", ""),
        "httpUserAgent": row.get("http_user_agent", ""),
        "httpContentType": row.get("http_content_type", ""),
        "dnsQueryType": row.get("dns_query_type", ""),
        "smtpCommand": row.get("smtp_command", ""),
        "smtpResponseCode": row.get("smtp_response_code", ""),
        "ftpCommand": row.get("ftp_command", ""),
        "ftpArgument": _redact_credential_argument(row.get("ftp_argument", ""), row.get("ftp_command", "")),
        "ftpResponseCode": row.get("ftp_response_code", ""),
        "tlsVersion": row.get("tls_version", ""),
        "tlsCipherSuite": row.get("tls_cipher_suite", ""),
        "icmpType": row.get("icmp_type", ""),
        "icmpCode": row.get("icmp_code", ""),
        "expertMessage": row.get("expert_message", ""),
        "sourcePort": source_port,
        "destinationPort": destination_port,
        "packetSize": size,
        "metadataOnly": protocol in {"TLS", "SSL", "HTTPS"} or destination_port == 443 or source_port == 443,
    }


def _redact_credential_argument(argument: str, command: str) -> str:
    if command.upper() in {"PASS", "USER"} and argument:
        return "[redacted]"
    return argument[:120]


def _dpi_summary(protocol: str, dpi: dict[str, Any], fallback: str) -> str:
    if protocol == "DNS" and dpi.get("dnsQueryType"):
        return f"DNS query metadata, type {dpi['dnsQueryType']}. {fallback}"
    if protocol in {"HTTP", "HTTP2"} and (dpi.get("httpMethod") or dpi.get("httpUri")):
        return f"HTTP {dpi.get('httpMethod') or 'request'} {dpi.get('httpUri') or '/'} observed from packet metadata."
    if protocol == "FTP" and dpi.get("ftpCommand"):
        return f"FTP command metadata observed: {dpi['ftpCommand']}."
    if protocol == "SMTP" and (dpi.get("smtpCommand") or dpi.get("smtpResponseCode")):
        return f"SMTP command/response metadata observed: {dpi.get('smtpCommand') or dpi.get('smtpResponseCode')}."
    if protocol in {"TLS", "SSL", "HTTPS"}:
        return "Encrypted session metadata only; Netra does not decrypt TLS payloads."
    if protocol == "ICMP" and dpi.get("icmpType"):
        return f"ICMP metadata type {dpi['icmpType']} code {dpi.get('icmpCode') or '0'}."
    return fallback


def _build_sessions(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for packet in packets:
        grouped[packet["sessionId"]].append(packet)
    sessions = []
    for session_id, items in grouped.items():
        first = items[0]
        total_bytes = sum(packet["size"] for packet in items)
        risk = max(packet["riskScore"] for packet in items)
        sessions.append({
            "id": session_id,
            "source": first["sourceIp"],
            "destination": first["destinationIp"],
            "protocol": first["protocol"],
            "startTime": items[0]["timestamp"],
            "endTime": items[-1]["timestamp"],
            "duration": _duration(items[0]["timestamp"], items[-1]["timestamp"]),
            "bytesSent": total_bytes,
            "bytesReceived": 0,
            "packetCount": len(items),
            "riskScore": min(100, risk + (12 if total_bytes > 5_000_000 else 0) + (10 if len(items) > 100 else 0)),
            "relatedAlertIds": [],
        })
    return sorted(sessions, key=lambda item: (item["riskScore"], item["packetCount"]), reverse=True)[:250]


def _build_detections(packets: list[dict[str, Any]], sessions: list[dict[str, Any]], features: dict[str, Any], zeek: dict[str, Any], filename: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates = _behavior_candidates(features, zeek)
    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for candidate in candidates:
        key = (candidate["attackClass"], candidate["sourceIp"], candidate["destination"])
        if key not in deduped or candidate["confidence"] > deduped[key]["confidence"]:
            deduped[key] = candidate

    alerts = []
    matches = []
    packets_by_session: dict[str, list[str]] = defaultdict(list)
    for packet in packets:
        packets_by_session[packet["sessionId"]].append(packet["id"])
    for index, item in enumerate(sorted(deduped.values(), key=lambda row: row["confidence"], reverse=True), start=1):
        alert_id = f"al-{index:04d}"
        evidence_session_ids = item.get("evidenceSessionIds", [])[:5]
        evidence_packet_ids = [packet_id for session_id in evidence_session_ids for packet_id in packets_by_session.get(session_id, [])[:2]][:10]
        alert = {
            "id": alert_id,
            "severity": item["severity"],
            "attackClass": item["attackClass"],
            "type": item["type"],
            "sourceIp": item["sourceIp"],
            "destination": item["destination"],
            "protocol": item["protocol"],
            "timestamp": packets[0]["timestamp"] if packets else datetime.now(timezone.utc).isoformat(),
            "confidence": item["confidence"],
            "status": "new",
            "ruleId": item["ruleId"],
            "evidencePacketIds": evidence_packet_ids,
            "evidenceSessionIds": evidence_session_ids,
            "explanation": item["explanation"],
            "recommendedAction": item["recommendedAction"],
            "detectorType": "behavior-rule",
            "observedSignals": item["observedSignals"],
            "confidenceFactors": item["confidenceFactors"],
            "limitations": item["limitations"],
        }
        alerts.append(alert)
        matches.append({
            "id": f"det-{index:04d}",
            "ruleId": item["ruleId"],
            "ruleName": item["type"],
            "category": item["category"],
            "attackClass": item["attackClass"],
            "matchedEntity": item["matchedEntity"],
            "confidence": item["confidence"],
            "status": "new",
            "evidencePacketIds": evidence_packet_ids,
            "evidenceSessionIds": evidence_session_ids,
            "explanation": item["explanation"],
            "recommendedAction": item["recommendedAction"],
            "detectorType": "behavior-rule",
            "observedSignals": item["observedSignals"],
            "confidenceFactors": item["confidenceFactors"],
            "limitations": item["limitations"],
        })

    for alert in alerts:
        for packet in packets:
            if packet["id"] in alert["evidencePacketIds"]:
                packet["relatedAlertId"] = alert["id"]
                packet["riskScore"] = max(packet["riskScore"], alert["confidence"])
                packet["severity"] = alert["severity"]
        for session in sessions:
            if session["id"] in alert["evidenceSessionIds"]:
                session["relatedAlertIds"].append(alert["id"])
                session["riskScore"] = max(session["riskScore"], alert["confidence"])

    return alerts[:100], matches[:100]


def _behavior_candidates(features: dict[str, Any], zeek: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    summary = features.get("summary", {})
    hosts = features.get("hosts", [])
    services = features.get("services", [])
    top_host = hosts[0] if hosts else {}
    top_service = services[0] if services else {}
    ssh_count = zeek.get("summary", {}).get("sshSessions", 0)
    ftp_sessions = sum(item.get("sessionCount", 0) for item in services if item.get("port") == 21 or item.get("service") == "FTP")

    if ssh_count >= 20 or ftp_sessions >= 20:
        proto = "SSH" if ssh_count >= ftp_sessions else "FTP"
        port = 22 if proto == "SSH" else 21
        candidates.append(_candidate("Credential Brute Force", "high", min(98, 82 + max(ssh_count, ftp_sessions) // 10), f"Repeated {proto} authentication attempts", "rule-bruteforce-ssh-ftp", features, None, port=port))
    telnet = next((item for item in services if item.get("port") == 23), {})
    if telnet and (telnet.get("destinationCount", 0) >= 5 or telnet.get("sessionCount", 0) >= 5):
        candidates.append(_candidate("IoT Botnet / Scanning", "critical", 92, "Telnet propagation or IoT botnet-style scanning", "rule-botnet-telnet-scanning", features, None, port=23))
    scan_hosts = [
        host
        for host in hosts
        if host.get("uniqueDestinations", 0) >= 40
        or (host.get("uniqueDestinationPorts", 0) >= 100 and len(host.get("sensitivePortsTouched", [])) >= 3)
    ]
    if scan_hosts:
        candidates.append(_candidate("Port Scan / Reconnaissance", "high", 90, "High host or service fan-out reconnaissance", "rule-port-scan-reconnaissance", features, None))
    if summary.get("beaconPairs", 0) and 0 < summary.get("externalHostCount", 0) <= 3:
        candidates.append(_candidate("Malware C2 / Beaconing", "high", 80, "Repeated external communications consistent with C2 review", "rule-malware-c2-beacon", features, None))
    if summary.get("dnsQueryCount", 0) >= 5 and (summary.get("longestDnsQuery", 0) > 80 or summary.get("averageDnsQueryLength", 0) > 50):
        candidates.append(_candidate("DNS Tunnel", "critical", 93, "Unusually long DNS query pattern", "rule-dns-tunnel", features, None, protocol="DNS"))
    if summary.get("icmpLargePacketCount", 0) >= 3:
        candidates.append(_candidate("ICMP Tunnel", "medium", 78, "Repeated large ICMP packets", "rule-icmp-tunnel", features, None, protocol="ICMP"))
    if summary.get("largestSessionBytes", 0) > 5_000_000:
        candidates.append(_candidate("Data Exfiltration", "high", 84, "Large outbound transfer volume", "rule-data-exfiltration", features, None))
    if any(item.get("port") == 3632 for item in services):
        candidates.append(_candidate("Remote Command Execution", "critical", 88, "distcc service traffic requires RCE review", "rule-remote-command-execution", features, None, port=3632))
    web_service = next((item for item in services if item.get("port") in {8009, 8080} and item.get("sessionCount", 0) >= 10 and item.get("packetCount", 0) >= 3), None)
    if web_service:
        candidates.append(_candidate("Web Service Exploitation", "high", 80, "Repeated application service traffic requires exploit review", "rule-service-exploit-web", features, None, port=web_service["port"]))
    if any(item.get("port") in {139, 445} and item.get("packetCount", 0) >= 10 and item.get("sessionCount", 0) >= 3 for item in services):
        candidates.append(_candidate("SMB / NetBIOS Lateral Movement", "high", 88, "NetBIOS/SMB internal movement pattern", "rule-smb-netbios-lateral", features, None, port=445))
    if any(item.get("port") == 25 and item.get("packetCount", 0) >= 20 for item in services):
        candidates.append(_candidate("Suspicious SMTP Transfer", "medium", 80, "SMTP transfer requires investigator review", "rule-smtp-suspicious", features, None, port=25))
    return candidates


def _candidate(attack_class: str, severity: str, confidence: int, finding_type: str, rule_id: str, features: dict[str, Any], sessions: list[dict[str, Any]] | None, port: int = 0, protocol: str = "") -> dict[str, Any]:
    hosts = features.get("hosts", [])
    services = features.get("services", [])
    service = next((item for item in services if port and item.get("port") == port), services[0] if services else {})
    host = hosts[0] if hosts else {}
    source = host.get("ip") or service.get("topSource") or "multiple-hosts"
    destination = service.get("topDestination") or host.get("topDestination") or "multiple-destinations"
    evidence_sessions = []
    if sessions:
        evidence_sessions = [session["id"] for session in sessions if (not port or session.get("destinationPort") == port)][:5]
    else:
        evidence_sessions = service.get("evidenceSessionIds", []) or host.get("evidenceSessionIds", [])
    explanation, recommended = _explain_detection(attack_class, finding_type, source, destination)
    observed_signals = [
        f"top service: {service.get('service', 'unknown')}:{service.get('port', port or 0)}",
        f"service packets: {service.get('packetCount', 0)}",
        f"max destination fan-out: {features.get('summary', {}).get('maxDestinationFanout', 0)}",
        f"max port fan-out: {features.get('summary', {}).get('maxPortFanout', 0)}",
    ]
    return {
        "severity": severity,
        "attackClass": attack_class,
        "type": finding_type,
        "sourceIp": source,
        "destination": destination,
        "protocol": protocol or service.get("service") or host.get("topProtocol") or "TCP",
        "confidence": min(99, confidence),
        "ruleId": rule_id,
        "category": _category_for_class(attack_class),
        "matchedEntity": f"{source} -> {destination}{':' + str(port) if port else ''}",
        "evidenceSessionIds": evidence_sessions[:8],
        "explanation": explanation,
        "recommendedAction": recommended,
        "observedSignals": observed_signals,
        "confidenceFactors": [{"signal": signal, "weight": max(10, confidence // len(observed_signals))} for signal in observed_signals],
        "limitations": "PCAP metadata indicates suspicious network behavior but must be correlated with endpoint and server logs before attribution.",
    }


def _explain_detection(attack_class: str, finding_type: str, source: str, destination: str) -> tuple[str, str]:
    explanations = {
        "Credential Brute Force": ("One source repeatedly opened authentication-service sessions to the same destination, which is consistent with scripted credential attempts.", "Correlate with SSH/FTP authentication logs, check failed-login volume, and isolate the source if unauthorized."),
        "IoT Botnet / Scanning": ("The traffic shows high fan-out across hosts or services, a common reconnaissance and botnet propagation pattern.", "Review the source host for malware, block unnecessary outbound scanning, and inspect contacted ports."),
        "Port Scan / Reconnaissance": ("One host contacted an unusually broad set of destinations or service ports, which is consistent with reconnaissance activity.", "Review the scanning source, validate whether the enumeration was authorized, and inspect the contacted services."),
        "Malware C2 / Beaconing": ("Repeated communications and timing concentration suggest command-and-control or beacon-like behavior.", "Correlate destinations with threat intelligence and preserve endpoint/network logs for the same time window."),
        "DNS Tunnel": ("DNS metadata contains unusually long query names or labels that can hide data in allowed DNS traffic.", "Review queried domains, resolver logs, and endpoint processes generating DNS requests."),
        "ICMP Tunnel": ("Large or repeated ICMP packets can indicate covert communication over a normally low-volume protocol.", "Validate whether ICMP traffic is expected and restrict ICMP egress if not needed."),
        "Data Exfiltration": ("A session or host produced unusually large outbound transfer volume compared with the capture baseline.", "Identify the transferred service, destination ownership, and whether sensitive data left the network."),
        "Service Exploitation": ("Traffic targets a vulnerable or sensitive service with exploit-sample characteristics.", "Patch or isolate the service and correlate with server logs around the captured timestamp."),
        "Web Service Exploitation": ("Traffic targets a web/application service with exploit-sample characteristics.", "Review web server access logs, deployed applications, and suspicious request payloads."),
        "Remote Command Execution": ("Service traffic matches a backdoor/RCE investigation pattern.", "Preserve server process logs and verify whether unauthorized commands executed."),
        "SMB / NetBIOS Lateral Movement": ("Internal SMB/NetBIOS traffic can indicate lateral movement or file-share probing.", "Check domain authentication logs and validate administrative share access."),
        "Suspicious SMTP Transfer": ("SMTP traffic may represent suspicious mail transfer or data movement requiring review.", "Inspect mail logs, sender/recipient metadata, and attachment evidence."),
    }
    return explanations.get(attack_class, (f"{finding_type} was detected between {source} and {destination}.", "Review the related packets, sessions, and Zeek logs before closing this finding."))


def _category_for_class(attack_class: str) -> str:
    if "Brute Force" in attack_class:
        return "Credential Attack"
    if "Botnet" in attack_class or "Scan" in attack_class:
        return "Reconnaissance / Botnet"
    if "C2" in attack_class or "Malware" in attack_class or "APT" in attack_class:
        return "Malware Communication"
    if "Tunnel" in attack_class or "Exfiltration" in attack_class:
        return "Covert Channel / Exfiltration"
    if "Exploitation" in attack_class or "Execution" in attack_class or "Exploit" in attack_class:
        return "Service Exploitation"
    if "SMB" in attack_class or "NetBIOS" in attack_class:
        return "Lateral Movement"
    return "Forensic Review"


def _build_payload_findings(packets: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alert_packet_ids = {packet_id for alert in alerts for packet_id in alert.get("evidencePacketIds", [])}
    findings = []
    for packet in packets:
        indicator = _payload_indicator(packet)
        if packet["riskScore"] < 70 and packet["id"] not in alert_packet_ids and indicator["risk"] == "low":
            continue
        risk = _max_severity(packet["severity"], indicator["risk"])
        findings.append({
            "id": f"pay-{len(findings) + 1:04d}",
            "packetId": packet["id"],
            "sessionId": packet["sessionId"],
            "protocol": packet["protocol"],
            "payloadType": indicator["payloadType"],
            "entropyScore": indicator["entropyScore"],
            "hiddenData": indicator["hiddenData"],
            "obfuscated": indicator["obfuscated"],
            "matchedPattern": indicator["matchedPattern"],
            "risk": risk,
            "textPreview": packet["asciiPreview"],
            "hexPreview": packet["hexPreview"],
            "extractedStrings": [value for value in [packet["sourceIp"], packet["destinationIp"], packet["protocol"], packet.get("relatedAlertId") or "", *indicator["extractedStrings"]] if value],
            "indicator": indicator["indicator"],
            "description": indicator["description"],
            "limitations": indicator["limitations"],
            "metadata": indicator["metadata"],
        })
    return findings[:100]


def _payload_indicator(packet: dict[str, Any]) -> dict[str, Any]:
    protocol = packet["protocol"]
    dpi = packet.get("dpi", {})
    info = f"{packet.get('asciiPreview', '')} {dpi.get('expertMessage', '')}".lower()
    dns_query = packet.get("dnsQuery") or ""
    extracted = []
    metadata: dict[str, Any] = {}
    indicator = "metadata-review"
    payload_type = "Metadata-derived forensic finding"
    description = "Packet metadata is relevant to the current investigation and should be reviewed with related sessions."
    hidden_data = False
    obfuscated = False
    risk = "low"

    if protocol == "DNS" and dns_query:
        longest_label = max((len(label) for label in dns_query.split(".")), default=0)
        hidden_data = len(dns_query) > 80 or longest_label > 45
        obfuscated = hidden_data or _looks_encoded(dns_query)
        risk = "high" if hidden_data else "medium"
        indicator = "dns-query-metadata"
        payload_type = "DNS metadata clue"
        description = "DNS query metadata can indicate tunneling when labels are unusually long or encoded-looking."
        extracted = [dns_query[:160], str(dpi.get("dnsQueryType") or "")]
        metadata = {"queryLength": len(dns_query), "longestLabel": longest_label, "queryType": dpi.get("dnsQueryType") or ""}
    elif protocol in {"HTTP", "HTTP2"}:
        method = dpi.get("httpMethod") or ""
        uri = dpi.get("httpUri") or ""
        user_agent = dpi.get("httpUserAgent") or ""
        exploit_terms = ["cmd=", "exec", "../", "%2e%2e", "select%20", "union%20", "passwd", "shell", "jndi:"]
        suspicious_uri = any(term in uri.lower() for term in exploit_terms)
        risk = "high" if suspicious_uri else ("medium" if method in {"POST", "PUT"} else "low")
        indicator = "http-request-metadata"
        payload_type = "HTTP request metadata"
        description = "HTTP request metadata is decoded where visible. Encrypted HTTPS payloads are not decrypted."
        extracted = [method, uri[:160], user_agent[:120]]
        metadata = {"method": method, "uri": uri[:240], "userAgent": user_agent[:160], "contentType": dpi.get("httpContentType") or ""}
    elif protocol == "FTP":
        command = (dpi.get("ftpCommand") or "").upper()
        transfer_commands = {"RETR", "STOR", "APPE", "LIST", "NLST", "USER", "PASS"}
        risk = "high" if command in {"USER", "PASS", "STOR", "RETR"} else ("medium" if command in transfer_commands else "low")
        indicator = "ftp-command-metadata"
        payload_type = "FTP command metadata"
        description = "FTP command metadata can reveal authentication attempts or file transfer activity; credential arguments are redacted."
        extracted = [command, str(dpi.get("ftpArgument") or "")]
        metadata = {"command": command, "argument": dpi.get("ftpArgument") or "", "responseCode": dpi.get("ftpResponseCode") or ""}
    elif protocol == "SMTP":
        command = (dpi.get("smtpCommand") or "").upper()
        risk = "medium" if command in {"MAIL", "RCPT", "DATA", "BDAT"} or "data fragment" in info else "low"
        indicator = "smtp-transfer-metadata"
        payload_type = "SMTP transfer metadata"
        description = "SMTP metadata can show mail transfer behavior, but attachment and body review requires mail server logs or decoded content."
        extracted = [command, str(dpi.get("smtpResponseCode") or "")]
        metadata = {"command": command, "responseCode": dpi.get("smtpResponseCode") or ""}
    elif protocol in {"TLS", "SSL", "HTTPS"}:
        sni = packet.get("sni") or ""
        obfuscated = not bool(sni)
        risk = "medium" if obfuscated or packet["destinationPort"] not in {443, 8443} else "low"
        indicator = "encrypted-traffic-metadata"
        payload_type = "Encrypted traffic metadata"
        description = "Only TLS handshake and flow metadata are available; Netra does not decrypt encrypted payloads."
        extracted = [sni[:160], str(dpi.get("tlsVersion") or ""), str(dpi.get("tlsCipherSuite") or "")]
        metadata = {"sni": sni, "tlsVersion": dpi.get("tlsVersion") or "", "cipherSuite": dpi.get("tlsCipherSuite") or "", "metadataOnly": True}
    elif protocol == "ICMP":
        hidden_data = packet["size"] >= 512
        risk = "high" if packet["size"] >= 1000 else ("medium" if hidden_data else "low")
        indicator = "icmp-size-metadata"
        payload_type = "ICMP metadata clue"
        description = "Large ICMP packets can be a covert-channel clue when unexpected in the environment."
        extracted = [str(dpi.get("icmpType") or ""), str(dpi.get("icmpCode") or "")]
        metadata = {"icmpType": dpi.get("icmpType") or "", "icmpCode": dpi.get("icmpCode") or "", "packetSize": packet["size"]}
    elif "malformed" in info or "checksum" in info or "retransmission" in info:
        risk = "medium"
        indicator = "packet-expert-warning"
        payload_type = "Packet expert warning"
        description = "tshark expert metadata identified an abnormal packet condition requiring analyst review."
        metadata = {"expertMessage": dpi.get("expertMessage") or ""}

    entropy = round(min(9.9, 2 + packet["riskScore"] / 18 + (1.2 if hidden_data else 0) + (0.8 if obfuscated else 0)), 1)
    return {
        "indicator": indicator,
        "payloadType": payload_type,
        "entropyScore": entropy,
        "hiddenData": hidden_data,
        "obfuscated": obfuscated,
        "matchedPattern": packet["decodedSummary"],
        "risk": risk,
        "description": description,
        "limitations": "Metadata-level finding only. Netra does not decrypt TLS or guarantee full application payload reconstruction.",
        "extractedStrings": extracted,
        "metadata": metadata,
    }


def _looks_encoded(value: str) -> bool:
    if len(value) < 24:
        return False
    compact = value.replace(".", "").replace("-", "")
    if not compact:
        return False
    alnum_ratio = sum(ch.isalnum() for ch in compact) / len(compact)
    digit_ratio = sum(ch.isdigit() for ch in compact) / len(compact)
    return alnum_ratio > 0.95 and digit_ratio > 0.2


def _max_severity(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _build_protocols(packets: list[dict[str, Any]], sessions: list[dict[str, Any]], zeek: dict[str, Any]) -> list[dict[str, Any]]:
    packet_counts = Counter(packet["protocol"] for packet in packets)
    suspicious_counts = Counter(packet["protocol"] for packet in packets if packet["riskScore"] >= 70)
    session_counts = Counter(session["protocol"] for session in sessions)
    top_destinations: dict[str, Counter[str]] = defaultdict(Counter)
    protocol_clues: dict[str, Counter[str]] = defaultdict(Counter)
    for packet in packets:
        top_destinations[packet["protocol"]][packet["destinationIp"]] += 1
        clue = _protocol_clue(packet)
        if clue:
            protocol_clues[packet["protocol"]][clue] += 1
    protocols = []
    zeek_summary = zeek.get("summary", {})
    zeek_protocol_counts = {"SSH": zeek_summary.get("sshSessions", 0), "DNS": zeek_summary.get("dnsQueries", 0), "HTTP": zeek_summary.get("httpRequests", 0), "TLS": zeek_summary.get("tlsSessions", 0)}
    for protocol, count in packet_counts.most_common():
        zeek_count = zeek_protocol_counts.get(protocol, 0)
        protocols.append({
            "protocol": protocol,
            "packetCount": count,
            "sessionCount": session_counts[protocol],
            "suspiciousCount": suspicious_counts[protocol],
            "status": "metadata-only" if protocol in {"TLS", "SSL"} else ("decoded" if zeek_count or protocol not in {"UNKNOWN"} else "partial"),
            "topDestination": top_destinations[protocol].most_common(1)[0][0] if top_destinations[protocol] else "unknown",
            "detail": _protocol_detail(protocol, count, zeek_count, protocol_clues[protocol]),
        })
    for protocol, count in zeek_protocol_counts.items():
        if count and protocol not in packet_counts:
            protocols.append({"protocol": protocol, "packetCount": 0, "sessionCount": count, "suspiciousCount": 0, "status": "decoded", "topDestination": "Zeek log", "detail": f"Zeek extracted {count} structured {protocol} event(s)."})
    return protocols


def _protocol_clue(packet: dict[str, Any]) -> str:
    protocol = packet["protocol"]
    dpi = packet.get("dpi", {})
    if protocol == "DNS" and packet.get("dnsQuery"):
        return f"DNS query: {packet['dnsQuery'][:60]}"
    if protocol in {"HTTP", "HTTP2"} and (dpi.get("httpMethod") or dpi.get("httpUri")):
        return f"HTTP {dpi.get('httpMethod') or 'request'} {str(dpi.get('httpUri') or '/')[:60]}"
    if protocol == "FTP" and dpi.get("ftpCommand"):
        return f"FTP {dpi['ftpCommand']}"
    if protocol == "SMTP" and (dpi.get("smtpCommand") or dpi.get("smtpResponseCode")):
        return f"SMTP {dpi.get('smtpCommand') or dpi.get('smtpResponseCode')}"
    if protocol in {"TLS", "SSL", "HTTPS"}:
        return f"TLS SNI: {packet.get('sni') or 'not visible'}"
    if protocol == "ICMP" and dpi.get("icmpType"):
        return f"ICMP type {dpi['icmpType']}"
    return ""


def _protocol_detail(protocol: str, packet_count: int, zeek_count: int, clues: Counter[str]) -> str:
    base = f"tshark parsed {packet_count} packet(s). Zeek contributed {zeek_count} structured {protocol} event(s)."
    if protocol in {"TLS", "SSL", "HTTPS"}:
        base += " Payload is encrypted; only handshake, SNI, port, timing, and flow metadata are reviewed."
    elif protocol in {"DNS", "HTTP", "FTP", "SMTP", "ICMP"}:
        base += " Netra extracted protocol metadata and suspicious clue indicators where visible."
    if clues:
        top = "; ".join(item for item, _ in clues.most_common(3))
        base += f" Top metadata clues: {top}."
    return base


def _build_timeline(packets: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alert_times = Counter((alert.get("timestamp", "")[11:16]) for alert in alerts if "T" in alert.get("timestamp", ""))
    buckets: dict[str, dict[str, Any]] = {}
    for packet in packets:
        key = packet["timestamp"][11:16] if "T" in packet["timestamp"] else packet["timestamp"][:5]
        bucket = buckets.setdefault(key, {"time": key, "mb": 0, "alerts": 0})
        bucket["mb"] += packet["size"] / 1_000_000
        if packet["riskScore"] >= 70:
            bucket["alerts"] += 1
    for key, count in alert_times.items():
        buckets.setdefault(key, {"time": key, "mb": 0, "alerts": 0})["alerts"] += count
    return [{"time": item["time"], "mb": round(item["mb"], 2), "alerts": item["alerts"]} for item in buckets.values()]


def _build_graph(sessions: list[dict[str, Any]], alerts: list[dict[str, Any]], features: dict[str, Any]) -> dict[str, Any]:
    alerts_by_session: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        for session_id in alert.get("evidenceSessionIds", []):
            alerts_by_session[session_id].append(alert)
    host_features = {item.get("ip"): item for item in features.get("hosts", [])}
    nodes = {}
    edges = []
    for session in sessions[:80]:
        session_alerts = alerts_by_session.get(session["id"], [])
        session_classes = list(dict.fromkeys(alert["attackClass"] for alert in session_alerts))
        for role in ("source", "destination"):
            host = session[role]
            host_feature = host_features.get(host, {})
            current = nodes.get(host, {"id": host, "label": host, "risk": 0, "packetCount": 0, "sessionCount": 0, "alertIds": [], "attackClasses": []})
            current["risk"] = max(current["risk"], session["riskScore"])
            current["packetCount"] = max(current["packetCount"], host_feature.get("packetCount", 0))
            current["sessionCount"] = max(current["sessionCount"], host_feature.get("sessionCount", 0))
            current["alertIds"] = list(dict.fromkeys(current["alertIds"] + [alert["id"] for alert in session_alerts]))
            current["attackClasses"] = list(dict.fromkeys(current["attackClasses"] + session_classes))
            nodes[host] = current
        edges.append({
            "source": session["source"],
            "target": session["destination"],
            "protocol": session["protocol"],
            "packets": session["packetCount"],
            "bytes": session["bytesSent"],
            "sessionId": session["id"],
            "risk": max(session["riskScore"], *(alert["confidence"] for alert in session_alerts), 0),
            "attackClass": session_classes[0] if session_classes else "Normal Baseline",
            "alertIds": [alert["id"] for alert in session_alerts],
        })
    return {"nodes": list(nodes.values()), "edges": edges}


def _score_packet(protocol: str, destination_port: int, size: int, row: dict[str, str]) -> tuple[int, str, str]:
    dns_query = row.get("dns_query", "")
    if protocol == "DNS" and (len(dns_query) > 80 or any(len(label) > 45 for label in dns_query.split("."))):
        return 92, "critical", "Possible DNS tunneling: unusually long query"
    if protocol == "ICMP" and size > 900:
        return 74, "medium", "Large ICMP payload for covert-channel review"
    if destination_port in {21, 22, 23, 25, 139, 445, 3632, 5900, 6667, 8009, 8080}:
        return 48, "low", f"Sensitive or investigation-relevant service touched on port {destination_port}"
    if protocol in {"TLS", "SSL"} and size > 1300:
        return 45, "low", "Large encrypted packet; metadata-only review"
    if size > 1400:
        return 35, "low", "Large packet observed"
    return 15, "low", "Normal packet metadata"


def _top_attack_class(alerts: list[dict[str, Any]]) -> str:
    if alerts:
        return max(alerts, key=lambda alert: alert.get("confidence", 0))["attackClass"]
    return "Normal Baseline"


def _risk_level(alerts: list[dict[str, Any]], anomalies: list[dict[str, Any]], top_attack_class: str) -> str:
    if top_attack_class == "Normal Baseline":
        return "low"
    if any(alert["severity"] == "critical" for alert in alerts) or top_attack_class in {"Remote Command Execution", "IoT Botnet / Scanning"}:
        return "critical"
    if any(alert["severity"] == "high" for alert in alerts) or any(item.get("confidence", 0) >= 90 for item in anomalies):
        return "high"
    if any(alert["severity"] == "medium" for alert in alerts) or any(item.get("confidence", 0) >= 75 for item in anomalies):
        return "medium"
    return "low"


def _chain_of_custody(now: str, case_id: str, evidence_id: str, saved: dict[str, Any], zeek: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"id": "cust-0001", "timestamp": now, "actor": "Netra analysis engine", "action": "Evidence uploaded", "caseId": case_id, "evidenceId": evidence_id, "hash": saved["sha256"], "details": f"{saved['filename']} uploaded, hashed, and stored."},
        {"id": "cust-0002", "timestamp": now, "actor": "Netra analysis engine", "action": "Packet and protocol analysis", "caseId": case_id, "evidenceId": evidence_id, "hash": saved["sha256"], "details": f"tshark parsed packet metadata; Zeek status: {zeek['status']}."},
    ]


def build_report_html(analysis: dict[str, Any], language: str = "en") -> str:
    evidence = analysis.get("evidence") or {}
    summary = analysis.get("summary", {})
    alerts = analysis.get("alerts", [])[:10]
    anomalies = analysis.get("anomalies", [])[:5]
    custody = analysis.get("chainOfCustody", [])
    ledger = analysis.get("custodyLedger", {}).get("verification", {})
    zeek = analysis.get("zeek", {})
    normalization = analysis.get("normalization") or evidence.get("normalization") or {}
    rows = "".join(f"<tr><td>{html.escape(alert['severity'])}</td><td>{html.escape(alert['attackClass'])}</td><td>{html.escape(alert['sourceIp'])}</td><td>{html.escape(alert['destination'])}</td><td>{alert['confidence']}%</td></tr>" for alert in alerts)
    anomaly_items = "".join(f"<li><strong>{html.escape(item['entity'])}</strong>: {html.escape(item['observed'])} vs {html.escape(item['baseline'])} ({item['confidence']}%)</li>" for item in anomalies)
    custody_items = "".join(f"<li>{html.escape(item['timestamp'])} - {html.escape(item['action'])} - {html.escape(item['hash'])}</li>" for item in custody)
    zeek_summary = ", ".join(f"{key}: {value}" for key, value in (zeek.get("summary") or {}).items())
    return f"""<!doctype html>
<html lang="{html.escape(language)}">
<head><meta charset="utf-8"><title>Netra forensic report {html.escape(analysis.get('caseId', ''))}</title>
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
    return json.dumps({
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
    }, indent=2)


def build_alert_csv(analysis: dict[str, Any]) -> str:
    from io import StringIO

    handle = StringIO()
    writer = csv.DictWriter(handle, fieldnames=["id", "severity", "attackClass", "type", "sourceIp", "destination", "protocol", "confidence", "status"])
    writer.writeheader()
    for alert in analysis.get("alerts", []):
        writer.writerow({key: alert.get(key, "") for key in writer.fieldnames})
    return handle.getvalue()


def _session_id(source: str, destination: str, source_port: int, destination_port: int, protocol: str) -> str:
    digest = sha256(f"{source}|{destination}|{source_port}|{destination_port}|{protocol}".encode("utf-8")).hexdigest()
    return f"sess-{digest[:10]}"


def _normalize_protocol(protocol: str, destination_port: int, source_port: int = 0) -> str:
    value = (protocol or "").upper()
    port = destination_port or source_port
    if value in {"SSL", "TLSV1.2", "TLSV1.3"} or port == 443:
        return "TLS"
    if port == 53:
        return "DNS"
    if port in {80, 8080, 8009}:
        return "HTTP"
    if port == 22:
        return "SSH"
    if port == 21:
        return "FTP"
    if port == 25:
        return "SMTP"
    if port in {139, 445}:
        return "SMB"
    return value or "UNKNOWN"


def _format_time(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _duration(start: str, end: str) -> str:
    try:
        seconds = max(0, int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()))
        if seconds < 60:
            return f"{seconds}s"
        return f"{seconds // 60}m {seconds % 60}s"
    except Exception:
        return "0s"


def _format_bytes(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f} MB"
    if value >= 1_000:
        return f"{value / 1_000:.1f} KB"
    return f"{value} B"


def _hex_preview(text: str) -> str:
    return " ".join(f"{byte:02x}" for byte in text.encode("utf-8", errors="ignore")[:32])


def _int(value: str) -> int:
    try:
        return int(value)
    except Exception:
        return 0
