from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from statistics import mean
from typing import Any


PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    1099: "JAVA-RMI",
    139: "NETBIOS",
    443: "TLS",
    445: "SMB",
    3389: "RDP",
    3632: "DISTCC",
    5900: "VNC",
    6667: "IRC",
    8009: "AJP",
    8080: "HTTP",
}
SENSITIVE_PORTS = {21, 22, 23, 25, 1099, 139, 445, 3389, 3632, 5900, 6667, 8009, 8080}


def extract_features(packets: list[dict[str, Any]], sessions: list[dict[str, Any]], zeek: dict[str, Any] | None = None, filename: str = "") -> dict[str, Any]:
    zeek = zeek or {}
    hosts = _host_features(packets, sessions)
    services = _service_features(packets, sessions)
    dns = _dns_features(packets, zeek)
    timing = _timing_features(packets)
    zeek_features = _zeek_features(zeek)
    summary = _summary_features(hosts, services, dns, sessions, packets, timing, zeek, filename)
    return {
        "hosts": hosts,
        "services": services,
        "dns": dns,
        "timing": timing,
        "zeek": zeek_features,
        "summary": summary,
    }


def _host_features(packets: list[dict[str, Any]], sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_host: dict[str, dict[str, Any]] = {}
    session_ids_by_host: dict[str, set[str]] = defaultdict(set)
    session_evidence_by_host: dict[str, list[str]] = defaultdict(list)
    destinations_by_host: dict[str, Counter[str]] = defaultdict(Counter)
    protocols_by_host: dict[str, Counter[str]] = defaultdict(Counter)
    ports_by_host: dict[str, set[int]] = defaultdict(set)
    dns_by_host: Counter[str] = Counter()

    for packet in packets:
        source = packet.get("sourceIp", "unknown")
        destination = packet.get("destinationIp", "unknown")
        item = by_host.setdefault(source, {"ip": source, "packetCount": 0, "byteCount": 0})
        item["packetCount"] += 1
        item["byteCount"] += int(packet.get("size", 0))
        destinations_by_host[source][destination] += 1
        protocols_by_host[source][packet.get("protocol", "UNKNOWN")] += 1
        port = int(packet.get("destinationPort") or 0)
        if port:
            ports_by_host[source].add(port)
        if packet.get("protocol") == "DNS":
            dns_by_host[source] += 1
        session_ids_by_host[source].add(packet.get("sessionId", ""))

    for session in sessions:
        source = session.get("source", "unknown")
        if session.get("id"):
            session_evidence_by_host[source].append(session["id"])

    rows = []
    for host, item in by_host.items():
        ports = sorted(ports_by_host[host])
        hints = []
        if len(destinations_by_host[host]) >= 20:
            hints.append("high-destination-fanout")
        if len(ports) >= 8:
            hints.append("high-port-fanout")
        if any(port in SENSITIVE_PORTS for port in ports):
            hints.append("sensitive-service")
        if item["packetCount"] >= 500:
            hints.append("high-packet-volume")
        rows.append({
            "ip": host,
            "packetCount": item["packetCount"],
            "byteCount": item["byteCount"],
            "uniqueDestinations": len(destinations_by_host[host]),
            "uniqueDestinationPorts": len(ports),
            "sessionCount": len(session_ids_by_host[host]),
            "topProtocol": protocols_by_host[host].most_common(1)[0][0] if protocols_by_host[host] else "UNKNOWN",
            "topDestination": destinations_by_host[host].most_common(1)[0][0] if destinations_by_host[host] else "unknown",
            "sensitivePortsTouched": [port for port in ports if port in SENSITIVE_PORTS],
            "dnsQueryCount": dns_by_host[host],
            "riskHints": hints,
            "evidenceSessionIds": session_evidence_by_host[host][:10],
        })
    return sorted(rows, key=lambda row: (len(row["riskHints"]), row["sessionCount"], row["packetCount"]), reverse=True)[:50]


def _service_features(packets: list[dict[str, Any]], sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_port: dict[int, dict[str, Any]] = {}
    sources: dict[int, Counter[str]] = defaultdict(Counter)
    destinations: dict[int, Counter[str]] = defaultdict(Counter)
    evidence_sessions: dict[int, list[str]] = defaultdict(list)
    for packet in packets:
        port = int(packet.get("destinationPort") or 0)
        if not port:
            continue
        item = by_port.setdefault(port, {"port": port, "service": PORT_SERVICES.get(port, packet.get("protocol") or "UNKNOWN"), "packetCount": 0, "byteCount": 0})
        item["packetCount"] += 1
        item["byteCount"] += int(packet.get("size", 0))
        sources[port][packet.get("sourceIp", "unknown")] += 1
        destinations[port][packet.get("destinationIp", "unknown")] += 1
    for session in sessions:
        for port in (21, 22, 23, 25, 53, 80, 1099, 139, 443, 445, 3389, 3632, 5900, 6667, 8009, 8080):
            if session.get("protocol") == PORT_SERVICES.get(port) or (PORT_SERVICES.get(port) == "HTTP" and session.get("protocol") == "HTTP"):
                evidence_sessions[port].append(session["id"])

    rows = []
    for port, item in by_port.items():
        hints = []
        if port in {21, 22} and item["packetCount"] >= 40:
            hints.append("repeated-auth-service-access")
        if port in SENSITIVE_PORTS:
            hints.append("sensitive-service")
        if len(destinations[port]) >= 20:
            hints.append("service-destination-fanout")
        rows.append({
            **item,
            "sessionCount": len(evidence_sessions[port]) or max(1, len(sources[port])),
            "sourceCount": len(sources[port]),
            "destinationCount": len(destinations[port]),
            "topSource": sources[port].most_common(1)[0][0] if sources[port] else "unknown",
            "topDestination": destinations[port].most_common(1)[0][0] if destinations[port] else "unknown",
            "riskHints": hints,
            "evidenceSessionIds": evidence_sessions[port][:10],
        })
    return sorted(rows, key=lambda row: (len(row["riskHints"]), row["sessionCount"], row["packetCount"]), reverse=True)[:50]


def _dns_features(packets: list[dict[str, Any]], zeek: dict[str, Any]) -> list[dict[str, Any]]:
    queries = [packet.get("dnsQuery", "") for packet in packets if packet.get("protocol") == "DNS" and packet.get("dnsQuery")]
    for row in (zeek.get("records", {}) or {}).get("dns.log", []):
        query = row.get("query")
        if query and query != "-":
            queries.append(query)
    counts = Counter(queries)
    rows = []
    for query, count in counts.most_common(25):
        labels = query.split(".")
        rows.append({
            "query": query,
            "count": count,
            "length": len(query),
            "longestLabel": max((len(label) for label in labels), default=0),
            "riskHints": [hint for hint, active in {
                "long-query": len(query) > 80,
                "long-label": any(len(label) > 45 for label in labels),
                "repeated-domain": count >= 10,
            }.items() if active],
        })
    return rows


def _timing_features(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pairs: dict[tuple[str, str], list[float]] = defaultdict(list)
    for packet in packets:
        try:
            timestamp = datetime.fromisoformat(packet["timestamp"]).timestamp()
        except Exception:
            continue
        pairs[(packet.get("sourceIp", "unknown"), packet.get("destinationIp", "unknown"))].append(timestamp)
    rows = []
    for (source, destination), timestamps in pairs.items():
        if len(timestamps) < 4:
            continue
        timestamps.sort()
        intervals = [round(timestamps[index] - timestamps[index - 1], 3) for index in range(1, len(timestamps))]
        if not intervals:
            continue
        avg = mean(intervals)
        repeated = sum(1 for value in intervals if avg and abs(value - avg) <= max(0.2, avg * 0.15))
        rows.append({
            "source": source,
            "destination": destination,
            "packetCount": len(timestamps),
            "averageIntervalSeconds": round(avg, 3),
            "repeatedIntervalCount": repeated,
            "beaconLike": repeated >= 5 and len(set(round(value, 1) for value in intervals)) <= 4,
        })
    return sorted(rows, key=lambda row: (row["beaconLike"], row["packetCount"]), reverse=True)[:30]


def _zeek_features(zeek: dict[str, Any]) -> list[dict[str, Any]]:
    summary = zeek.get("summary", {})
    return [
        {"name": "connections", "value": summary.get("connections", 0)},
        {"name": "dnsQueries", "value": summary.get("dnsQueries", 0)},
        {"name": "httpRequests", "value": summary.get("httpRequests", 0)},
        {"name": "tlsSessions", "value": summary.get("tlsSessions", 0)},
        {"name": "sshSessions", "value": summary.get("sshSessions", 0)},
        {"name": "weirdEvents", "value": summary.get("weirdEvents", 0)},
    ]


def _summary_features(hosts: list[dict[str, Any]], services: list[dict[str, Any]], dns: list[dict[str, Any]], sessions: list[dict[str, Any]], packets: list[dict[str, Any]], timing: list[dict[str, Any]], zeek: dict[str, Any], filename: str) -> dict[str, Any]:
    all_hosts = {packet.get("sourceIp") for packet in packets} | {packet.get("destinationIp") for packet in packets}
    top_host = hosts[0] if hosts else {}
    top_service = services[0] if services else {}
    largest_session = max((session.get("bytesSent", 0) for session in sessions), default=0)
    longest_dns = max((row.get("length", 0) for row in dns), default=0)
    avg_dns = round(mean([row.get("length", 0) for row in dns]), 2) if dns else 0
    return {
        "filename": filename,
        "internalHostCount": sum(1 for host in all_hosts if _is_private(host or "")),
        "externalHostCount": sum(1 for host in all_hosts if host and not _is_private(host)),
        "uniquePorts": len({item.get("port") for item in services}),
        "dominantProtocol": top_host.get("topProtocol") or "UNKNOWN",
        "topTalker": top_host.get("ip") or "unknown",
        "topService": top_service.get("service") or "UNKNOWN",
        "maxDestinationFanout": max((item.get("uniqueDestinations", 0) for item in hosts), default=0),
        "maxPortFanout": max((item.get("uniqueDestinationPorts", 0) for item in hosts), default=0),
        "largestSessionBytes": largest_session,
        "longestDnsQuery": longest_dns,
        "averageDnsQueryLength": avg_dns,
        "repeatedDnsDomainCount": sum(1 for item in dns if item.get("count", 0) >= 10),
        "icmpLargePacketCount": sum(1 for packet in packets if packet.get("protocol") == "ICMP" and int(packet.get("size", 0)) > 900),
        "beaconPairs": sum(1 for item in timing if item.get("beaconLike")),
        "sshConnectionCount": (zeek.get("summary", {}) or {}).get("sshSessions", 0),
        "dnsQueryCount": (zeek.get("summary", {}) or {}).get("dnsQueries", 0) or sum(1 for packet in packets if packet.get("protocol") == "DNS"),
    }


def _is_private(ip: str) -> bool:
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.30.") or ip.startswith("172.31.") or ip in {"unknown", ""}
