import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class DetectorDefinition:
    rule_id: str
    title: str
    description: str
    category: str
    attack_class: str
    keywords: tuple[str, ...]
    signals: tuple[str, ...]
    limitations: tuple[str, ...]
    severity: str
    confidence_factors: tuple[str, ...]
    evidence_requirements: tuple[str, ...]


def _rule(rule_id, title, category, attack_class, severity, signals, keywords=()):
    return DetectorDefinition(
        rule_id, title, f"Flags {attack_class} indicators for investigator review.", category,
        attack_class, tuple(keywords), tuple(signals),
        ("Network metadata alone does not establish attribution.", "Correlate with endpoint and service logs."),
        severity, tuple(signals), ("One or more validated entity-level signals",),
    )


DETECTOR_REGISTRY = {
    item.rule_id: item
    for item in (
        _rule("rule-bruteforce-ssh-ftp", "SSH/FTP credential brute force", "Credential Attack", "Credential Brute Force", "high", ("repeated authentication sessions",), ("ssh", "ftp", "authentication", "repeated")),
        _rule("rule-botnet-telnet-scanning", "Telnet botnet scanning", "Reconnaissance / Botnet", "IoT Botnet / Scanning", "critical", ("telnet fan-out",), ("telnet", "scan", "botnet")),
        _rule("rule-port-scan-reconnaissance", "Port-scan reconnaissance", "Reconnaissance", "Port Scan / Reconnaissance", "high", ("destination fan-out", "port fan-out"), ("scan", "fan-out", "reconnaissance")),
        _rule("rule-malware-c2-beacon", "Malware C2 beaconing", "Malware Communication", "Malware C2 / Beaconing", "high", ("periodic external communication",), ("beacon", "periodic", "command", "control")),
        _rule("rule-dns-tunnel", "DNS tunneling pattern", "Covert Channels", "DNS Tunnel", "critical", ("long DNS query", "DNS query volume"), ("dns", "query", "tunnel")),
        _rule("rule-icmp-tunnel", "ICMP tunneling pattern", "Covert Channels", "ICMP Tunnel", "medium", ("repeated large ICMP packets",), ("icmp", "payload", "covert")),
        _rule("rule-data-exfiltration", "Large outbound transfer", "Exfiltration", "Data Exfiltration", "high", ("large session bytes",), ("outbound", "large", "transfer")),
        _rule("rule-remote-command-execution", "Remote command execution", "Service Exploitation", "Remote Command Execution", "critical", ("distcc service traffic",), ("distcc", "rce", "execution")),
        _rule("rule-service-exploit-web", "Web-service exploitation", "Service Exploitation", "Web Service Exploitation", "high", ("repeated application-service traffic",), ("web", "service", "exploit")),
        _rule("rule-smb-netbios-lateral", "SMB/NetBIOS lateral movement", "Lateral Movement", "SMB / NetBIOS Lateral Movement", "high", ("internal SMB/NetBIOS sessions",), ("smb", "netbios", "lateral")),
        _rule("rule-smtp-suspicious", "Suspicious SMTP transfer", "Data Transfer", "Suspicious SMTP Transfer", "medium", ("high SMTP packet volume",), ("smtp", "mail", "transfer")),
    )
}


def detector_definition(rule_id: str) -> DetectorDefinition:
    try:
        return DETECTOR_REGISTRY[rule_id]
    except KeyError as exc:
        raise ValueError(f"Unknown detector rule: {rule_id}") from exc


def load_rules() -> list[dict[str, Any]]:
    return [
        {
            **asdict(item),
            "id": item.rule_id,
            "name": item.title,
            "attack_class": item.attack_class,
            "productionActive": True,
        }
        for item in DETECTOR_REGISTRY.values()
    ]


def classify_detection(record: dict[str, Any]) -> list[dict[str, Any]]:
    text = json.dumps(record, sort_keys=True).lower()
    matches = []
    for rule in DETECTOR_REGISTRY.values():
        matched = [keyword for keyword in rule.keywords if keyword.lower() in text]
        if not matched:
            continue
        confidence = min(95, 55 + len(matched) * 10)
        matches.append({"ruleId": rule.rule_id, "ruleName": rule.title, "category": rule.category, "confidence": confidence, "attackClass": rule.attack_class})
    return matches
