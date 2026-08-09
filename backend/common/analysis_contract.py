from typing import Any


def empty_analysis() -> dict[str, Any]:
    zeek = {
        "status": "not-run", "logDir": "", "logs": [],
        "summary": {"connections": 0, "dnsQueries": 0, "httpRequests": 0, "tlsSessions": 0, "sshSessions": 0, "notices": 0, "weirdEvents": 0},
        "topServices": [], "topDnsQueries": [], "topExternalHosts": [], "records": {}, "error": "",
    }
    summary = {"packets": 0, "sessions": 0, "protocolsDecoded": 0, "payloadFindings": 0, "alerts": 0, "anomalies": 0, "topAttackClass": "Normal Baseline", "riskLevel": "low", "toolStatus": {}, "zeek": zeek}
    return {
        "caseId": "", "jobId": "", "evidenceId": "", "createdAt": "", "riskLevel": "low",
        "topAttackClass": "Normal Baseline", "detectedAttackClasses": [], "toolStatus": {}, "zeek": zeek,
        "features": {"hosts": [], "services": [], "dns": [], "timing": [], "zeek": [], "summary": {}},
        "chainOfCustody": [], "evidence": None, "case": None, "packets": [], "sessions": [],
        "decodedProtocols": [], "payloadFindings": [], "alerts": [], "detectionMatches": [], "anomalies": [],
        "trafficTimeline": [], "protocolChartData": [], "graph": {"nodes": [], "edges": []}, "summary": summary,
    }
