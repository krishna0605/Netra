from __future__ import annotations

from typing import Any

from django.conf import settings

from netra_ml.explanations import recommended_action
from netra_ml.modeling import score_with_model


def score_anomalies(features: dict[str, Any], sessions: list[dict[str, Any]], alerts: list[dict[str, Any]], filename: str = "") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    summary = features.get("summary", {})
    hosts = features.get("hosts", [])
    services = features.get("services", [])

    for host in hosts[:8]:
        if host.get("uniqueDestinations", 0) >= 20:
            rows.append(_record(host["ip"], "High destination fan-out", "Typical host contacts fewer than 20 destinations in this capture", f"{host['uniqueDestinations']} unique destinations", f"{max(1, host['uniqueDestinations'] // 10)}x", min(96, 70 + host["uniqueDestinations"]), "Scanning, botnet propagation, or reconnaissance", ["uniqueDestinations", "sessionCount", "topProtocol"]))
        if host.get("uniqueDestinationPorts", 0) >= 8:
            rows.append(_record(host["ip"], "High port fan-out", "Typical host touches fewer than 8 destination ports", f"{host['uniqueDestinationPorts']} destination ports", f"{max(1, host['uniqueDestinationPorts'] // 4)}x", min(94, 68 + host["uniqueDestinationPorts"] * 2), "Port scan or service discovery", ["uniqueDestinationPorts", "sensitivePortsTouched", "packetCount"]))
        if host.get("sessionCount", 0) >= 50 and host.get("sensitivePortsTouched"):
            rows.append(_record(host["ip"], "High repeated service access", "Typical host contacts a sensitive service fewer than 20 times in this baseline", f"{host['sessionCount']} sessions touching {host['sensitivePortsTouched']}", f"{max(2, host['sessionCount'] // 20)}x", min(97, 76 + host["sessionCount"] // 6), "Credential brute force or scripted authentication attempt", ["sessionCount", "sensitivePortsTouched", "destinationConcentration"]))
        if host.get("byteCount", 0) > 5_000_000:
            rows.append(_record(host["ip"], "High single-host traffic concentration", "Typical host contributes a smaller share of bytes", f"{_fmt(host['byteCount'])} from one source", "high volume", min(90, 72 + host["byteCount"] // 1_000_000), "Bulk transfer, exfiltration, or replayed traffic", ["byteCount", "packetCount", "topDestination"]))

    if summary.get("longestDnsQuery", 0) > 80:
        rows.append(_record(summary.get("topTalker", "DNS client"), "Long DNS query pattern", "Typical DNS names are short labels under 80 characters", f"Longest DNS query is {summary['longestDnsQuery']} characters", f"{round(summary['longestDnsQuery'] / 40, 1)}x", 92, "DNS tunneling or encoded payload inside DNS metadata", ["longestDnsQuery", "averageDnsQueryLength", "repeatedDnsDomainCount"]))
    if summary.get("dnsQueryCount", 0) >= 100:
        rows.append(_record(summary.get("topTalker", "DNS client"), "High DNS query volume", "Typical capture baseline has fewer DNS lookups", f"{summary['dnsQueryCount']} DNS queries", "high volume", min(90, 70 + summary["dnsQueryCount"] // 20), "Automated lookup, tunnel, or malware resolver behavior", ["dnsQueryCount", "repeatedDnsDomainCount"]))
    if summary.get("largestSessionBytes", 0) > 5_000_000:
        rows.append(_record(summary.get("topTalker", "host"), "Large outbound transfer", "Typical session is below 5 MB in this demo baseline", f"Largest session is {_fmt(summary['largestSessionBytes'])}", "large transfer", 88, "Data exfiltration or bulk file movement", ["largestSessionBytes", "dominantProtocol", "topService"]))
    if summary.get("beaconPairs", 0):
        rows.append(_record(summary.get("topTalker", "host pair"), "Beacon-like repeated communication", "Typical traffic has irregular timing", f"{summary['beaconPairs']} host pair(s) with repeated intervals", "periodic", 84, "Malware C2 beaconing or scheduled automated task", ["beaconPairs", "averageIntervalSeconds"]))

    for service in services[:5]:
        if service.get("riskHints") and service.get("port") not in {53, 80, 443}:
            rows.append(_record(f"{service.get('service')}:{service.get('port')}", "Rare or sensitive service usage", "Baseline services should be expected and justified", f"{service.get('packetCount', 0)} packets, {service.get('sessionCount', 0)} sessions", "service risk", min(90, 68 + service.get("sessionCount", 0)), "Sensitive service access or exploitation attempt", ["service", "port", "riskHints"]))

    if not rows and alerts:
        alert = alerts[0]
        rows.append(_record(alert["sourceIp"], "Alert-backed anomaly", "No strong statistical baseline, but detector confidence is high", f"{alert['attackClass']} at {alert['confidence']}% confidence", "detector-backed", alert["confidence"], alert["type"], ["attackClass", "confidence", "evidenceSessionIds"]))

    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in rows:
        key = (item["entity"], item["behaviour"])
        if key not in deduped or item["confidence"] > deduped[key]["confidence"]:
            deduped[key] = item
    output = sorted(deduped.values(), key=lambda item: item["confidence"], reverse=True)[:20]
    for index, item in enumerate(output, start=1):
        item["id"] = f"anom-{index:04d}"
        item["recommendedAction"] = recommended_action(item["behaviour"], item["hypothesis"])
    model_score = score_with_model(features, settings.BASE_DIR.parent / "ml-services" / "anomaly-engine" / "models" / "anomaly-model.pkl")
    if model_score:
        for item in output:
            item.update(model_score)
            item["confidence"] = max(item["confidence"], model_score["mlAnomalyScore"])
        if not output and model_score["mlPrediction"] == "anomalous":
            output.append(_record(summary.get("topTalker", "capture"), "ML-assisted anomaly", "Trained benchmark model expected lower-risk feature mix", f"Model score {model_score['mlAnomalyScore']}%", "model-assisted", model_score["mlAnomalyScore"], "Unknown or mixed suspicious behavior", ["modelVersion", "featureSchema"]))
            output[-1].update(model_score)
            output[-1]["id"] = "anom-0001"
            output[-1]["recommendedAction"] = recommended_action(output[-1]["behaviour"], output[-1]["hypothesis"])
    return [item for item in output if item["confidence"] >= 50]


def _record(entity: str, behaviour: str, baseline: str, observed: str, deviation: str, confidence: int, hypothesis: str, top_features: list[str]) -> dict[str, Any]:
    return {
        "id": "",
        "entity": entity,
        "behaviour": behaviour,
        "baseline": baseline,
        "observed": observed,
        "deviation": deviation,
        "confidence": max(50, min(99, int(confidence))),
        "hypothesis": hypothesis,
        "topFeatures": top_features,
        "recommendedAction": "",
    }


def _fmt(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f} MB"
    if value >= 1_000:
        return f"{value / 1_000:.1f} KB"
    return f"{value} B"
