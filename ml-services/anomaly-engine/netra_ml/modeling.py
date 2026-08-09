from __future__ import annotations

from pathlib import Path
from typing import Any


FEATURE_NAMES = [
    "internalHostCount", "externalHostCount", "uniquePorts", "maxDestinationFanout",
    "maxPortFanout", "largestSessionBytes", "longestDnsQuery", "averageDnsQueryLength",
    "repeatedDnsDomainCount", "icmpLargePacketCount", "beaconPairs", "sshConnectionCount",
    "dnsQueryCount", "hostRiskHintCount", "serviceRiskHintCount",
]


def vectorize_features(features: dict[str, Any]) -> list[float]:
    summary = features.get("summary", {}) or {}
    hosts = features.get("hosts", []) or []
    services = features.get("services", []) or []
    values = {
        **{name: summary.get(name, 0) for name in FEATURE_NAMES},
        "hostRiskHintCount": sum(len(row.get("riskHints", [])) for row in hosts),
        "serviceRiskHintCount": sum(len(row.get("riskHints", [])) for row in services),
    }
    return [float(values[name] or 0) for name in FEATURE_NAMES]


def train_model(rows: list[dict[str, Any]], model_path: Path, metadata_path: Path) -> dict[str, Any]:
    del rows, model_path, metadata_path
    raise RuntimeError(
        "Executable Python model export is disabled. A future reviewed release must use signed ONNX provenance and held-out evaluation."
    )
