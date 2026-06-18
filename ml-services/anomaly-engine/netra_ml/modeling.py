from __future__ import annotations

import json
import pickle
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FEATURE_NAMES = [
    "internalHostCount",
    "externalHostCount",
    "uniquePorts",
    "maxDestinationFanout",
    "maxPortFanout",
    "largestSessionBytes",
    "longestDnsQuery",
    "averageDnsQueryLength",
    "repeatedDnsDomainCount",
    "icmpLargePacketCount",
    "beaconPairs",
    "sshConnectionCount",
    "dnsQueryCount",
    "hostRiskHintCount",
    "serviceRiskHintCount",
]


def vectorize_features(features: dict[str, Any]) -> list[float]:
    summary = features.get("summary", {}) or {}
    hosts = features.get("hosts", []) or []
    services = features.get("services", []) or []
    values = {
        "internalHostCount": summary.get("internalHostCount", 0),
        "externalHostCount": summary.get("externalHostCount", 0),
        "uniquePorts": summary.get("uniquePorts", 0),
        "maxDestinationFanout": summary.get("maxDestinationFanout", 0),
        "maxPortFanout": summary.get("maxPortFanout", 0),
        "largestSessionBytes": summary.get("largestSessionBytes", 0),
        "longestDnsQuery": summary.get("longestDnsQuery", 0),
        "averageDnsQueryLength": summary.get("averageDnsQueryLength", 0),
        "repeatedDnsDomainCount": summary.get("repeatedDnsDomainCount", 0),
        "icmpLargePacketCount": summary.get("icmpLargePacketCount", 0),
        "beaconPairs": summary.get("beaconPairs", 0),
        "sshConnectionCount": summary.get("sshConnectionCount", 0),
        "dnsQueryCount": summary.get("dnsQueryCount", 0),
        "hostRiskHintCount": sum(len(row.get("riskHints", [])) for row in hosts),
        "serviceRiskHintCount": sum(len(row.get("riskHints", [])) for row in services),
    }
    return [float(values[name] or 0) for name in FEATURE_NAMES]


def train_model(rows: list[dict[str, Any]], model_path: Path, metadata_path: Path) -> dict[str, Any]:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

    if len(rows) < 2:
        raise ValueError("At least two labeled captures are required to train an anomaly model.")
    x = [row["vector"] for row in rows]
    y = [int(row["label"]) for row in rows]
    if len(set(y)) >= 2:
        model_type = "RandomForestClassifier"
        model = RandomForestClassifier(n_estimators=80, random_state=42, class_weight="balanced")
        model.fit(x, y)
        predictions = [int(value) for value in model.predict(x)]
        scores = [float(prob[1]) if len(prob) > 1 else 0.0 for prob in model.predict_proba(x)]
    else:
        model_type = "IsolationForest"
        model = IsolationForest(n_estimators=80, contamination="auto", random_state=42)
        model.fit(x)
        raw = model.predict(x)
        predictions = [1 if value == -1 else 0 for value in raw]
        scores = [float(-value) for value in model.decision_function(x)]

    precision, recall, f1, _ = precision_recall_fscore_support(y, predictions, average="binary", zero_division=0)
    matrix = confusion_matrix(y, predictions, labels=[0, 1]).tolist()
    metadata = {
        "version": f"netra-anomaly-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "modelType": model_type,
        "trainedAt": datetime.now(timezone.utc).isoformat(),
        "featureNames": FEATURE_NAMES,
        "trainingRows": len(rows),
        "metrics": {
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "confusionMatrix": matrix,
        },
        "limitations": [
            "This model is trained on the available local benchmark manifest and is not independent legal certification.",
            "Fallback explainable scoring remains active when the model artifact is unavailable.",
        ],
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_bytes(pickle.dumps({"model": model, "metadata": metadata}))
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata | {"rows": [{"id": row["id"], "label": row["label"], "prediction": prediction, "score": round(score, 4)} for row, prediction, score in zip(rows, predictions, scores)]}


def load_model(model_path: Path) -> tuple[Any, dict[str, Any]] | None:
    if not model_path.exists():
        return None
    payload = pickle.loads(model_path.read_bytes())
    return payload["model"], payload.get("metadata", {})


def score_with_model(features: dict[str, Any], model_path: Path) -> dict[str, Any] | None:
    loaded = load_model(model_path)
    if not loaded:
        return None
    model, metadata = loaded
    vector = [vectorize_features(features)]
    if hasattr(model, "predict_proba"):
        probability = float(model.predict_proba(vector)[0][1])
        prediction = int(model.predict(vector)[0])
        score = round(probability * 100)
    else:
        prediction = 1 if int(model.predict(vector)[0]) == -1 else 0
        score = 75 if prediction else 25
    return {
        "modelVersion": metadata.get("version", "unknown"),
        "modelType": metadata.get("modelType", type(model).__name__),
        "mlAnomalyScore": max(0, min(99, int(score))),
        "mlPrediction": "anomalous" if prediction else "baseline",
        "featureSchema": metadata.get("featureNames", FEATURE_NAMES),
    }
