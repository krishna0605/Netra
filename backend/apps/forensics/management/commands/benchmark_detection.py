from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from django.core.management.base import BaseCommand

from common.analysis import MAX_PACKETS, analyze_pcap


class Command(BaseCommand):
    help = "Run Netra detector/anomaly benchmark against a labeled PCAP manifest."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--manifest", required=True, help="Path to labeled benchmark manifest JSON.")
        parser.add_argument("--pcap-root", default="", help="Directory containing PCAP files. Defaults to manifest directory.")
        parser.add_argument("--output-dir", default="docs/benchmarks", help="Directory for JSON and Markdown benchmark outputs.")
        parser.add_argument("--fail-under-f1", type=float, default=0.0, help="Fail if multilabel F1 is below this value.")
        parser.add_argument("--max-cases", type=int, default=0, help="Optional limit for quick smoke runs.")

    def handle(self, *args, **options) -> None:
        manifest_path = Path(options["manifest"]).resolve()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        pcap_root = Path(options["pcap_root"]).resolve() if options["pcap_root"] else manifest_path.parent
        output_dir = Path(options["output_dir"]).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        cases = manifest.get("cases", [])
        if options["max_cases"]:
            cases = cases[: options["max_cases"]]
        if not cases:
            raise SystemExit("Benchmark manifest has no cases.")

        started = datetime.now(timezone.utc)
        rows: list[dict[str, Any]] = []
        labels: set[str] = set()
        tp = fp = fn = 0
        benign_total = benign_correct = 0
        per_class: dict[str, Counter[str]] = defaultdict(Counter)

        for index, item in enumerate(cases, start=1):
            pcap_path = pcap_root / item["file"]
            if not pcap_path.exists():
                raise SystemExit(f"Missing benchmark PCAP: {pcap_path}")
            expected = set(item.get("expectedAttackClasses", []))
            labels.update(expected)
            case_id = f"BENCH-{item['id']}"
            evidence_id = f"bench-ev-{uuid4().hex[:8]}"
            job_id = f"bench-job-{uuid4().hex[:8]}"
            digest = _sha256(pcap_path)
            saved = {
                "filename": pcap_path.name,
                "size_bytes": pcap_path.stat().st_size,
                "sha256": digest,
                "plaintext_sha256": digest,
                "encrypted_sha256": "",
                "stored_path": str(pcap_path),
                "intake": {"packetLimit": str(MAX_PACKETS)},
            }
            self.stdout.write(f"[{index}/{len(cases)}] analyzing {pcap_path.name}")
            try:
                analysis = analyze_pcap(pcap_path, case_id, evidence_id, job_id, saved)
                predicted = set(analysis.get("detectedAttackClasses") or [])
                if analysis.get("topAttackClass") and analysis.get("topAttackClass") != "Normal Baseline":
                    predicted.add(analysis["topAttackClass"])
                predicted.discard("Normal Baseline")
                error = ""
            except Exception as exc:
                analysis = {}
                predicted = set()
                error = f"{type(exc).__name__}: {exc}"

            labels.update(predicted)
            case_tp = len(expected & predicted)
            case_fp = len(predicted - expected)
            case_fn = len(expected - predicted)
            tp += case_tp
            fp += case_fp
            fn += case_fn
            for label in expected | predicted:
                if label in expected and label in predicted:
                    per_class[label]["tp"] += 1
                elif label in predicted:
                    per_class[label]["fp"] += 1
                else:
                    per_class[label]["fn"] += 1
            if item.get("benign"):
                benign_total += 1
                if not predicted and not error:
                    benign_correct += 1

            anomalies = analysis.get("anomalies", []) if analysis else []
            alerts = analysis.get("alerts", []) if analysis else []
            rows.append(
                {
                    "id": item["id"],
                    "file": item["file"],
                    "expectedAttackClasses": sorted(expected),
                    "predictedAttackClasses": sorted(predicted),
                    "topAttackClass": analysis.get("topAttackClass", "analysis-failed") if analysis else "analysis-failed",
                    "riskLevel": analysis.get("riskLevel", "unknown") if analysis else "unknown",
                    "packets": len(analysis.get("packets", [])) if analysis else 0,
                    "sessions": len(analysis.get("sessions", [])) if analysis else 0,
                    "alerts": len(alerts),
                    "anomalies": len(anomalies),
                    "maxAlertConfidence": max((alert.get("confidence", 0) for alert in alerts), default=0),
                    "maxAnomalyConfidence": max((row.get("confidence", 0) for row in anomalies), default=0),
                    "truePositives": case_tp,
                    "falsePositives": case_fp,
                    "falseNegatives": case_fn,
                    "passed": case_fp == 0 and case_fn == 0 and not error,
                    "error": error,
                    "notes": item.get("notes", ""),
                }
            )

        precision = tp / (tp + fp) if tp + fp else (1.0 if tp == 0 and fp == 0 else 0.0)
        recall = tp / (tp + fn) if tp + fn else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
        benign_accuracy = benign_correct / benign_total if benign_total else None
        completed = datetime.now(timezone.utc)
        result = {
            "version": manifest.get("version", "unknown"),
            "startedAt": started.isoformat(),
            "completedAt": completed.isoformat(),
            "caseCount": len(rows),
            "metrics": {
                "truePositives": tp,
                "falsePositives": fp,
                "falseNegatives": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "benignAccuracy": round(benign_accuracy, 4) if benign_accuracy is not None else None,
            },
            "perClass": {
                label: {
                    "tp": per_class[label]["tp"],
                    "fp": per_class[label]["fp"],
                    "fn": per_class[label]["fn"],
                    "precision": _safe_div(per_class[label]["tp"], per_class[label]["tp"] + per_class[label]["fp"]),
                    "recall": _safe_div(per_class[label]["tp"], per_class[label]["tp"] + per_class[label]["fn"]),
                }
                for label in sorted(labels)
            },
            "rows": rows,
            "limitations": [
                "This benchmark uses a small labeled PCAP corpus and measures deterministic behavior rules plus explainable anomaly scoring.",
                "Scores are engineering smoke metrics, not independent law-enforcement accuracy certification.",
                "PCAP-only evidence cannot prove account compromise without endpoint/server log correlation.",
            ],
        }
        stamp = completed.strftime("%Y%m%d-%H%M%S")
        json_path = output_dir / f"phase6-detection-benchmark-{stamp}.json"
        md_path = output_dir / f"phase6-detection-benchmark-{stamp}.md"
        json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        md_path.write_text(_markdown(result), encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Benchmark JSON: {json_path}"))
        self.stdout.write(self.style.SUCCESS(f"Benchmark report: {md_path}"))
        self.stdout.write(self.style.SUCCESS(f"F1={result['metrics']['f1']} precision={result['metrics']['precision']} recall={result['metrics']['recall']}"))
        if f1 < options["fail_under_f1"]:
            raise SystemExit(f"Benchmark F1 {f1:.4f} is below required {options['fail_under_f1']:.4f}.")


def _sha256(path: Path) -> str:
    h = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_div(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else (1.0 if numerator == 0 else 0.0)


def _markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Netra Phase 6 Detection Benchmark",
        "",
        f"- Version: `{result['version']}`",
        f"- Started: `{result['startedAt']}`",
        f"- Completed: `{result['completedAt']}`",
        f"- Cases: `{result['caseCount']}`",
        "",
        "## Summary Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in result["metrics"].items():
        lines.append(f"| {key} | {value} |")
    lines += [
        "",
        "## Case Results",
        "",
        "| Case | Expected | Predicted | Alerts | Anomalies | Max Alert | Max Anomaly | Result |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    for row in result["rows"]:
        expected = ", ".join(row["expectedAttackClasses"]) or "Benign"
        predicted = ", ".join(row["predictedAttackClasses"]) or "None"
        status = "PASS" if row["passed"] else "REVIEW"
        if row["error"]:
            status = f"ERROR: {row['error']}"
        lines.append(f"| {row['file']} | {expected} | {predicted} | {row['alerts']} | {row['anomalies']} | {row['maxAlertConfidence']} | {row['maxAnomalyConfidence']} | {status} |")
    lines += [
        "",
        "## Per-Class Metrics",
        "",
        "| Class | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label, metrics in result["perClass"].items():
        lines.append(f"| {label} | {metrics['tp']} | {metrics['fp']} | {metrics['fn']} | {metrics['precision']} | {metrics['recall']} |")
    lines += [
        "",
        "## Limitations",
        "",
    ]
    lines.extend(f"- {item}" for item in result["limitations"])
    lines.append("")
    return "\n".join(lines)
