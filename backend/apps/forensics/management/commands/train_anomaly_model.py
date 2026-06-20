from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from django.core.management.base import BaseCommand, CommandError

from common.analysis import MAX_PACKETS, analyze_pcap
from netra_ml.modeling import train_model, vectorize_features


class Command(BaseCommand):
    help = "Train and benchmark the Netra anomaly model from a labeled PCAP manifest."

    def add_arguments(self, parser):
        parser.add_argument("--manifest", required=True)
        parser.add_argument("--pcap-root", default="")
        parser.add_argument("--model-dir", default="ml-services/anomaly-engine/models")
        parser.add_argument("--output-dir", default="Miscellaneous/docs/benchmarks")
        parser.add_argument("--fail-under-f1", type=float, default=0.0)

    def handle(self, *args, **options):
        manifest_path = Path(options["manifest"]).resolve()
        if not manifest_path.exists():
            raise CommandError(f"Missing manifest: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        pcap_root = Path(options["pcap_root"]).resolve() if options["pcap_root"] else manifest_path.parent
        model_dir = Path(options["model_dir"]).resolve()
        output_dir = Path(options["output_dir"]).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        rows = []
        for item in manifest.get("cases", []):
            pcap_path = pcap_root / item["file"]
            if not pcap_path.exists():
                raise CommandError(f"Missing PCAP for ML training: {pcap_path}")
            digest = _sha256(pcap_path)
            saved = {
                "filename": pcap_path.name,
                "size_bytes": pcap_path.stat().st_size,
                "sha256": digest,
                "plaintext_sha256": digest,
                "encrypted_sha256": digest,
                "stored_path": str(pcap_path),
                "intake": {"packetLimit": str(MAX_PACKETS)},
            }
            self.stdout.write(f"Extracting ML features from {pcap_path.name}")
            analysis = analyze_pcap(pcap_path, f"ML-BENCH-{item['id']}", f"ml-ev-{uuid4().hex[:8]}", f"ml-job-{uuid4().hex[:8]}", saved)
            rows.append(
                {
                    "id": item["id"],
                    "file": item["file"],
                    "label": 0 if item.get("benign") else 1,
                    "vector": vectorize_features(analysis.get("features", {})),
                    "expectedAttackClasses": item.get("expectedAttackClasses", []),
                }
            )
        if len(rows) < 2:
            raise CommandError("Need at least two manifest rows to train the anomaly model.")
        model_path = model_dir / "anomaly-model.pkl"
        metadata_path = model_dir / "anomaly-model.json"
        result = train_model(rows, model_path, metadata_path)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        json_path = output_dir / f"ml-anomaly-benchmark-{stamp}.json"
        md_path = output_dir / f"ml-anomaly-benchmark-{stamp}.md"
        json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        md_path.write_text(_markdown(result, model_path, metadata_path), encoding="utf-8")
        self.stdout.write(self.style.SUCCESS(f"Model artifact: {model_path}"))
        self.stdout.write(self.style.SUCCESS(f"Model metadata: {metadata_path}"))
        self.stdout.write(self.style.SUCCESS(f"ML benchmark JSON: {json_path}"))
        self.stdout.write(self.style.SUCCESS(f"ML benchmark report: {md_path}"))
        f1 = float(result.get("metrics", {}).get("f1", 0))
        if f1 < options["fail_under_f1"]:
            raise CommandError(f"ML benchmark F1 {f1:.4f} is below required {options['fail_under_f1']:.4f}.")


def _sha256(path: Path) -> str:
    h = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _markdown(result: dict, model_path: Path, metadata_path: Path) -> str:
    lines = [
        "# Netra ML Anomaly Benchmark",
        "",
        f"- Model version: `{result.get('version')}`",
        f"- Model type: `{result.get('modelType')}`",
        f"- Trained rows: `{result.get('trainingRows')}`",
        f"- Model artifact: `{model_path}`",
        f"- Metadata: `{metadata_path}`",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in (result.get("metrics") or {}).items():
        lines.append(f"| {key} | {value} |")
    lines += ["", "## Rows", "", "| Case | Label | Prediction | Score |", "|---|---:|---:|---:|"]
    for row in result.get("rows", []):
        lines.append(f"| {row['id']} | {row['label']} | {row['prediction']} | {row['score']} |")
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in result.get("limitations", []))
    lines.append("")
    return "\n".join(lines)
