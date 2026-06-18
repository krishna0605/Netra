from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from common.analysis import MAX_PACKETS, analyze_pcap


class Command(BaseCommand):
    help = "Validate Phase 7 DPI metadata clues and Phase 8 large-PCAP completeness markers."

    def add_arguments(self, parser):
        parser.add_argument("--mode", choices=["dpi", "large", "all"], default="all")
        parser.add_argument("--pcap-root", required=True)
        parser.add_argument("--output-dir", required=True)

    def handle(self, *args, **options):
        pcap_root = Path(options["pcap_root"])
        output_dir = Path(options["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        if not pcap_root.exists():
            raise CommandError(f"PCAP root does not exist: {pcap_root}")

        results = {
            "checkedAt": datetime.now(timezone.utc).isoformat(),
            "mode": options["mode"],
            "packetMetadataLimit": MAX_PACKETS,
            "dpi": None,
            "largePcap": None,
            "passed": True,
        }
        failures: list[str] = []

        if options["mode"] in {"dpi", "all"}:
            dpi_result = self._validate_dpi(pcap_root)
            results["dpi"] = dpi_result
            failures.extend(dpi_result["failures"])

        if options["mode"] in {"large", "all"}:
            large_result = self._validate_large_pcap(pcap_root)
            results["largePcap"] = large_result
            failures.extend(large_result["failures"])

        results["passed"] = not failures
        results["failures"] = failures

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        json_path = output_dir / f"phase7-8-analysis-validation-{stamp}.json"
        md_path = output_dir / f"phase7-8-analysis-validation-{stamp}.md"
        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        md_path.write_text(self._markdown(results), encoding="utf-8")

        self.stdout.write(f"Wrote {json_path}")
        self.stdout.write(f"Wrote {md_path}")
        if failures:
            raise CommandError("; ".join(failures))
        self.stdout.write(self.style.SUCCESS("Phase 7/8 analysis capability validation passed."))

    def _validate_dpi(self, pcap_root: Path) -> dict:
        cases = [
            {"file": "hydra_ftp.pcap", "expectedProtocol": "FTP", "expectedIndicator": "ftp-command-metadata"},
            {"file": "smtp.pcap", "expectedProtocol": "SMTP", "expectedIndicator": "smtp-transfer-metadata"},
        ]
        evaluated = []
        failures: list[str] = []
        for item in cases:
            path = pcap_root / item["file"]
            if not path.exists():
                failures.append(f"Missing DPI validation PCAP: {item['file']}")
                continue
            analysis = analyze_pcap(path, f"CYB-GJ-DPI-{item['expectedProtocol']}", f"ev-dpi-{item['expectedProtocol'].lower()}", f"job-dpi-{item['expectedProtocol'].lower()}", self._saved(path))
            findings = analysis.get("payloadFindings", [])
            matching = [
                finding
                for finding in findings
                if finding.get("protocol") == item["expectedProtocol"]
                and finding.get("indicator") == item["expectedIndicator"]
                and "Metadata-level" in finding.get("limitations", "")
            ]
            protocol_records = [record for record in analysis.get("decodedProtocols", []) if record.get("protocol") == item["expectedProtocol"]]
            evaluated.append({
                "file": item["file"],
                "expectedProtocol": item["expectedProtocol"],
                "payloadFindingCount": len(findings),
                "matchingFindingCount": len(matching),
                "protocolRecordCount": len(protocol_records),
                "sampleFinding": matching[0] if matching else None,
            })
            if not matching:
                failures.append(f"{item['file']} did not produce expected {item['expectedProtocol']} metadata payload finding.")
            if not protocol_records:
                failures.append(f"{item['file']} did not produce decoded protocol summary for {item['expectedProtocol']}.")
        return {"cases": evaluated, "failures": failures}

    def _validate_large_pcap(self, pcap_root: Path) -> dict:
        path = pcap_root / "normal2.pcap"
        if not path.exists():
            return {"file": "normal2.pcap", "failures": ["Missing large-PCAP validation file: normal2.pcap"]}
        analysis = analyze_pcap(path, "CYB-GJ-LARGE-PCAP", "ev-large-pcap", "job-large-pcap", self._saved(path))
        observed = int(analysis.get("observedPackets") or 0)
        indexed = int(analysis.get("indexedPackets") or 0)
        completeness = analysis.get("searchCompleteness")
        failures: list[str] = []
        if indexed > MAX_PACKETS:
            failures.append(f"Indexed packet metadata exceeded MAX_PACKETS: {indexed} > {MAX_PACKETS}")
        if observed <= indexed:
            failures.append(f"Large PCAP did not prove capped metadata indexing: observed={observed}, indexed={indexed}")
        if completeness != "truncated-search-index":
            failures.append(f"Expected truncated-search-index completeness, got {completeness}")
        return {
            "file": path.name,
            "sizeBytes": path.stat().st_size,
            "observedPackets": observed,
            "indexedPackets": indexed,
            "searchCompleteness": completeness,
            "summary": analysis.get("summary", {}),
            "failures": failures,
        }

    def _saved(self, path: Path) -> dict:
        data = path.read_bytes()
        digest = sha256(data).hexdigest()
        return {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "sha256": digest,
            "plaintext_sha256": digest,
            "encrypted_sha256": digest,
            "stored_path": str(path),
            "intake": {},
        }

    def _markdown(self, results: dict) -> str:
        lines = [
            "# Phase 7/8 Analysis Capability Validation",
            "",
            f"- Checked at: `{results['checkedAt']}`",
            f"- Packet metadata limit: `{results['packetMetadataLimit']}`",
            f"- Passed: `{results['passed']}`",
            "",
            "## DPI Metadata",
            "",
        ]
        for case in (results.get("dpi") or {}).get("cases", []):
            lines.append(f"- `{case['file']}` expected `{case['expectedProtocol']}`: {case['matchingFindingCount']} matching finding(s), {case['protocolRecordCount']} protocol record(s).")
        lines += ["", "## Large PCAP", ""]
        large = results.get("largePcap") or {}
        if large:
            lines.append(f"- File: `{large.get('file')}`")
            lines.append(f"- Observed packets: `{large.get('observedPackets')}`")
            lines.append(f"- Indexed packet metadata: `{large.get('indexedPackets')}`")
            lines.append(f"- Search completeness: `{large.get('searchCompleteness')}`")
        if results.get("failures"):
            lines += ["", "## Failures", ""]
            lines.extend(f"- {failure}" for failure in results["failures"])
        return "\n".join(lines) + "\n"
