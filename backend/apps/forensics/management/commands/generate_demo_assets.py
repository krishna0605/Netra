from __future__ import annotations

import hashlib
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand

from common.pdf_report import build_report_pdf


class Command(BaseCommand):
    help = "Generate the sanitized, deterministic PCAP and sample PDF used for the public hackathon demo."

    def add_arguments(self, parser):
        parser.add_argument(
            "--output-dir",
            default=str(settings.REPO_ROOT / "frontend" / "public" / "demo"),
            help="Directory that will receive the public synthetic demo assets.",
        )

    def handle(self, *args, **options):
        output_dir = Path(options["output_dir"]).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = output_dir / "netra-sanitized-demo.pcap"
        pdf_path = output_dir / "netra-sanitized-sample-report.pdf"

        call_command("generate_synthetic_pcap", str(pcap_path), force=True)
        pcap_sha256 = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
        analysis = {
            "caseId": "DEMO-NETRA-SANITIZED-001",
            "riskLevel": "medium",
            "topAttackClass": "Synthetic credential-access simulation",
            "summary": {"packets": 8, "sessions": 5, "alerts": 2, "anomalies": 1},
            "evidence": {
                "id": "ev-sanitized-demo",
                "filename": pcap_path.name,
                "sha256": pcap_sha256,
                "plaintextSha256": pcap_sha256,
                "encryptedSha256": "Not applicable - public synthetic fixture",
                "manifestHash": "Public demo asset",
                "keyId": "Not applicable",
                "storageUri": "/demo/netra-sanitized-demo.pcap",
            },
            "normalization": {
                "selectedType": "Auto-detect",
                "detectedType": "PCAP",
                "normalizedType": "PCAP",
                "confidence": 99,
                "parser": "pcap",
                "valid": True,
                "signals": ["magic:pcap", "extension:.pcap", "synthetic:test-net"],
            },
            "alerts": [
                {"severity": "medium", "attackClass": "Synthetic FTP authentication", "sourceIp": "192.0.2.12", "destination": "198.51.100.21:21", "confidence": 88},
                {"severity": "low", "attackClass": "Synthetic DNS beacon indicator", "sourceIp": "192.0.2.10", "destination": "beacon.netra-demo.invalid", "confidence": 72},
            ],
            "anomalies": [
                {"entity": "192.0.2.12", "observed": "Synthetic FTP command sequence", "baseline": "No FTP authentication", "confidence": 82},
            ],
            "sessions": [
                {"source": "192.0.2.12", "destination": "198.51.100.21", "protocol": "FTP", "packetCount": 3, "riskScore": 68},
                {"source": "192.0.2.10", "destination": "198.51.100.53", "protocol": "DNS", "packetCount": 1, "riskScore": 42},
            ],
            "decodedProtocols": [
                {"protocol": "FTP", "sessionCount": 1, "packetCount": 3, "severity": "medium", "summary": "Synthetic USER/PASS/RETR sequence for demonstration only."},
                {"protocol": "DNS", "sessionCount": 1, "packetCount": 1, "severity": "low", "summary": "Documentation-only .invalid query."},
            ],
            "payloadFindings": [
                {"payloadType": "Synthetic command metadata", "protocol": "FTP", "risk": "medium", "description": "Harmless demonstration credentials; no real system or account is referenced."},
            ],
            "toolStatus": {"tshark": "validated", "zeek": "not required for sample"},
            "custodyLedger": {"events": []},
        }
        legal = {
            "items": [
                {"item": "Synthetic-data declaration", "status": "complete", "detail": "All addresses use RFC 5737 TEST-NET ranges and all domain names use .invalid."},
                {"item": "ML limitation", "status": "complete", "detail": "Experimental ML output assists triage and is not a standalone evidentiary conclusion."},
            ]
        }
        custody = {"verified": True, "eventCount": 0, "latestHash": pcap_sha256}
        pdf_path.write_bytes(build_report_pdf(analysis, "English", legal, custody))

        pdf_sha256 = hashlib.sha256(pdf_path.read_bytes()).hexdigest()
        manifest = output_dir / "SHA256SUMS.txt"
        manifest.write_text(
            f"{pcap_sha256}  {pcap_path.name}\n{pdf_sha256}  {pdf_path.name}\n",
            encoding="ascii",
        )
        self.stdout.write(self.style.SUCCESS(f"Sanitized demo assets generated in {output_dir}"))
