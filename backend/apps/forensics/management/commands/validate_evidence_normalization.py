from __future__ import annotations

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand, CommandError

from common.evidence_normalization import normalize_evidence_upload


class Command(BaseCommand):
    help = "Validate Netra evidence type normalization rules."

    def handle(self, *args, **options):
        cases = [
            (
                "pcap-selected-pcap",
                SimpleUploadedFile("sample.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64),
                "PCAP",
                "PCAP",
                True,
                "",
            ),
            (
                "pcap-selected-firewall",
                SimpleUploadedFile("sample.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64),
                "Firewall Logs",
                "PCAP",
                False,
                "evidence_type_mismatch",
            ),
            (
                "pcap-renamed-log-selected-firewall",
                SimpleUploadedFile("renamed.log", b"\xd4\xc3\xb2\xa1" + b"\x00" * 64),
                "Firewall Logs",
                "PCAP",
                False,
                "evidence_type_mismatch",
            ),
            (
                "pcapng-auto",
                SimpleUploadedFile("sample.pcapng", b"\x0a\x0d\x0d\x0a" + b"\x00" * 64),
                "Auto-detect",
                "PCAP",
                True,
                "",
            ),
            (
                "firewall-log",
                SimpleUploadedFile("firewall.log", b"timestamp,src_ip,dst_ip,action,rule\n2026-06-17,10.0.0.1,8.8.8.8,deny,blocked-egress\n"),
                "Firewall Logs",
                "Firewall Logs",
                True,
                "",
            ),
            (
                "dns-log",
                SimpleUploadedFile("dns.csv", b"time,query,qname,rrtype,rcode\n1,example.com,example.com,A,NOERROR\n"),
                "DNS Logs",
                "DNS Logs",
                True,
                "",
            ),
            (
                "tls-metadata-json",
                SimpleUploadedFile("tls.json", b'{"sni":"example.com","ja3":"abc","tls_version":"1.3","cipher":"TLS_AES_128_GCM_SHA256"}'),
                "TLS Metadata",
                "TLS Metadata",
                True,
                "",
            ),
            (
                "invalid-pcap",
                SimpleUploadedFile("fake.pcap", b"not-a-pcap"),
                "PCAP",
                "Unknown",
                False,
                "invalid_pcap",
            ),
            (
                "html-rejected",
                SimpleUploadedFile("page.html", b"<html><body>not evidence</body></html>"),
                "Auto-detect",
                "Unknown",
                False,
                "unsupported_evidence_extension",
            ),
            (
                "map-rejected",
                SimpleUploadedFile("bundle.map", b'{"version":3,"sources":["app.ts"]}'),
                "Mixed Evidence",
                "Unknown",
                False,
                "unsupported_evidence_extension",
            ),
            (
                "cts-rejected",
                SimpleUploadedFile("script.cts", b"export const unsafe = true;"),
                "DNS Logs",
                "Unknown",
                False,
                "unsupported_evidence_extension",
            ),
        ]
        failures = []
        for name, upload, selected, expected_type, expected_valid, expected_code in cases:
            result = normalize_evidence_upload(upload, selected)
            ok = result.detected_type == expected_type and result.valid == expected_valid and result.code == expected_code
            if not ok:
                failures.append(f"{name}: detected={result.detected_type} valid={result.valid} code={result.code}; expected {expected_type}/{expected_valid}/{expected_code}")
            self.stdout.write(f"[{'PASS' if ok else 'FAIL'}] {name}: {result.detected_type}, valid={result.valid}, code={result.code or '-'}, parser={result.parser}")
        if failures:
            raise CommandError("; ".join(failures))
        self.stdout.write(self.style.SUCCESS("Evidence normalization validation passed."))
