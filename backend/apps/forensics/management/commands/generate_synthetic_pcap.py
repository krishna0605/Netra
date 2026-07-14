from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, PcapNgWriter, PcapWriter


class Command(BaseCommand):
    help = "Generate a deterministic synthetic PCAP/PCAPNG for authorized release validation."

    def add_arguments(self, parser):
        parser.add_argument("output", help="Destination ending in .pcap or .pcapng")
        parser.add_argument("--force", action="store_true", help="Replace an existing synthetic fixture")

    def handle(self, *args, **options):
        target = Path(options["output"]).expanduser().resolve()
        if target.suffix.lower() not in {".pcap", ".pcapng"}:
            raise CommandError("Output must end in .pcap or .pcapng.")
        if target.exists() and not options["force"]:
            raise CommandError("Output already exists; pass --force to replace it.")
        target.parent.mkdir(parents=True, exist_ok=True)

        ethernet = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}
        packets = [
            Ether(**ethernet) / IP(src="192.0.2.10", dst="198.51.100.22") / TCP(sport=41000, dport=22, flags="S"),
            Ether(**ethernet) / IP(src="192.0.2.10", dst="198.51.100.53") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="beacon.netra-demo.invalid")),
            Ether(**ethernet) / IP(src="192.0.2.11", dst="203.0.113.80") / TCP(sport=42000, dport=80, flags="PA") / Raw(b"GET /demo HTTP/1.1\r\nHost: portal.netra-demo.invalid\r\n\r\n"),
            Ether(**ethernet) / IP(src="192.0.2.12", dst="198.51.100.21") / TCP(sport=43000, dport=21, flags="PA") / Raw(b"USER synthetic-demo\r\n"),
            Ether(**ethernet) / IP(src="192.0.2.12", dst="198.51.100.21") / TCP(sport=43000, dport=21, flags="PA") / Raw(b"PASS simulated-only\r\n"),
            Ether(**ethernet) / IP(src="192.0.2.12", dst="198.51.100.21") / TCP(sport=43000, dport=21, flags="PA") / Raw(b"RETR harmless-demo.txt\r\n"),
            Ether(**ethernet) / IP(src="192.0.2.13", dst="203.0.113.44") / TCP(sport=44000, dport=443, flags="S"),
            Ether(**ethernet) / IP(src="192.0.2.10", dst="198.51.100.22") / TCP(sport=41001, dport=22, flags="S"),
        ]
        for index, packet in enumerate(packets):
            packet.time = 1_720_000_000 + index

        writer = PcapNgWriter(str(target)) if target.suffix.lower() == ".pcapng" else PcapWriter(str(target), sync=True)
        try:
            for packet in packets:
                writer.write(packet)
        finally:
            writer.close()

        self.stdout.write(self.style.SUCCESS(f"Synthetic fixture generated: {target.name} ({target.stat().st_size} bytes, {len(packets)} packets)"))
