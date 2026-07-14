from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, PcapNgWriter, PcapWriter


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
            Ether(**ethernet) / IP(src="10.10.1.5", dst="192.0.2.10") / TCP(sport=41000, dport=22, flags="S"),
            Ether(**ethernet) / IP(src="10.10.1.5", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="netra.example")),
            Ether(**ethernet) / IP(src="10.10.1.6", dst="198.51.100.20") / TCP(sport=42000, dport=443, flags="S"),
        ]
        for index, packet in enumerate(packets):
            packet.time = 1_720_000_000 + index

        writer = PcapNgWriter(str(target)) if target.suffix.lower() == ".pcapng" else PcapWriter(str(target), sync=True)
        try:
            for packet in packets:
                writer.write(packet)
        finally:
            writer.close()

        self.stdout.write(self.style.SUCCESS(f"Synthetic fixture generated: {target.name} ({target.stat().st_size} bytes, 3 packets)"))
