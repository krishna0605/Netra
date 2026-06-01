import shutil
import subprocess
from pathlib import Path


def available_packet_tools() -> dict[str, bool]:
    return {
        "scapy": _module_available("scapy"),
        "tshark": shutil.which("tshark") is not None,
        "zeek": shutil.which("zeek") is not None,
    }


def _module_available(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except Exception:
        return False


def tshark_protocol_summary(pcap_path: str | Path) -> list[str]:
    if shutil.which("tshark") is None:
        return []
    command = ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "_ws.col.Protocol"]
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def scapy_packet_count(pcap_path: str | Path, limit: int = 100000) -> int:
    try:
        from scapy.all import PcapReader

        count = 0
        with PcapReader(str(pcap_path)) as reader:
            for _packet in reader:
                count += 1
                if count >= limit:
                    break
        return count
    except Exception:
        return 0
