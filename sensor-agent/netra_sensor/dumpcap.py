from __future__ import annotations

import platform
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


WINDOWS_CANDIDATES = (
    Path(r"C:\Program Files\Wireshark\dumpcap.exe"),
    Path(r"C:\Program Files (x86)\Wireshark\dumpcap.exe"),
)


def discover_capture_engine() -> str:
    executable = shutil.which("dumpcap")
    if executable:
        return executable
    if platform.system() == "Windows":
        for candidate in WINDOWS_CANDIDATES:
            if candidate.exists():
                return str(candidate)
    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        return tcpdump
    raise RuntimeError("No packet capture engine found. Install Wireshark dumpcap or tcpdump.")


def capture_engine_version(executable: str) -> str:
    result = subprocess.run(
        [executable, "--version"],
        capture_output=True,
        check=True,
        text=True,
        timeout=60,
    )
    return result.stdout.splitlines()[0].strip()


def list_interfaces(executable: str) -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            [executable, "-D"],
            capture_output=True,
            check=True,
            text=True,
            timeout=20,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        if platform.system() == "Windows":
            return _windows_netadapter_interfaces()
        raise
    interfaces = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        match = re.match(r"^(\d+)\.\s+([^\s]+)(?:\s+\((.*)\))?$", line)
        if not match:
            continue
        interfaces.append(
            {
                "index": match.group(1),
                "name": match.group(2),
                "label": match.group(3) or match.group(2),
            }
        )
    return interfaces


def _windows_netadapter_interfaces() -> list[dict[str, str]]:
    script = (
        "Get-NetAdapter -IncludeHidden | "
        "Where-Object { $_.InterfaceGuid } | "
        "Select-Object Name,InterfaceGuid | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        check=True,
        text=True,
        timeout=20,
    )
    payload = json.loads(result.stdout or "[]")
    rows = payload if isinstance(payload, list) else [payload]
    interfaces = [
        {
            "index": str(index),
            "name": rf"\Device\NPF_{{{str(row['InterfaceGuid']).strip('{}').upper()}}}",
            "label": row["Name"],
        }
        for index, row in enumerate(rows, start=1)
    ]
    interfaces.append(
        {
            "index": str(len(interfaces) + 1),
            "name": r"\Device\NPF_Loopback",
            "label": "Adapter for loopback traffic capture",
        }
    )
    return interfaces


def build_capture_command(
    executable: str,
    interface_name: str,
    duration_seconds: int,
    packet_limit: int,
    output_path: Path,
    bpf_filter: str = "",
) -> list[str]:
    if Path(executable).name.lower().startswith("tcpdump"):
        command = [
            executable,
            "-i",
            interface_name,
            "-c",
            str(packet_limit),
            "-G",
            str(duration_seconds),
            "-W",
            "1",
            "-w",
            str(output_path),
        ]
        if bpf_filter:
            command.extend(bpf_filter.split())
        return command

    command = [
        executable,
        "-i",
        interface_name,
        "-a",
        f"duration:{duration_seconds}",
        "-c",
        str(packet_limit),
        "-w",
        str(output_path),
    ]
    if bpf_filter:
        command.extend(["-f", bpf_filter])
    return command


def validate_bpf(executable: str, interface_name: str, bpf_filter: str) -> None:
    if not bpf_filter:
        return
    if Path(executable).name.lower().startswith("tcpdump"):
        command = [executable, "-i", interface_name, "-d", *bpf_filter.split()]
    else:
        with tempfile.TemporaryDirectory(prefix="netra-bpf-") as temp_dir:
            target = Path(temp_dir) / "probe.pcap"
            command = [
                executable,
                "-i",
                interface_name,
                "-f",
                bpf_filter,
                "-a",
                "duration:1",
                "-w",
                str(target),
            ]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=3)
            except subprocess.TimeoutExpired:
                # dumpcap can keep a Windows Npcap probe alive after accepting a
                # valid filter. subprocess.run terminates the probe on timeout.
                return
            if result.returncode != 0:
                raise ValueError(result.stderr.strip() or "Capture filter could not be compiled.")
            return
    result = subprocess.run(command, capture_output=True, text=True, timeout=8)
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or "Capture filter could not be compiled.")
