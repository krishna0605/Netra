from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .dumpcap import build_capture_command, validate_bpf
from .uploader import SensorClient


def execute_capture_command(
    client: SensorClient, sensor_id: str, executable: str, command: dict[str, Any]
) -> None:
    job_id = command["jobId"]
    duration_seconds = int(command["durationSeconds"])
    packet_limit = int(command["packetLimit"])
    chunk_seconds = int(command["chunkIntervalSeconds"])
    started = time.monotonic()
    uploaded_packets = 0
    sequence = 0
    validate_bpf(executable, command["interfaceName"], command.get("bpfFilter", ""))

    with tempfile.TemporaryDirectory(prefix="netra-sensor-") as temp_dir:
        while time.monotonic() - started < duration_seconds and uploaded_packets < packet_limit:
            remaining_duration = max(1, duration_seconds - int(time.monotonic() - started))
            capture_duration = min(chunk_seconds, remaining_duration)
            sequence += 1
            chunk_path = Path(temp_dir) / f"capture-{sequence:06d}.pcap"
            capture_command = build_capture_command(
                executable,
                command["interfaceName"],
                capture_duration,
                packet_limit - uploaded_packets,
                chunk_path,
                command.get("bpfFilter", ""),
            )
            process = subprocess.Popen(capture_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                _, stderr = process.communicate(timeout=capture_duration + 3)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    _, stderr = process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, stderr = process.communicate(timeout=3)
            if process.returncode not in (0, -15, 1):
                raise RuntimeError(stderr.strip() or "Capture engine failed.")
            if not chunk_path.exists() or chunk_path.stat().st_size == 0:
                continue
            result = client.upload_chunk(sensor_id, job_id, sequence, chunk_path)
            uploaded_packets += int(result.get("packetCount", 0))
            client.heartbeat(
                sensor_id,
                {
                    "status": "capturing",
                    "metadata": {
                        "currentJobId": job_id,
                        "chunksUploaded": sequence,
                        "packetsUploaded": uploaded_packets,
                    },
                },
            )

    client.complete_capture(sensor_id, job_id)
