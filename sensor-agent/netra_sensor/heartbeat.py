from __future__ import annotations

import platform
import socket
import time
import re
import shutil

from . import __version__
from .capture import execute_capture_command
from .config import SensorConfig
from .dumpcap import capture_engine_version, discover_capture_engine, list_interfaces
from .uploader import SensorClient


def run_sensor(config: SensorConfig) -> None:
    executable = discover_capture_engine()
    client = SensorClient(config.server, config.shared_key, config.retry_initial_seconds, config.retry_max_seconds)
    interfaces = list_interfaces(executable)
    registration = client.register(
        {
            "id": "sensor-" + re.sub(r"[^a-z0-9-]+", "-", socket.gethostname().lower()).strip("-"),
            "name": config.name,
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "agentVersion": __version__,
            "captureEngine": executable,
            "captureEngineVersion": capture_engine_version(executable),
            "interfaces": interfaces,
        }
    )
    sensor_id = registration["id"]
    started_at = time.monotonic()
    print(f"Registered {config.name} as {sensor_id}")
    while True:
        command = None
        try:
            disk = shutil.disk_usage(".")
            client.heartbeat(
                sensor_id,
                {
                    "status": "online",
                    "interfaces": interfaces,
                    "captureEngineVersion": capture_engine_version(executable),
                    "metadata": {"storageFreeBytes": disk.free, "uptimeSeconds": int(time.monotonic() - started_at)},
                },
            )
            command = client.next_command(sensor_id)
            if command:
                print(f"Starting bounded capture {command['jobId']}")
                execute_capture_command(client, sensor_id, executable, command)
        except Exception as exc:
            print(f"Sensor server unavailable or capture failed: {exc}")
            if command:
                try:
                    client.fail_capture(sensor_id, command["jobId"], str(exc))
                except Exception:
                    pass
        time.sleep(config.poll_seconds)
