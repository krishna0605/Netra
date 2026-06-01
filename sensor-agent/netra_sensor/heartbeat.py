from __future__ import annotations

import platform
import socket
import time
import re

from . import __version__
from .capture import execute_capture_command
from .config import SensorConfig
from .dumpcap import capture_engine_version, discover_capture_engine, list_interfaces
from .uploader import SensorClient


def run_sensor(config: SensorConfig) -> None:
    executable = discover_capture_engine()
    client = SensorClient(config.server, config.shared_key)
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
    print(f"Registered {config.name} as {sensor_id}")
    while True:
        client.heartbeat(
            sensor_id,
            {
                "status": "online",
                "interfaces": interfaces,
                "captureEngineVersion": capture_engine_version(executable),
            },
        )
        command = client.next_command(sensor_id)
        if command:
            print(f"Starting bounded capture {command['jobId']}")
            try:
                execute_capture_command(client, sensor_id, executable, command)
            except Exception as exc:
                client.fail_capture(sensor_id, command["jobId"], str(exc))
                client.heartbeat(sensor_id, {"status": "warning", "lastError": str(exc)})
                print(f"Capture failed: {exc}")
        time.sleep(config.poll_seconds)
