from __future__ import annotations

import os
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class SensorConfig:
    server: str
    shared_key: str
    name: str
    poll_seconds: float
    retry_initial_seconds: float
    retry_max_seconds: float

    @classmethod
    def from_env(cls) -> "SensorConfig":
        return cls(
            server=os.getenv("NETRA_SERVER_URL", "http://localhost:8000").rstrip("/"),
            shared_key=os.getenv(
                "NETRA_SENSOR_SHARED_KEY", "netra-phase5-local-sensor-key"
            ),
            name=os.getenv("NETRA_SENSOR_NAME", f"Netra Sensor - {socket.gethostname()}"),
            poll_seconds=float(os.getenv("NETRA_SENSOR_POLL_SECONDS", "3")),
            retry_initial_seconds=float(os.getenv("NETRA_SENSOR_RETRY_INITIAL_SECONDS", "1")),
            retry_max_seconds=float(os.getenv("NETRA_SENSOR_RETRY_MAX_SECONDS", "30")),
        )
