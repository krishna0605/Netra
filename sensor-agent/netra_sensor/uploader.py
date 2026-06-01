from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

import requests


class SensorClient:
    def __init__(self, server: str, shared_key: str) -> None:
        self.server = server.rstrip("/")
        self.headers = {"X-Netra-Sensor-Key": shared_key}

    def _url(self, path: str) -> str:
        return f"{self.server}/api{path}"

    def register(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = requests.post(
            self._url("/sensors/register"), json=payload, headers=self.headers, timeout=10
        )
        response.raise_for_status()
        return response.json()

    def heartbeat(self, sensor_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = requests.post(
            self._url(f"/sensors/{sensor_id}/heartbeat"),
            json=payload,
            headers=self.headers,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()

    def next_command(self, sensor_id: str) -> dict[str, Any] | None:
        response = requests.get(
            self._url(f"/sensors/{sensor_id}/commands/next"),
            headers=self.headers,
            timeout=10,
        )
        response.raise_for_status()
        return response.json().get("command")

    def upload_chunk(self, sensor_id: str, job_id: str, sequence: int, path: Path) -> dict[str, Any]:
        content_type = mimetypes.guess_type(path.name)[0] or "application/vnd.tcpdump.pcap"
        with path.open("rb") as handle:
            response = requests.post(
                self._url(f"/sensors/{sensor_id}/chunks"),
                data={"jobId": job_id, "sequence": str(sequence)},
                files={"file": (path.name, handle, content_type)},
                headers=self.headers,
                timeout=60,
            )
        response.raise_for_status()
        return response.json()

    def complete_capture(self, sensor_id: str, job_id: str) -> dict[str, Any]:
        response = requests.post(
            self._url(f"/sensors/{sensor_id}/captures/{job_id}/complete"),
            json={},
            headers=self.headers,
            timeout=180,
        )
        response.raise_for_status()
        return response.json()

    def fail_capture(self, sensor_id: str, job_id: str, error: str) -> dict[str, Any]:
        response = requests.post(
            self._url(f"/sensors/{sensor_id}/captures/{job_id}/fail"),
            json={"error": error},
            headers=self.headers,
            timeout=20,
        )
        response.raise_for_status()
        return response.json()
