from __future__ import annotations

import mimetypes
import time
from pathlib import Path
from typing import Any

import requests


class SensorClient:
    def __init__(self, server: str, shared_key: str, retry_initial_seconds: float = 1, retry_max_seconds: float = 30) -> None:
        self.server = server.rstrip("/")
        self.headers = {"X-Netra-Sensor-Key": shared_key}
        self.retry_initial_seconds = retry_initial_seconds
        self.retry_max_seconds = retry_max_seconds

    def _url(self, path: str) -> str:
        return f"{self.server}/api{path}"

    def _request(self, method: str, path: str, **kwargs):
        delay = self.retry_initial_seconds
        for attempt in range(1, 6):
            try:
                response = requests.request(method, self._url(path), **kwargs)
                response.raise_for_status()
                return response
            except requests.RequestException:
                if attempt == 5:
                    raise
                time.sleep(delay)
                delay = min(self.retry_max_seconds, delay * 2)

    def register(self, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._request("POST", "/sensors/register", json=payload, headers=self.headers, timeout=10)
        return response.json()

    def heartbeat(self, sensor_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._request(
            "POST", f"/sensors/{sensor_id}/heartbeat",
            json=payload,
            headers=self.headers,
            timeout=10,
        )
        return response.json()

    def next_command(self, sensor_id: str) -> dict[str, Any] | None:
        response = self._request(
            "GET", f"/sensors/{sensor_id}/commands/next",
            headers=self.headers,
            timeout=10,
        )
        return response.json().get("command")

    def upload_chunk(self, sensor_id: str, job_id: str, sequence: int, path: Path) -> dict[str, Any]:
        content_type = mimetypes.guess_type(path.name)[0] or "application/vnd.tcpdump.pcap"
        with path.open("rb") as handle:
            response = self._request(
                "POST", f"/sensors/{sensor_id}/chunks",
                data={"jobId": job_id, "sequence": str(sequence)},
                files={"file": (path.name, handle, content_type)},
                headers=self.headers,
                timeout=60,
            )
        return response.json()

    def complete_capture(self, sensor_id: str, job_id: str) -> dict[str, Any]:
        response = self._request(
            "POST", f"/sensors/{sensor_id}/captures/{job_id}/complete",
            json={},
            headers=self.headers,
            timeout=180,
        )
        return response.json()

    def fail_capture(self, sensor_id: str, job_id: str, error: str) -> dict[str, Any]:
        response = self._request(
            "POST", f"/sensors/{sensor_id}/captures/{job_id}/fail",
            json={"error": error},
            headers=self.headers,
            timeout=20,
        )
        return response.json()
