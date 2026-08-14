from __future__ import annotations

import argparse
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


MAX_RESPONSE_BYTES = 32 * 1024


def _health_url(api_origin: str) -> str:
    origin = api_origin.rstrip("/")
    parsed = urllib.parse.urlparse(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("API origin must be a credential-free HTTPS origin")
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("API origin must not contain a path, query, or fragment")
    return f"{origin}/api/health"


def _read_health(url: str) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "Netra-Deployment-Gate/1"},
    )
    with urllib.request.urlopen(request, timeout=10, context=ssl.create_default_context()) as response:
        if response.status != 200:
            raise RuntimeError(f"health endpoint returned HTTP {response.status}")
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError("health response exceeded the bounded response size")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise RuntimeError("health response was not a JSON object")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait for the expected Railway API release to become active.")
    parser.add_argument("--api-origin", required=True)
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--interval", type=int, default=10)
    args = parser.parse_args()

    if not 7 <= len(args.expected_release) <= 64 or not all(
        character in "0123456789abcdefABCDEF" for character in args.expected_release
    ):
        raise ValueError("expected release must be a Git commit SHA")
    if not 1 <= args.timeout <= 1800 or not 1 <= args.interval <= 60:
        raise ValueError("timeout or interval is outside the reviewed bounds")

    url = _health_url(args.api_origin)
    deadline = time.monotonic() + args.timeout
    last_reason = "no response"
    while time.monotonic() < deadline:
        try:
            payload = _read_health(url)
            if payload.get("status") != "ok" or payload.get("service") != "netra-backend":
                last_reason = "endpoint returned an unexpected service identity"
            elif payload.get("releaseId") != args.expected_release:
                last_reason = "the active API still reports a different release"
            else:
                print(f"Railway API health gate passed for release {args.expected_release}.")
                return 0
        except (json.JSONDecodeError, OSError, RuntimeError, urllib.error.URLError) as error:
            last_reason = type(error).__name__
        time.sleep(args.interval)

    raise RuntimeError(f"Railway API health gate timed out: {last_reason}")


if __name__ == "__main__":
    raise SystemExit(main())
