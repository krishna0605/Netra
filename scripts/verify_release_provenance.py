from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import time
import urllib.parse
import urllib.request


MAX_RESPONSE_BYTES = 32 * 1024


def safe_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value.rstrip("/"))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Origins must be credential-free HTTPS URLs")
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Origins must not contain a path, query, or fragment")
    return value.rstrip("/")


def read_json(url: str, token: str = "") -> dict[str, object]:
    headers = {"Accept": "application/json", "User-Agent": "Netra-Release-Provenance/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15, context=ssl.create_default_context()) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if response.status != 200 or len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeError(f"Unexpected response from {url}")
    document = json.loads(body)
    if not isinstance(document, dict):
        raise RuntimeError(f"Expected a JSON object from {url}")
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description="Require GitHub, Vercel and Railway to serve one release SHA.")
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--github-repository", required=True)
    parser.add_argument("--frontend-origin", required=True)
    parser.add_argument("--api-origin", required=True)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--interval", type=int, default=10)
    args = parser.parse_args()

    expected = args.expected_release.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise ValueError("expected release must be a full Git SHA")
    frontend = safe_origin(args.frontend_origin)
    api = safe_origin(args.api_origin)
    if not 1 <= args.interval <= 60 or not 1 <= args.timeout <= 1800:
        raise ValueError("timeout or interval is outside the reviewed bounds")

    github = read_json(
        f"https://api.github.com/repos/{args.github_repository}/commits/main",
        os.getenv("GITHUB_TOKEN", ""),
    )
    github_sha = str(github.get("sha") or "").lower()
    if github_sha != expected:
        raise RuntimeError(f"GitHub main is {github_sha or 'missing'}, expected {expected}")
    if not github.get("commit", {}).get("verification", {}).get("verified"):
        raise RuntimeError("GitHub does not report the release commit signature as verified")

    deadline = time.monotonic() + args.timeout
    last = "production endpoints have not converged"
    while time.monotonic() < deadline:
        try:
            frontend_release = read_json(f"{frontend}/release.json")
            health = read_json(f"{api}/api/health")
            vercel_sha = str(frontend_release.get("releaseId") or "").lower()
            api_sha = str(health.get("releaseId") or "").lower()
            worker = health.get("worker") if isinstance(health.get("worker"), dict) else {}
            worker_sha = str(worker.get("releaseId") or "").lower()
            worker_status = str(worker.get("status") or "unknown")
            if frontend_release.get("environment") != "production":
                last = "Vercel alias does not report a production artifact"
            elif vercel_sha != expected:
                last = f"Vercel reports {vercel_sha or 'missing'}"
            elif api_sha != expected:
                last = f"Railway API reports {api_sha or 'missing'}"
            elif worker_sha != expected or worker_status != "healthy":
                last = f"Railway worker reports {worker_sha or 'missing'} ({worker_status})"
            else:
                print(f"Expected local/GitHub SHA: {expected}")
                print(f"GitHub main SHA:          {github_sha}")
                print(f"Vercel production SHA:   {vercel_sha}")
                print(f"Railway API SHA:         {api_sha}")
                print(f"Railway worker SHA:      {worker_sha}")
                print("Result:                   MATCH")
                return 0
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            last = f"{type(error).__name__}: {error}"
        time.sleep(args.interval)

    raise RuntimeError(f"Release provenance timed out: {last}")


if __name__ == "__main__":
    raise SystemExit(main())
