"""Assert the deployed images run application code as the reviewed user.

The Python test suite and the GitHub policy gates all execute Django directly,
so neither observes how the container actually starts. A change to the image's
USER directive or entrypoint can therefore pass every existing check and still
break production. This gate builds the real images and inspects the runtime the
application process is handed.

It exists because replacing `USER 10001:10001` with a `setpriv` privilege drop
kept the uid and gid correct but left HOME pointing at root's home directory,
which the runtime user cannot read.
"""

from __future__ import annotations

import json
import subprocess  # nosec B404 - builds and inspects local images only.
import sys
import tempfile
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_UID = 10001
EXPECTED_GID = 10001

PROBE = (
    "import grp, json, os, pwd;"
    "home = os.path.expanduser('~');"
    "print('NETRA_RUNTIME ' + json.dumps({"
    "'uid': os.getuid(), 'gid': os.getgid(),"
    "'home': home, 'home_readable': os.access(home, os.R_OK),"
    "'home_writable': os.access(home, os.W_OK),"
    "'groups': sorted(os.getgroups()),"
    "'storage_writable': os.access(os.environ.get('NETRA_STORAGE_ROOT', '/app/storage'), os.W_OK)"
    "}))"
)


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=False, capture_output=True, text=True, **kwargs)  # nosec B603


def build(dockerfile: Path, tag: str, context: Path) -> None:
    try:
        location = dockerfile.relative_to(REPOSITORY_ROOT)
    except ValueError:
        location = dockerfile.name
    print(f"==> building {tag} from {location}")
    result = run(["docker", "build", "-f", str(dockerfile), "-t", tag, str(context)])
    if result.returncode != 0:
        raise SystemExit(f"docker build failed for {tag}:\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}")


def inspect(tag: str, extra_args: list[str] | None = None) -> dict:
    command = ["docker", "run", "--rm", *(extra_args or []), tag, "python", "-c", PROBE]
    result = run(command)
    if result.returncode != 0:
        raise SystemExit(f"docker run failed for {tag}:\n{result.stdout[-4000:]}\n{result.stderr[-4000:]}")
    for line in result.stdout.splitlines():
        if line.startswith("NETRA_RUNTIME "):
            return json.loads(line.removeprefix("NETRA_RUNTIME "))
    raise SystemExit(f"{tag} did not report a runtime identity:\n{result.stdout[-4000:]}")


def assert_runtime(label: str, runtime: dict) -> list[str]:
    failures = []
    if runtime["uid"] != EXPECTED_UID or runtime["gid"] != EXPECTED_GID:
        failures.append(
            f"{label}: application runs as {runtime['uid']}:{runtime['gid']}, expected {EXPECTED_UID}:{EXPECTED_GID}"
        )
    if runtime["home"] in {"/root", "/"}:
        failures.append(f"{label}: HOME is {runtime['home']}, which the runtime user does not own")
    if not runtime["home_readable"] or not runtime["home_writable"]:
        failures.append(
            f"{label}: HOME {runtime['home']} is not readable and writable by the runtime user"
        )
    if EXPECTED_GID not in runtime["groups"]:
        failures.append(f"{label}: supplementary groups {runtime['groups']} lost the primary group")
    return failures


def main() -> int:
    failures: list[str] = []

    # The API image must keep starting through a plain USER directive. It mounts
    # no volume, so it has no reason to carry the privilege-dropping entrypoint.
    api_dockerfile = REPOSITORY_ROOT / "backend" / "Dockerfile"
    if "netra-entrypoint" in api_dockerfile.read_text(encoding="utf-8"):
        failures.append("backend/Dockerfile must not use the volume entrypoint; the API mounts no volume")
    build(api_dockerfile, "netra-api-runtime-check", REPOSITORY_ROOT)
    failures.extend(assert_runtime("api", inspect("netra-api-runtime-check")))

    # The worker entrypoint is exercised against a root-owned mount, which is
    # what Railway hands the container, without rebuilding the slow worker image.
    with tempfile.TemporaryDirectory() as staging:
        probe_context = Path(staging)
        (probe_context / "docker-entrypoint.sh").write_bytes(
            (REPOSITORY_ROOT / "backend" / "docker-entrypoint.sh").read_bytes()
        )
        (probe_context / "Dockerfile").write_text(
            "FROM netra-api-runtime-check\n"
            "USER 0:0\n"
            "RUN apt-get update \\\n"
            "    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends util-linux \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
            "COPY docker-entrypoint.sh /usr/local/bin/netra-entrypoint\n"
            "RUN chmod 0755 /usr/local/bin/netra-entrypoint && command -v setpriv\n"
            'ENTRYPOINT ["netra-entrypoint"]\n',
            encoding="utf-8",
        )
        build(probe_context / "Dockerfile", "netra-worker-entrypoint-check", probe_context)

    # A tmpfs mounted as root reproduces a freshly attached Railway volume.
    runtime = inspect(
        "netra-worker-entrypoint-check",
        ["--tmpfs", "/app/storage:uid=0,gid=0,mode=700"],
    )
    failures.extend(assert_runtime("worker-entrypoint", runtime))
    if not runtime["storage_writable"]:
        failures.append(
            "worker-entrypoint: the entrypoint did not make a root-owned /app/storage writable by the runtime user"
        )

    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("Validated container runtime identity for the API image and the worker entrypoint.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
