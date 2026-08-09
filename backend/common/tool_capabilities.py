from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings

from common.parser_runner import ParserFailure, ParserLimits, run_parser


VERSION_PATTERN = re.compile(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)")


def _version(tool: str) -> dict[str, object]:
    with TemporaryDirectory(prefix=f"netra-{tool}-version-") as directory:
        root = Path(directory)
        marker = root / "probe.input"
        marker.touch()
        try:
            result = run_parser(
                tool=tool,
                arguments=["--version"],
                input_path=marker,
                working_directory=root,
                limits=ParserLimits.configured(timeout_seconds=10),
            )
        except ParserFailure:
            return {"available": False, "version": ""}
    match = VERSION_PATTERN.search(f"{result.stdout}\n{result.stderr}")
    return {"available": result.returncode == 0 and bool(match), "version": match.group(1) if match else ""}


@lru_cache(maxsize=1)
def worker_capabilities() -> dict[str, object]:
    return {
        "pcap": True,
        "pcapng": True,
        "structuredEvidence": True,
        "tshark": _version("tshark"),
        "zeek": _version("zeek"),
    }


def capability_failures(capabilities: dict[str, object] | None = None) -> list[str]:
    data = capabilities or worker_capabilities()
    failures = []
    for tool, required in (("tshark", settings.NETRA_REQUIRED_TSHARK_VERSION), ("zeek", settings.NETRA_REQUIRED_ZEEK_VERSION)):
        observed = data.get(tool) if isinstance(data.get(tool), dict) else {}
        if not observed.get("available") or observed.get("version") != required:
            failures.append(tool)
    return failures


def require_worker_capabilities() -> dict[str, object]:
    capabilities = worker_capabilities()
    failures = capability_failures(capabilities)
    if failures:
        raise RuntimeError(f"Required worker tools are unavailable or version-mismatched: {', '.join(failures)}")
    return capabilities
