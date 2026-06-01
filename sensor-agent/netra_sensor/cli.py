from __future__ import annotations

import argparse
import json

from .config import SensorConfig
from .dumpcap import capture_engine_version, discover_capture_engine, list_interfaces
from .heartbeat import run_sensor


def main() -> None:
    parser = argparse.ArgumentParser(description="Netra native sensor agent")
    parser.add_argument("command", choices=("check", "interfaces", "run"))
    args = parser.parse_args()
    executable = discover_capture_engine()
    if args.command == "check":
        print(
            json.dumps(
                {"captureEngine": executable, "version": capture_engine_version(executable)},
                indent=2,
            )
        )
        return
    if args.command == "interfaces":
        print(json.dumps(list_interfaces(executable), indent=2))
        return
    run_sensor(SensorConfig.from_env())


if __name__ == "__main__":
    main()
