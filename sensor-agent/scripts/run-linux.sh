#!/usr/bin/env bash
set -euo pipefail
SENSOR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$SENSOR_ROOT"
"$SENSOR_ROOT/.venv/bin/python" -m netra_sensor.cli "${1:-run}"
