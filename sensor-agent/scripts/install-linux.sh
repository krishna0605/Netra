#!/usr/bin/env bash
set -euo pipefail
SENSOR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 -m venv "$SENSOR_ROOT/.venv"
"$SENSOR_ROOT/.venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r "$SENSOR_ROOT/requirements.txt"
echo "Netra sensor installed."
