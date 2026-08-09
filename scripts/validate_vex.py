from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path


MAX_EXCEPTION_DAYS = 30
REQUIRED_FIELDS = {"vulnerability", "products", "status", "justification", "impact_statement", "action_statement", "timestamp"}


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else ".security/vex.openvex.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    statements = document.get("statements")
    if not isinstance(statements, list):
        raise ValueError("VEX statements must be a list")
    now = datetime.now(UTC)
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict) or not REQUIRED_FIELDS.issubset(statement):
            raise ValueError(f"VEX statement {index} is missing owner/reachability/remediation fields")
        created = datetime.fromisoformat(str(statement["timestamp"]).replace("Z", "+00:00"))
        expires_raw = statement.get("expires")
        if not expires_raw:
            raise ValueError(f"VEX statement {index} has no expiry")
        expires = datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
        if expires <= now:
            raise ValueError(f"VEX statement {index} has expired")
        if expires - created > timedelta(days=MAX_EXCEPTION_DAYS):
            raise ValueError(f"VEX statement {index} exceeds the 30-day exception limit")
    print(f"Validated {len(statements)} unexpired VEX statement(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
