from __future__ import annotations

import re
from pathlib import Path


ACTION_PATTERN = re.compile(r"^\s*-\s+uses:\s+[^@\s]+@([0-9a-f]{40})(?:\s+#\s+.+)?$", re.MULTILINE)
USES_LINE = re.compile(r"^\s*-\s+uses:\s+(.+)$", re.MULTILINE)


def main() -> int:
    workflow_files = sorted(Path(".github/workflows").glob("*.yml"))
    if not workflow_files:
        raise ValueError("No GitHub workflows exist")
    for path in workflow_files:
        text = path.read_text(encoding="utf-8")
        if "pull_request_target:" in text or "permissions: write-all" in text:
            raise ValueError(f"{path}: unsafe trigger or broad permissions")
        is_post_deploy = "deployment_status:" in text
        if not is_post_deploy and ("release-candidate-*" not in text or "branches: [main]" not in text):
            raise ValueError(f"{path}: main and signed candidate-tag push gates are required")
        if is_post_deploy and "workflow_dispatch:" not in text:
            raise ValueError(f"{path}: post-deployment health must retain an owner-triggered verification path")
        uses = USES_LINE.findall(text)
        pinned = ACTION_PATTERN.findall(text)
        if len(uses) != len(pinned):
            raise ValueError(f"{path}: every external Action must use a full 40-character SHA")
        if re.search(r"\b(?:railway|vercel)\s+(?:deploy|up)|supabase\s+link", text, re.IGNORECASE):
            raise ValueError(f"{path}: deployment/link commands are prohibited")
    print(f"Validated {len(workflow_files)} least-privilege workflow(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
