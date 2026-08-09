from __future__ import annotations

import re
from pathlib import Path


ROOT = Path("infra/supabase/migrations")
SECRET_PATTERNS = ("service_role_key", "postgresql://", "supabase_secret_key")


def main() -> int:
    files = sorted(ROOT.glob("*.sql"))
    if not files:
        raise SystemExit("No local Supabase migrations were found.")
    for path in files:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        if any(pattern in lowered for pattern in SECRET_PATTERNS):
            raise ValueError(f"{path}: secret-bearing value or connection string is prohibited")
        if "security definer" in lowered and not re.search(r"set\s+search_path\s*=", lowered):
            raise ValueError(f"{path}: SECURITY DEFINER requires an explicit search_path")
        if re.search(r"grant\s+all\s+on\s+all\s+tables.*\b(?:anon|authenticated)\b", lowered, re.DOTALL):
            raise ValueError(f"{path}: blanket Data API grants are prohibited")
    print(f"Validated {len(files)} local Supabase SQL migration(s) without linking a project.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
