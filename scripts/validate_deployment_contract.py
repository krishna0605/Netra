from __future__ import annotations

import json
import re
from pathlib import Path


FRONTEND_ORIGIN = "https://netra-hackathon-console-20260714.vercel.app"
ADMIN_ORIGIN = FRONTEND_ORIGIN
API_ORIGIN = "https://netra-api-production.up.railway.app"
SUPABASE_ORIGIN = "https://frjzewpyjgirorbguegm.supabase.co"

# Keys that let a platform decide, on its own, not to build a commit. Netra's
# release contract is exact-SHA parity: the same commit must reach Vercel, the
# Railway API and the Railway worker, and a release is only successful when all
# of them report it. A path filter breaks that silently — the platform reports
# success while continuing to serve an older commit, which is precisely how
# production came to serve 7eb0e91 while main was 8fd9419.
SKIP_KEYS = frozenset({"watchPatterns", "ignoreCommand"})


def skip_keys(document: object, path: str = "") -> list[str]:
    """Every deployment-skipping key anywhere in a configuration document."""
    found: list[str] = []
    if isinstance(document, dict):
        for key, value in document.items():
            here = f"{path}.{key}" if path else key
            if key in SKIP_KEYS:
                found.append(here)
            found.extend(skip_keys(value, here))
    elif isinstance(document, list):
        for index, value in enumerate(document):
            found.extend(skip_keys(value, f"{path}[{index}]"))
    return found


def main() -> int:
    api = json.loads(Path("railway.json").read_text(encoding="utf-8"))
    worker = json.loads(Path("railway.worker.json").read_text(encoding="utf-8"))
    vercel = json.loads(Path("vercel.json").read_text(encoding="utf-8"))
    environment = Path(".env.supabase.production.example").read_text(encoding="utf-8")

    for name, document in (("railway.json", api), ("railway.worker.json", worker), ("vercel.json", vercel)):
        for found in skip_keys(document):
            raise ValueError(f"{name} must deploy every main commit; remove {found}")

    if api["build"] != {
        "builder": "DOCKERFILE",
        "dockerfilePath": "backend/Dockerfile",
    }:
        raise ValueError("Railway API must build only from the reviewed API Docker contract")
    if api["deploy"].get("preDeployCommand") != ["python manage.py predeploy"]:
        raise ValueError("Railway API pre-deploy must use the reviewed check-and-migrate command")
    if worker["build"].get("dockerfilePath") != "backend/Dockerfile.worker":
        raise ValueError("Railway worker must use the isolated worker image")
    # A startCommand overrides the image CMD and silently skips the fail-fast
    # cache preflight, so the worker must inherit the reviewed image contract.
    if "startCommand" in worker["deploy"]:
        raise ValueError("Railway worker must inherit the worker image entrypoint and command")
    worker_image = Path("backend/Dockerfile.worker").read_text(encoding="utf-8")
    if 'ENTRYPOINT ["netra-entrypoint"]' not in worker_image:
        raise ValueError("Railway worker must correct persistent volume ownership through the reviewed entrypoint")
    if "maintain_storage_cache --startup &&" not in worker_image:
        raise ValueError("Railway worker must fail closed when the encrypted Storage cache is unusable")
    if "run_postgres_worker" not in worker_image:
        raise ValueError("Railway worker must use the PostgreSQL row-lock consumer")

    if vercel.get("buildCommand") != "node scripts/build-vercel-site.mjs":
        raise ValueError("The Vercel project must build both browser workspaces atomically")
    rewrites = {(row["source"], row["destination"]) for row in vercel.get("rewrites", [])}
    if ("/workspace", "/workspace/index.html") not in rewrites:
        raise ValueError("The combined Vercel artifact must mount administration at /workspace")
    csp = next(
        header["value"]
        for group in vercel["headers"]
        for header in group["headers"]
        if header["key"] == "Content-Security-Policy"
    )
    if "*" in csp or "wss:" in csp or "ws:" in csp:
        raise ValueError("The Vercel CSP must contain no wildcard or WebSocket source")
    for origin in (API_ORIGIN, SUPABASE_ORIGIN):
        if origin not in csp:
            raise ValueError(f"The Vercel CSP is missing exact origin {origin}")

    for retired_config in (
        Path("frontend/vercel.json"),
        Path("admin/vercel.json"),
        # The change-aware build filter is retired, not disabled. Leaving the
        # script in the tree invites a future commit to wire it back up.
        Path("scripts/vercel-ignore-build.mjs"),
    ):
        if retired_config.exists():
            raise ValueError(f"Retired deployment file must not exist: {retired_config}")

    required_assignments = {
        "NETRA_AUTH_INVITATIONS_ENABLED": "0",
        "NETRA_PASSWORD_RECOVERY_ENABLED": "0",
        "NETRA_ENABLE_INTEGRATIONS": "0",
        "NETRA_ENABLE_STRUCTURED_IMPORTS": "0",
        "NETRA_STORAGE_DEEP_HEALTHCHECK": "0",
        "NETRA_DIRECT_UPLOAD_ENABLED": "0",
        "NETRA_FRONTEND_ORIGINS": FRONTEND_ORIGIN,
        "NETRA_ADMIN_ORIGINS": ADMIN_ORIGIN,
        "DJANGO_CSRF_TRUSTED_ORIGINS": FRONTEND_ORIGIN,
        "VITE_API_BASE_URL": f"{API_ORIGIN}/api",
        "VITE_CONSOLE_URL": FRONTEND_ORIGIN,
    }
    for name, value in required_assignments.items():
        if not re.search(rf"^{re.escape(name)}={re.escape(value)}$", environment, re.MULTILINE):
            raise ValueError(f"Production example is missing exact assignment {name}")

    for retired in (
        "SUPABASE_ANON_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "VITE_SUPABASE_ANON_KEY",
        "VITE_SUPABASE_REALTIME_ENABLED",
    ):
        if re.search(rf"^{retired}=", environment, re.MULTILINE):
            raise ValueError(f"Retired deployment variable is assigned: {retired}")

    print("Validated the exact-SHA Railway, Vercel, Supabase, and disabled-email deployment contract.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
