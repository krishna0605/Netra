from __future__ import annotations

import json
import re
from pathlib import Path


FRONTEND_ORIGIN = "https://netra-hackathon-console-20260714.vercel.app"
ADMIN_ORIGIN = FRONTEND_ORIGIN
API_ORIGIN = "https://netra-api-production.up.railway.app"
SUPABASE_ORIGIN = "https://frjzewpyjgirorbguegm.supabase.co"


def main() -> int:
    api = json.loads(Path("railway.json").read_text(encoding="utf-8"))
    worker = json.loads(Path("railway.worker.json").read_text(encoding="utf-8"))
    vercel = json.loads(Path("vercel.json").read_text(encoding="utf-8"))
    environment = Path(".env.supabase.production.example").read_text(encoding="utf-8")

    if api["build"] != {
        "builder": "DOCKERFILE",
        "dockerfilePath": "backend/Dockerfile",
        "watchPatterns": ["backend/**", "railway.json"],
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

    if vercel.get("ignoreCommand") != "node scripts/vercel-ignore-build.mjs":
        raise ValueError("The Vercel project must use the reviewed change-aware build filter")
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

    for retired_config in (Path("frontend/vercel.json"), Path("admin/vercel.json")):
        if retired_config.exists():
            raise ValueError(f"Second-project Vercel config must not exist: {retired_config}")
    ignore_script = Path("scripts/vercel-ignore-build.mjs").read_text(encoding="utf-8")
    if "VERCEL_GIT_PREVIOUS_SHA" not in ignore_script:
        raise ValueError("The Vercel build filter must compare exact Vercel SHAs")
    for expected_path in ('"frontend"', '"admin"', '"vercel.json"'):
        if expected_path not in ignore_script:
            raise ValueError(f"The Vercel build filter does not watch {expected_path}")

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

    print("Validated the main-only Railway, Vercel, Supabase, and disabled-email deployment contract.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
