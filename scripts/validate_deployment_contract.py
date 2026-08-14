from __future__ import annotations

import json
import re
from pathlib import Path


FRONTEND_ORIGIN = "https://netra-hackathon-console-20260714.vercel.app"
ADMIN_ORIGIN = "https://netra-operations-workspace.vercel.app"
API_ORIGIN = "https://netra-api-production.up.railway.app"
SUPABASE_ORIGIN = "https://frjzewpyjgirorbguegm.supabase.co"


def main() -> int:
    api = json.loads(Path("railway.json").read_text(encoding="utf-8"))
    worker = json.loads(Path("railway.worker.json").read_text(encoding="utf-8"))
    vercel = json.loads(Path("frontend/vercel.json").read_text(encoding="utf-8"))
    admin_vercel = json.loads(Path("admin/vercel.json").read_text(encoding="utf-8"))
    environment = Path(".env.supabase.production.example").read_text(encoding="utf-8")

    if api["build"] != {
        "builder": "DOCKERFILE",
        "dockerfilePath": "backend/Dockerfile",
        "watchPatterns": ["backend/**", "railway.json"],
    }:
        raise ValueError("Railway API must build only from the reviewed API Docker contract")
    if api["deploy"].get("preDeployCommand") != [
        "python manage.py check --deploy && python manage.py migrate --noinput",
    ]:
        raise ValueError("Railway API pre-deploy must run check --deploy before migrate in one command")
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

    for name, config in (("frontend", vercel), ("admin", admin_vercel)):
        if config.get("ignoreCommand") != "node scripts/vercel-ignore-build.mjs":
            raise ValueError(f"{name} Vercel project must use the reviewed change-aware build filter")
        csp = next(
            header["value"]
            for group in config["headers"]
            for header in group["headers"]
            if header["key"] == "Content-Security-Policy"
        )
        if "*" in csp or "wss:" in csp or "ws:" in csp:
            raise ValueError(f"{name} Vercel CSP must contain no wildcard or WebSocket source")
        for origin in (API_ORIGIN, SUPABASE_ORIGIN):
            if origin not in csp:
                raise ValueError(f"{name} Vercel CSP is missing exact origin {origin}")

    for name, expected_path in (("frontend", "frontend"), ("admin", "admin")):
        ignore_script = Path(name, "scripts", "vercel-ignore-build.mjs").read_text(encoding="utf-8")
        if "VERCEL_GIT_PREVIOUS_SHA" not in ignore_script or f'"{expected_path}"' not in ignore_script:
            raise ValueError(f"{name} Vercel build filter does not compare the exact project path and Vercel SHA")

    required_assignments = {
        "NETRA_AUTH_INVITATIONS_ENABLED": "0",
        "NETRA_PASSWORD_RECOVERY_ENABLED": "0",
        "NETRA_ENABLE_INTEGRATIONS": "0",
        "NETRA_ENABLE_STRUCTURED_IMPORTS": "0",
        "NETRA_STORAGE_DEEP_HEALTHCHECK": "0",
        "NETRA_DIRECT_UPLOAD_ENABLED": "0",
        "NETRA_FRONTEND_ORIGINS": f"{FRONTEND_ORIGIN},{ADMIN_ORIGIN}",
        "NETRA_ADMIN_ORIGINS": ADMIN_ORIGIN,
        "DJANGO_CSRF_TRUSTED_ORIGINS": f"{FRONTEND_ORIGIN},{ADMIN_ORIGIN}",
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
