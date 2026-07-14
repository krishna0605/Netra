from __future__ import annotations

import json
import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass

from django.conf import settings
from django.core.cache import cache


@dataclass(frozen=True)
class SupabaseUser:
    id: str
    email: str
    display_name: str
    role: str


def verify_supabase_token(token: str) -> SupabaseUser | None:
    if not settings.SUPABASE_URL or not settings.SUPABASE_ANON_KEY:
        return None
    token_fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
    cache_key = f"netra:supabase-user:{token_fingerprint}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return SupabaseUser(**cached)
    request = urllib.request.Request(
        f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/user",
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "apikey": settings.SUPABASE_ANON_KEY,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    email = payload.get("email") or ""
    metadata = payload.get("user_metadata") or {}
    app_metadata = payload.get("app_metadata") or {}
    role = app_metadata.get("netra_role") or app_metadata.get("role") or "Viewer"
    if role not in {"Admin", "Investigator", "Analyst", "Viewer"}:
        role = "Viewer"
    display_name = metadata.get("display_name") or metadata.get("name") or email or payload.get("id", "Supabase User")
    user = SupabaseUser(id=payload.get("id", ""), email=email, display_name=display_name, role=role)
    if settings.NETRA_SUPABASE_TOKEN_CACHE_SECONDS:
        cache.set(cache_key, user.__dict__, timeout=settings.NETRA_SUPABASE_TOKEN_CACHE_SECONDS)
    return user


def supabase_password_login(email: str, password: str) -> dict | None:
    if not settings.SUPABASE_URL or not settings.SUPABASE_ANON_KEY:
        return None
    body = json.dumps({"email": email, "password": password}).encode("utf-8")
    request = urllib.request.Request(
        f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/token?grant_type=password",
        method="POST",
        data=body,
        headers={"apikey": settings.SUPABASE_ANON_KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def supabase_refresh(refresh_token: str) -> dict | None:
    if not settings.SUPABASE_URL or not settings.SUPABASE_ANON_KEY:
        return None
    body = json.dumps({"refresh_token": refresh_token}).encode("utf-8")
    request = urllib.request.Request(
        f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/token?grant_type=refresh_token",
        method="POST",
        data=body,
        headers={"apikey": settings.SUPABASE_ANON_KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
