from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from django.conf import settings

from common.jwt_verifier import (
    SupabaseTokenInvalid,
    SupabaseVerificationUnavailable,
    VerifiedSupabaseToken,
    verify_es256_token,
)


@dataclass(frozen=True)
class SupabaseUser:
    id: str
    email: str
    display_name: str
    role: str
    aal: str = "aal1"


@dataclass(frozen=True)
class SupabaseVerification:
    user: SupabaseUser
    verified_token: VerifiedSupabaseToken | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _bounded_json(response, maximum: int) -> dict:
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise SupabaseVerificationUnavailable("Auth response exceeded its configured bound")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupabaseVerificationUnavailable("Auth response was invalid") from exc
    if not isinstance(payload, dict):
        raise SupabaseVerificationUnavailable("Auth response was invalid")
    return payload


def _remote_user(token: str, *, timeout: int, maximum: int) -> dict | None:
    if not settings.SUPABASE_URL or not settings.SUPABASE_PUBLISHABLE_KEY:
        raise SupabaseVerificationUnavailable("Supabase Auth is not configured")
    request = urllib.request.Request(
        f"{settings.SUPABASE_URL.rstrip('/')}/auth/v1/user",
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "apikey": settings.SUPABASE_PUBLISHABLE_KEY,
            "Accept": "application/json",
        },
    )
    try:
        with _opener().open(request, timeout=timeout) as response:
            return _bounded_json(response, maximum)
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            return None
        raise SupabaseVerificationUnavailable("Supabase Auth is unavailable") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SupabaseVerificationUnavailable("Supabase Auth is unavailable") from exc


def _remote_aal(token: str) -> str:
    """Decode AAL only after the same token has been remotely verified."""
    import base64

    try:
        segment = token.split(".")[1]
        segment += "=" * (-len(segment) % 4)
        payload = json.loads(base64.urlsafe_b64decode(segment).decode("utf-8"))
    except (IndexError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return "aal1"
    return "aal2" if payload.get("aal") == "aal2" else "aal1"


def verify_supabase_request_token(token: str) -> SupabaseVerification:
    if settings.NETRA_SUPABASE_JWT_MODE == "asymmetric-jwks":
        verified = verify_es256_token(token)
        display_name = verified.email or str(verified.subject)
        return SupabaseVerification(
            user=SupabaseUser(
                id=str(verified.subject),
                email=verified.email,
                display_name=display_name,
                role="Viewer",
                aal=verified.aal,
            ),
            verified_token=verified,
        )

    payload = _remote_user(token, timeout=3, maximum=64 * 1024)
    if payload is None:
        raise SupabaseTokenInvalid("Supabase session is invalid")
    subject = payload.get("id")
    email = payload.get("email") or ""
    if not isinstance(subject, str) or not subject or not isinstance(email, str) or len(email) > 320:
        raise SupabaseTokenInvalid("Supabase identity response is invalid")
    metadata = payload.get("user_metadata") if isinstance(payload.get("user_metadata"), dict) else {}
    display_name = metadata.get("display_name") or metadata.get("name") or email or subject
    if not isinstance(display_name, str):
        display_name = email or subject
    return SupabaseVerification(
        user=SupabaseUser(id=subject, email=email, display_name=display_name[:200], role="Viewer", aal=_remote_aal(token))
    )


def verify_supabase_token(token: str) -> SupabaseUser | None:
    """Compatibility helper for login/refresh call sites."""
    try:
        return verify_supabase_request_token(token).user
    except (SupabaseTokenInvalid, SupabaseVerificationUnavailable):
        return None


def verify_privileged_supabase_session(token: str, expected_subject: str) -> bool:
    payload = _remote_user(
        token,
        timeout=settings.NETRA_SUPABASE_PRIVILEGED_VERIFY_TIMEOUT_SECONDS,
        maximum=64 * 1024,
    )
    if payload is None:
        return False
    subject = payload.get("id")
    return isinstance(subject, str) and subject == expected_subject


def _auth_request(path: str, payload: dict, *, timeout: int) -> dict | None:
    if not settings.SUPABASE_URL or not settings.SUPABASE_PUBLISHABLE_KEY:
        return None
    request = urllib.request.Request(
        f"{settings.SUPABASE_URL.rstrip('/')}{path}",
        method="POST",
        data=json.dumps(payload).encode("utf-8"),
        headers={"apikey": settings.SUPABASE_PUBLISHABLE_KEY, "Content-Type": "application/json"},
    )
    try:
        with _opener().open(request, timeout=timeout) as response:
            return _bounded_json(response, 128 * 1024)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, SupabaseVerificationUnavailable):
        return None


def supabase_password_login(email: str, password: str) -> dict | None:
    return _auth_request("/auth/v1/token?grant_type=password", {"email": email, "password": password}, timeout=15)


def supabase_refresh(refresh_token: str) -> dict | None:
    return _auth_request("/auth/v1/token?grant_type=refresh_token", {"refresh_token": refresh_token}, timeout=15)
