"""Minimal, bounded Supabase Auth Admin client for trusted backend use only."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from django.conf import settings


class SupabaseAdminError(RuntimeError):
    pass


class SupabaseAdminConflict(SupabaseAdminError):
    pass


@dataclass(frozen=True)
class SupabaseAdminUser:
    id: str
    email: str
    invited_at: str
    email_confirmed_at: str
    last_sign_in_at: str
    mfa_state: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _bounded_json(response) -> dict[str, Any]:
    maximum = settings.NETRA_AUTH_ADMIN_RESPONSE_MAX_BYTES
    raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise SupabaseAdminError("Supabase Auth response exceeded the configured safety limit.")
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupabaseAdminError("Supabase Auth returned an invalid response.") from exc
    if not isinstance(payload, dict):
        raise SupabaseAdminError("Supabase Auth returned an invalid response.")
    return payload


def _request(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if not settings.SUPABASE_URL or not settings.SUPABASE_SECRET_KEY:
        raise SupabaseAdminError("Supabase Auth administration is not configured.")
    base = settings.SUPABASE_URL.rstrip("/")
    url = f"{base}/auth/v1/{path.lstrip('/')}"
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        method=method,
        data=body,
        headers={
            "apikey": settings.SUPABASE_SECRET_KEY,
            "Authorization": f"Bearer {settings.SUPABASE_SECRET_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Netra-Auth-Admin/1",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=settings.NETRA_AUTH_ADMIN_TIMEOUT_SECONDS) as response:
            return _bounded_json(response)
    except urllib.error.HTTPError as exc:
        if exc.code in {400, 409, 422}:
            raise SupabaseAdminConflict("The Supabase Auth identity already exists or conflicts.") from exc
        raise SupabaseAdminError("Supabase Auth administration is temporarily unavailable.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SupabaseAdminError("Supabase Auth administration is temporarily unavailable.") from exc


def _user_from_payload(payload: dict[str, Any]) -> SupabaseAdminUser:
    factors = payload.get("factors") if isinstance(payload.get("factors"), list) else []
    verified = any(isinstance(factor, dict) and factor.get("status") == "verified" for factor in factors)
    return SupabaseAdminUser(
        id=str(payload.get("id") or ""),
        email=str(payload.get("email") or "").strip().lower(),
        invited_at=str(payload.get("invited_at") or ""),
        email_confirmed_at=str(payload.get("email_confirmed_at") or payload.get("confirmed_at") or ""),
        last_sign_in_at=str(payload.get("last_sign_in_at") or ""),
        mfa_state="verified" if verified else "unenrolled",
    )


def invite_user(email: str, *, redirect_to: str) -> SupabaseAdminUser:
    payload = _request(
        "invite",
        method="POST",
        payload={"email": email, "redirect_to": redirect_to},
    )
    return _user_from_payload(payload)


def list_users(*, page: int = 1) -> tuple[list[SupabaseAdminUser], int | None]:
    page = max(1, page)
    per_page = settings.NETRA_AUTH_ADMIN_LIST_PAGE_SIZE
    query = urllib.parse.urlencode({"page": page, "per_page": per_page})
    payload = _request(f"admin/users?{query}")
    rows = payload.get("users") if isinstance(payload.get("users"), list) else []
    users = [_user_from_payload(row) for row in rows if isinstance(row, dict)]
    next_page = page + 1 if len(users) == per_page else None
    return users, next_page


def find_user_by_email(email: str, *, max_pages: int = 5) -> SupabaseAdminUser | None:
    expected = email.strip().lower()
    for page in range(1, max_pages + 1):
        users, next_page = list_users(page=page)
        for user in users:
            if user.email == expected:
                return user
        if next_page is None:
            break
    return None


@dataclass(frozen=True)
class SupabaseFactor:
    id: str
    factor_type: str
    status: str
    friendly_name: str


def _factor_from_payload(payload: dict[str, Any]) -> SupabaseFactor:
    return SupabaseFactor(
        id=str(payload.get("id") or ""),
        factor_type=str(payload.get("factor_type") or ""),
        status=str(payload.get("status") or ""),
        friendly_name=str(payload.get("friendly_name") or ""),
    )


def create_user(email: str, password: str, *, email_confirm: bool = True) -> SupabaseAdminUser:
    """Create an account with a password the administrator chose.

    email_confirm defaults to True because nothing is sent. The deployment has
    no approved custom SMTP domain, so an unconfirmed account would wait on a
    message that never arrives. The administrator hands the password over in
    person or by whatever channel the unit already trusts, which is also why
    this exists instead of the invitation flow.
    """
    payload = _request(
        "admin/users",
        method="POST",
        payload={"email": email, "password": password, "email_confirm": email_confirm},
    )
    return _user_from_payload(payload)


def get_user(user_id: str) -> SupabaseAdminUser | None:
    try:
        return _user_from_payload(_request(f"admin/users/{urllib.parse.quote(user_id, safe='')}"))
    except SupabaseAdminError:
        return None


def set_password(user_id: str, password: str) -> SupabaseAdminUser:
    """Replace an account's password.

    GoTrue invalidates the account's refresh tokens as a side effect, so no new
    access tokens can be minted afterwards. Already-issued access tokens are a
    separate problem and are handled by the Netra-side denylist; see
    common/session_revocation.py.
    """
    return _user_from_payload(
        _request(
            f"admin/users/{urllib.parse.quote(user_id, safe='')}",
            method="PUT",
            payload={"password": password},
        )
    )


def set_ban(user_id: str, *, banned: bool) -> SupabaseAdminUser:
    """Disable or restore an account at the identity provider.

    Deactivation is a ban, never a delete. Deleting the Supabase identity would
    orphan every custody and audit row that names it, and those rows are
    evidence handling records that must keep resolving to a person long after
    that person has left the unit.

    "none" is GoTrue's spelling for lifting a ban; a duration lifts it by
    expiry, and there is no separate unban call.
    """
    return _user_from_payload(
        _request(
            f"admin/users/{urllib.parse.quote(user_id, safe='')}",
            method="PUT",
            payload={"ban_duration": "876000h" if banned else "none"},
        )
    )


def list_factors(user_id: str) -> list[SupabaseFactor]:
    payload = _request(f"admin/users/{urllib.parse.quote(user_id, safe='')}/factors")
    rows = payload.get("factors") if isinstance(payload.get("factors"), list) else []
    if not rows and isinstance(payload.get("data"), list):
        rows = payload["data"]
    return [_factor_from_payload(row) for row in rows if isinstance(row, dict)]


def delete_factor(user_id: str, factor_id: str) -> None:
    _request(
        f"admin/users/{urllib.parse.quote(user_id, safe='')}/factors/{urllib.parse.quote(factor_id, safe='')}",
        method="DELETE",
    )
