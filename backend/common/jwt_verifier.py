from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Mapping
from uuid import UUID

import jwt
from django.conf import settings

from common.step_up import factor_verified_at


MAX_TOKEN_BYTES = 16 * 1024
MAX_KID_LENGTH = 128
MAX_EMAIL_LENGTH = 320
MAX_JWKS_KEYS = 10
NEGATIVE_CACHE_SECONDS = 30


class SupabaseTokenInvalid(Exception):
    """The bearer token cannot establish a Supabase identity."""


class SupabaseVerificationUnavailable(Exception):
    """A valid verification key cannot currently be obtained safely."""


@dataclass(frozen=True)
class VerifiedSupabaseToken:
    subject: UUID
    email: str
    aal: str
    # When the session last proved possession of a second factor, read from the
    # amr claim. None when the token records no such challenge. Callers that
    # gate destructive work must read this rather than aal, which only says a
    # factor was used at some point in the session's life.
    factor_verified_at: datetime | None
    session_id: str
    issuer: str
    audience: tuple[str, ...]
    expires_at: datetime
    issued_at: datetime
    key_id: str
    algorithm: str
    token_fingerprint: str


@dataclass(frozen=True)
class JwksCacheState:
    fetched_at: datetime | None
    expires_at: datetime | None
    keys_by_id: Mapping[str, object]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


_lock = threading.Lock()
_keys_by_id: dict[str, object] = {}
_fetched_at = 0.0
_expires_at = 0.0
_negative_kids: dict[str, float] = {}


def reset_jwks_cache() -> None:
    """Reset process-local state. Intended for deterministic tests only."""
    global _keys_by_id, _fetched_at, _expires_at
    with _lock:
        _keys_by_id = {}
        _fetched_at = 0.0
        _expires_at = 0.0
        _negative_kids.clear()


def jwks_cache_state(*, now: float | None = None) -> JwksCacheState:
    current = time.time() if now is None else now
    with _lock:
        fetched = datetime.fromtimestamp(_fetched_at, UTC) if _fetched_at else None
        expires = datetime.fromtimestamp(_expires_at, UTC) if _expires_at > current else None
        keys = MappingProxyType(dict(_keys_by_id)) if _expires_at > current else MappingProxyType({})
    return JwksCacheState(fetched_at=fetched, expires_at=expires, keys_by_id=keys)


def _issuer() -> str:
    base = settings.SUPABASE_URL.rstrip("/")
    if not base.startswith("https://"):
        raise SupabaseVerificationUnavailable("Supabase issuer is not configured with HTTPS")
    return f"{base}/auth/v1"


def _bounded_read(response, maximum: int) -> bytes:
    payload = response.read(maximum + 1)
    if len(payload) > maximum:
        raise SupabaseVerificationUnavailable("JWKS response exceeded its configured bound")
    return payload


def _fetch_jwks() -> dict[str, object]:
    request = urllib.request.Request(
        f"{_issuer()}/.well-known/jwks.json",
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "Netra-JWKS/1"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=settings.NETRA_SUPABASE_JWKS_TIMEOUT_SECONDS) as response:
            if getattr(response, "status", 200) != 200:
                raise SupabaseVerificationUnavailable("JWKS endpoint returned an unexpected status")
            body = _bounded_read(response, settings.NETRA_SUPABASE_JWKS_RESPONSE_MAX_BYTES)
        document = json.loads(body.decode("utf-8"))
    except SupabaseVerificationUnavailable:
        raise
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupabaseVerificationUnavailable("JWKS endpoint is unavailable") from exc

    records = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(records, list) or not records or len(records) > MAX_JWKS_KEYS:
        raise SupabaseVerificationUnavailable("JWKS did not contain a bounded key set")
    parsed: dict[str, object] = {}
    try:
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("invalid key")
            kid = record.get("kid")
            if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_LENGTH or kid in parsed:
                raise ValueError("invalid or duplicate kid")
            if record.get("kty") != "EC" or record.get("crv") != "P-256" or record.get("alg") != "ES256":
                raise ValueError("unsupported key")
            if record.get("use") not in {None, "sig"}:
                raise ValueError("invalid key use")
            key_ops = record.get("key_ops")
            if key_ops is not None and (not isinstance(key_ops, list) or set(key_ops) != {"verify"}):
                raise ValueError("invalid key operations")
            parsed[kid] = jwt.PyJWK.from_dict(record, algorithm="ES256").key
    except (ValueError, jwt.PyJWKError) as exc:
        raise SupabaseVerificationUnavailable("JWKS contained an invalid signing key") from exc
    return parsed


def _refresh(*, now: float) -> None:
    global _keys_by_id, _fetched_at, _expires_at
    parsed = _fetch_jwks()
    _keys_by_id = parsed
    _fetched_at = now
    _expires_at = now + settings.NETRA_SUPABASE_JWKS_CACHE_SECONDS
    _negative_kids.clear()


def _key_for(kid: str, *, now: float) -> object:
    with _lock:
        if _expires_at > now and kid in _keys_by_id:
            return _keys_by_id[kid]
        if _negative_kids.get(kid, 0) > now:
            raise SupabaseTokenInvalid("Unknown signing key")
        try:
            _refresh(now=now)
        except SupabaseVerificationUnavailable:
            if _expires_at > now and kid in _keys_by_id:
                return _keys_by_id[kid]
            raise
        if kid not in _keys_by_id:
            _negative_kids[kid] = now + NEGATIVE_CACHE_SECONDS
            raise SupabaseTokenInvalid("Unknown signing key")
        return _keys_by_id[kid]


def verify_es256_token(token: str, *, now: float | None = None) -> VerifiedSupabaseToken:
    if not isinstance(token, str) or not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES or token.count(".") != 2:
        raise SupabaseTokenInvalid("Malformed bearer token")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise SupabaseTokenInvalid("Malformed JWT header") from exc
    if header.get("alg") != "ES256" or header.get("typ") not in {None, "JWT"}:
        raise SupabaseTokenInvalid("Unsupported JWT algorithm or type")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid or len(kid) > MAX_KID_LENGTH:
        raise SupabaseTokenInvalid("Missing or invalid signing key ID")

    timestamp = time.time() if now is None else now
    key = _key_for(kid, now=timestamp)
    issuer = _issuer()
    audience = settings.NETRA_SUPABASE_JWT_AUDIENCE
    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=["ES256"],
            audience=audience,
            issuer=issuer,
            leeway=30,
            options={"require": ["iss", "aud", "exp", "iat", "sub", "aal", "role"]},
        )
    except jwt.PyJWTError as exc:
        raise SupabaseTokenInvalid("JWT signature or claims are invalid") from exc

    if claims.get("role") != "authenticated" or claims.get("aal") not in {"aal1", "aal2"}:
        raise SupabaseTokenInvalid("JWT role or assurance level is invalid")
    try:
        subject = UUID(str(claims["sub"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SupabaseTokenInvalid("JWT subject is invalid") from exc
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if not isinstance(issued_at, (int, float)) or not isinstance(expires_at, (int, float)) or issued_at > timestamp + 30:
        raise SupabaseTokenInvalid("JWT timestamps are invalid")
    email = claims.get("email", "")
    if not isinstance(email, str) or len(email) > MAX_EMAIL_LENGTH:
        raise SupabaseTokenInvalid("JWT email is invalid")
    token_fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
    session_id = claims.get("session_id", "")
    if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
        # Older/local tokens may not carry Supabase's session_id claim. Binding
        # the context to the verified token fingerprint remains fail-closed;
        # a refresh simply creates a new context.
        session_id = token_fingerprint
    aud_claim = claims.get("aud")
    audiences = (aud_claim,) if isinstance(aud_claim, str) else tuple(aud_claim)
    return VerifiedSupabaseToken(
        subject=subject,
        email=email,
        aal=claims["aal"],
        # Deliberately not added to the require list above. A password-only
        # session legitimately carries no second-factor entry, and demanding
        # the claim would reject every one of them. Absence is handled where it
        # matters — as a refusal at the step-up gate — not by making every
        # ordinary request fail here.
        factor_verified_at=factor_verified_at(claims.get("amr")),
        session_id=session_id,
        issuer=issuer,
        audience=audiences,
        expires_at=datetime.fromtimestamp(expires_at, UTC),
        issued_at=datetime.fromtimestamp(issued_at, UTC),
        key_id=kid,
        algorithm="ES256",
        token_fingerprint=token_fingerprint,
    )
