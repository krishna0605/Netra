from __future__ import annotations


def elevated_api_headers(key: str, *, content_type: str | None = None) -> dict[str, str]:
    """Build privileged Supabase API headers for modern and legacy keys.

    Modern ``sb_secret_`` keys are opaque API keys, not JWTs. Sending one as
    ``Authorization: Bearer`` causes downstream Supabase services to reject it
    as an invalid JWT. Legacy service-role keys remain valid bearer tokens.
    """

    headers = {"apikey": key}
    if not key.startswith("sb_secret_"):
        headers["Authorization"] = f"Bearer {key}"
    if content_type:
        headers["Content-Type"] = content_type
    return headers
