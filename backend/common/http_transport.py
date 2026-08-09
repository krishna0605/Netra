from __future__ import annotations

import urllib.request
from urllib.parse import urlsplit


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


def normalized_https_origin(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port not in {None, 443}
    ):
        raise RuntimeError("The configured service origin must be an HTTPS origin without credentials or a path.")
    return f"https://{parsed.hostname.lower()}"


def open_same_origin(request: urllib.request.Request, *, origin: str, timeout: float):
    expected = normalized_https_origin(origin)
    requested = urlsplit(request.full_url)
    requested_origin = normalized_https_origin(f"{requested.scheme}://{requested.netloc}")
    if requested_origin != expected:
        raise RuntimeError("The outbound request does not match the configured service origin.")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    return opener.open(request, timeout=timeout)


def bounded_read(response, maximum_bytes: int) -> bytes:
    payload = response.read(maximum_bytes + 1)
    if len(payload) > maximum_bytes:
        raise RuntimeError("The remote response exceeded its configured size bound.")
    return payload
