from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from apps.forensics.models import IntegrationDelivery
from apps.forensics.services.integration_credentials import read_integration_secret


class WebhookDeliveryProblem(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ValidatedWebhook:
    hostname: str
    path: str
    addresses: tuple[str, ...]


def _normalize_host(hostname: str) -> str:
    return hostname.rstrip(".").encode("idna").decode("ascii").lower()


def _allowed_hosts() -> set[str]:
    return {
        _normalize_host(value.strip())
        for value in getattr(settings, "NETRA_WEBHOOK_ALLOWED_HOSTS", [])
        if value.strip()
    }


def _safe_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_global and not any(
        (
            address.is_loopback,
            address.is_private,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )


def validate_webhook_url(url: str) -> ValidatedWebhook:
    try:
        parsed = urlsplit((url or "").strip())
        hostname = _normalize_host(parsed.hostname or "")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise WebhookDeliveryProblem("webhook_destination_not_allowed", "The webhook destination is invalid.") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
        or hostname not in _allowed_hosts()
    ):
        raise WebhookDeliveryProblem("webhook_destination_not_allowed", "The webhook destination is not approved.")
    try:
        records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise WebhookDeliveryProblem("webhook_destination_unavailable", "The webhook destination could not be resolved.") from exc
    addresses = tuple(sorted({record[4][0] for record in records}))
    if not addresses or not all(_safe_address(value) for value in addresses):
        raise WebhookDeliveryProblem("webhook_destination_unsafe", "The webhook destination resolves to an unsafe network.")
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return ValidatedWebhook(hostname=hostname, path=path, addresses=addresses)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str):
        super().__init__(hostname, port=443, timeout=settings.NETRA_WEBHOOK_CONNECT_TIMEOUT_SECONDS, context=ssl.create_default_context())
        self._address = address

    def connect(self):
        raw = socket.create_connection((self._address, 443), self.timeout)
        raw.settimeout(settings.NETRA_WEBHOOK_READ_TIMEOUT_SECONDS)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def queue_delivery(*, integration, case, delivery_type: str, payload: dict, idempotency_key: str) -> tuple[IntegrationDelivery, bool]:
    if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > settings.NETRA_WEBHOOK_REQUEST_MAX_BYTES:
        raise WebhookDeliveryProblem("webhook_payload_too_large", "The webhook payload exceeds the configured limit.")
    return IntegrationDelivery.objects.get_or_create(
        idempotency_key=idempotency_key,
        defaults={
            "integration": integration,
            "case": case,
            "delivery_type": delivery_type,
            "payload_json": payload,
            "result": "queued",
            "max_attempts": settings.NETRA_WEBHOOK_MAX_ATTEMPTS,
            "next_attempt_at": timezone.now(),
        },
    )


@transaction.atomic
def claim_next_delivery(worker_id: str) -> IntegrationDelivery | None:
    now = timezone.now()
    delivery = (
        IntegrationDelivery.objects.select_for_update(skip_locked=True)
        .select_related("integration", "integration__credential", "case")
        .filter(result__in=["queued", "retry_wait"], attempt_count__lt=F("max_attempts"))
        .filter(Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
        .order_by("created_at")
        .first()
    )
    if delivery is None:
        return None
    delivery.result = "running"
    delivery.attempt_count += 1
    delivery.lease_owner = worker_id
    delivery.claimed_at = now
    delivery.lease_expires_at = now + timedelta(seconds=30)
    delivery.save()
    return delivery


def process_delivery(delivery: IntegrationDelivery) -> IntegrationDelivery:
    connection = delivery.integration
    url = str(connection.config.get("url") or "")
    body = json.dumps(delivery.payload_json, sort_keys=True, separators=(",", ":")).encode("utf-8")
    secret = read_integration_secret(connection)
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest() if secret else ""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Netra/phase5",
        "Idempotency-Key": delivery.idempotency_key or str(delivery.pk),
    }
    if signature:
        headers["X-Netra-Signature"] = signature
    try:
        target = validate_webhook_url(url)
        # Re-resolve immediately before the pinned connection. A changed or
        # unsafe answer fails before any socket is opened.
        target = validate_webhook_url(url)
        connection_http = _PinnedHTTPSConnection(target.hostname, target.addresses[0])
        try:
            connection_http.request("POST", target.path, body=body, headers=headers)
            response = connection_http.getresponse()
            preview = response.read(settings.NETRA_WEBHOOK_RESPONSE_MAX_BYTES + 1)
        finally:
            connection_http.close()
        if len(preview) > settings.NETRA_WEBHOOK_RESPONSE_MAX_BYTES:
            raise WebhookDeliveryProblem("webhook_response_too_large", "The webhook response exceeded the configured limit.")
        if 300 <= response.status < 400:
            raise WebhookDeliveryProblem("webhook_redirect_rejected", "Webhook redirects are not followed.")
        if not 200 <= response.status < 300:
            raise WebhookDeliveryProblem("webhook_http_error", "The webhook returned a non-success status.")
        delivery.result = "success"
        delivery.response_summary = f"HTTP {response.status}"
        delivery.error_code = ""
        connection.status = "connected"
        connection.last_sync_at = timezone.now()
        connection.save(update_fields=["status", "last_sync_at", "updated_at"])
    except WebhookDeliveryProblem as problem:
        delivery.error_code = problem.code
        delivery.response_summary = problem.code
        delivery.result = "retry_wait" if delivery.attempt_count < delivery.max_attempts else "failed"
        delivery.next_attempt_at = timezone.now() + timedelta(seconds=5)
    except Exception:
        delivery.error_code = "webhook_delivery_failed"
        delivery.response_summary = "webhook_delivery_failed"
        delivery.result = "retry_wait" if delivery.attempt_count < delivery.max_attempts else "failed"
        delivery.next_attempt_at = timezone.now() + timedelta(seconds=5)
    delivery.lease_owner = ""
    delivery.lease_expires_at = None
    delivery.save()
    return delivery
