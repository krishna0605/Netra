import io
import socket
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import IntegrationConnection, IntegrationCredential, IntegrationDelivery, UserProfile
from apps.forensics.services.integration_credentials import read_integration_secret, store_integration_secret
from apps.forensics.services.webhook_delivery import (
    ValidatedWebhook,
    WebhookDeliveryProblem,
    claim_next_delivery,
    process_delivery,
    queue_delivery,
    validate_webhook_url,
)
from apps.forensics.tests.factories import netra_organization


def dns(address: str):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (address, 443))]


@override_settings(NETRA_WEBHOOK_ALLOWED_HOSTS=["hooks.example.test"])
class WebhookDestinationTests(SimpleTestCase):
    @patch("apps.forensics.services.webhook_delivery.socket.getaddrinfo", return_value=dns("93.184.216.34"))
    def test_exact_https_allowlist_is_accepted(self, _resolver):
        target = validate_webhook_url("https://hooks.example.test/netra?source=test")
        self.assertEqual(target.hostname, "hooks.example.test")
        self.assertEqual(target.path, "/netra?source=test")

    def test_http_userinfo_nonstandard_port_and_unlisted_host_are_rejected(self):
        for url in (
            "http://hooks.example.test/netra",
            "https://user@hooks.example.test/netra",
            "https://hooks.example.test:8443/netra",
            "https://evil.example.test/netra",
            "https://hooks.example.test./netra",
            "https://hooks.example.test/netra#fragment",
        ):
            with self.assertRaises(WebhookDeliveryProblem, msg=url):
                validate_webhook_url(url)

    @override_settings(NETRA_WEBHOOK_ALLOWED_HOSTS=["127.0.0.1", "::1"])
    def test_ip_literal_hosts_are_rejected_even_if_misconfigured_in_allowlist(self):
        for url in ("https://127.0.0.1/netra", "https://[::1]/netra"):
            with self.assertRaises(WebhookDeliveryProblem, msg=url):
                validate_webhook_url(url)

    @patch("apps.forensics.services.webhook_delivery.socket.getaddrinfo", return_value=dns("127.0.0.1"))
    def test_private_or_loopback_resolution_is_rejected(self, _resolver):
        with self.assertRaisesRegex(WebhookDeliveryProblem, "unsafe network"):
            validate_webhook_url("https://hooks.example.test/netra")

    @patch(
        "apps.forensics.services.webhook_delivery.socket.getaddrinfo",
        return_value=dns("93.184.216.34") + dns("169.254.169.254"),
    )
    def test_mixed_safe_and_metadata_dns_answers_are_rejected(self, _resolver):
        with self.assertRaises(WebhookDeliveryProblem):
            validate_webhook_url("https://hooks.example.test/netra")


@override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_ENABLE_INTEGRATIONS=True,
    NETRA_WEBHOOK_ALLOWED_HOSTS=["hooks.example.test"],
    NETRA_EVIDENCE_KEY="phase-five-integration-test-key",
    NETRA_EVIDENCE_KEY_ID="phase-five-integration-key-id",
)
class IntegrationCredentialTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        self.user = get_user_model().objects.create_user(username="integration-admin@example.test")
        UserProfile.objects.create(user=self.user, organization=self.organization, role="Admin")
        token = RefreshToken.for_user(self.user).access_token
        token["aal"] = "aal2"
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {str(token)}"}
        self.client = Client()
        self.connection = IntegrationConnection.objects.create(
            organization=self.organization,
            system_name="Synthetic webhook",
            api_mode="webhook-json",
            config={"url": "https://hooks.example.test/netra"},
        )

    def test_new_credential_is_encrypted_and_round_trips(self):
        credential = store_integration_secret(self.connection, "synthetic-secret")
        self.assertEqual(credential.secret_value, "")
        self.assertTrue(credential.secret_envelope.get("ciphertext"))
        self.assertNotIn("synthetic-secret", str(credential.secret_envelope))
        self.assertEqual(read_integration_secret(self.connection), "synthetic-secret")

    def test_credential_endpoint_requires_aal2_and_never_returns_secret(self):
        response = self.client.put(
            f"/api/integrations/{self.connection.pk}/credential",
            data={"secret": "another-secret"},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["encrypted"])
        self.assertNotContains(response, "another-secret")

    def test_plan_only_migration_does_not_change_plaintext_credential(self):
        credential = IntegrationCredential.objects.create(
            integration=self.connection,
            secret_label="legacy",
            secret_value="legacy-secret",
        )
        output = io.StringIO()
        call_command("migrate_integration_credentials", stdout=output)
        credential.refresh_from_db()
        self.assertEqual(credential.secret_value, "legacy-secret")
        self.assertEqual(credential.secret_envelope, {})
        self.assertIn("PLAN ONLY", output.getvalue())

    def test_configuration_rejects_nested_credentials(self):
        response = self.client.post(
            "/api/integrations",
            data={"systemName": "Unsafe config", "config": {"headers": [{"client-secret": "secret"}]}},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "secret_not_accepted")

    @patch("apps.forensics.services.webhook_delivery.validate_webhook_url")
    @patch("apps.forensics.services.webhook_delivery._PinnedHTTPSConnection")
    def test_durable_worker_claims_and_completes_one_delivery(self, connection_class, validate):
        store_integration_secret(self.connection, "delivery-secret")
        validate.return_value = ValidatedWebhook("hooks.example.test", "/netra", ("93.184.216.34",))
        response = MagicMock(status=204)
        response.read.return_value = b""
        connection_class.return_value.getresponse.return_value = response
        delivery, created = queue_delivery(
            integration=self.connection,
            case=None,
            delivery_type="test",
            payload={"source": "netra"},
            idempotency_key="delivery-test-1",
        )
        self.assertTrue(created)
        claimed = claim_next_delivery("worker-test")
        self.assertEqual(claimed.pk, delivery.pk)
        completed = process_delivery(claimed)
        self.assertEqual(completed.result, "success")
        self.assertEqual(validate.call_count, 2)

    def test_idempotency_key_conflict_cannot_rebind_a_delivery(self):
        first, created = queue_delivery(
            integration=self.connection,
            case=None,
            delivery_type="test",
            payload={"source": "netra", "value": 1},
            idempotency_key="delivery-conflict-1",
        )
        self.assertTrue(created)
        with self.assertRaisesRegex(WebhookDeliveryProblem, "different delivery operation"):
            queue_delivery(
                integration=self.connection,
                case=None,
                delivery_type="test",
                payload={"source": "netra", "value": 2},
                idempotency_key="delivery-conflict-1",
            )
        self.assertEqual(IntegrationDelivery.objects.get(pk=first.pk).payload_json["value"], 1)

    def test_expired_worker_lease_is_reclaimed_once(self):
        delivery, _ = queue_delivery(
            integration=self.connection,
            case=None,
            delivery_type="test",
            payload={"source": "netra"},
            idempotency_key="delivery-expired-lease",
        )
        delivery.result = "running"
        delivery.attempt_count = 0
        delivery.lease_owner = "dead-worker"
        delivery.lease_expires_at = timezone.now() - timedelta(seconds=1)
        delivery.save()
        claimed = claim_next_delivery("replacement-worker")
        self.assertEqual(claimed.pk, delivery.pk)
        self.assertEqual(claimed.lease_owner, "replacement-worker")
        self.assertEqual(claimed.attempt_count, 1)

    @patch("apps.forensics.services.webhook_delivery._PinnedHTTPSConnection")
    @patch("apps.forensics.services.webhook_delivery.validate_webhook_url")
    def test_changed_dns_answer_is_rejected_before_socket_connect(self, validate, connection_class):
        store_integration_secret(self.connection, "delivery-secret")
        validate.side_effect = [
            ValidatedWebhook("hooks.example.test", "/netra", ("93.184.216.34",)),
            ValidatedWebhook("hooks.example.test", "/netra", ("93.184.216.35",)),
        ]
        delivery, _ = queue_delivery(
            integration=self.connection,
            case=None,
            delivery_type="test",
            payload={"source": "netra"},
            idempotency_key="delivery-rebinding",
        )
        delivery.attempt_count = 1
        delivery.save(update_fields=["attempt_count", "updated_at"])
        completed = process_delivery(delivery)
        self.assertEqual(completed.error_code, "webhook_dns_rebinding")
        connection_class.assert_not_called()
