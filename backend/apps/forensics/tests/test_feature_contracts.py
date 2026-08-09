from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import UserProfile
from apps.forensics.tests.factories import netra_organization


@override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_SEARCH_PROVIDER="postgres",
    NETRA_ENABLE_INTEGRATIONS=False,
)
class CapabilityContractTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="capabilities@example.test")
        UserProfile.objects.create(user=user, organization=netra_organization(), role="Admin")
        token = str(RefreshToken.for_user(user).access_token)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        self.client = Client()

    def test_capabilities_are_authoritative_and_also_exposed_by_identity(self):
        response = self.client.get("/api/capabilities", **self.headers)
        self.assertEqual(response.status_code, 200)
        capabilities = response.json()["results"]
        self.assertEqual(capabilities["postgres_search"]["state"], "available")
        self.assertEqual(capabilities["integration_delivery"]["state"], "not_implemented")
        self.assertEqual(capabilities["integration_configuration"]["state"], "disabled")
        self.assertEqual(self.client.get("/api/auth/me", **self.headers).json()["capabilities"], capabilities)
