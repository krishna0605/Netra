from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.forensics.models import Case, CaseMembership, OperationalEvent, UserProfile
from apps.forensics.tests.factories import netra_organization


@override_settings(
    NETRA_ACCESS_MODE="bearer",
    NETRA_AUTH_PROVIDER="django",
    NETRA_AUTH_PROXY_ENABLED=False,
    NETRA_PUBLIC_API_AUTH_REQUIRED=True,
    NETRA_REALTIME_PROVIDER="sse",
    NETRA_SSE_MAX_SECONDS=0.04,
    NETRA_SSE_POLL_SECONDS=0.01,
    NETRA_SSE_HEARTBEAT_SECONDS=0.01,
    NETRA_RATE_LIMIT_SSE_USER_PER_MINUTE=20,
    NETRA_RATE_LIMIT_SSE_ORG_PER_MINUTE=20,
)
class BoundedSseContractTests(TestCase):
    def setUp(self):
        self.organization = netra_organization()
        self.user = get_user_model().objects.create_user(username="sse-user@example.test")
        UserProfile.objects.create(user=self.user, organization=self.organization, role="Investigator")
        token = str(RefreshToken.for_user(self.user).access_token)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        self.client = Client()
        self.case = Case.objects.create(
            id="CASE-SSE-001",
            organization=self.organization,
            display_reference="CASE-SSE-001",
            title="SSE case",
            investigator="Synthetic Investigator",
        )
        CaseMembership.objects.create(case=self.case, user=self.user, role="Investigator")

    def _consume(self, response) -> str:
        return b"".join(response.streaming_content).decode("utf-8")

    def test_stream_is_case_scoped_resumable_and_bounded(self):
        first = OperationalEvent.objects.create(
            organization=self.organization,
            case=self.case,
            event_type="analysis.progress",
            payload_json={"jobId": "job-1", "private": "not emitted"},
        )
        second = OperationalEvent.objects.create(
            organization=self.organization,
            case=self.case,
            event_type="analysis.completed",
            payload_json={"jobId": "job-1"},
        )
        response = self.client.get(
            f"/api/events/stream?caseRef={self.case.route_ref}",
            HTTP_LAST_EVENT_ID=str(first.pk),
            **self.headers,
        )
        self.assertEqual(response.status_code, 200)
        body = self._consume(response)
        self.assertIn("retry: 5000", body)
        self.assertIn(f"id: {second.pk}", body)
        self.assertNotIn(f"id: {first.pk}\n", body)
        self.assertNotIn("private", body)
        self.assertIn(": heartbeat", body)

    def test_missing_scope_and_invalid_cursor_are_rejected(self):
        self.assertEqual(self.client.get("/api/events/stream", **self.headers).status_code, 400)
        response = self.client.get(
            f"/api/events/stream?caseRef={self.case.route_ref}",
            HTTP_LAST_EVENT_ID="not-an-integer",
            **self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "invalid_event_cursor")
