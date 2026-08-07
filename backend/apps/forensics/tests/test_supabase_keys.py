from django.test import SimpleTestCase

from common.supabase_keys import elevated_api_headers


class SupabaseKeyHeaderTests(SimpleTestCase):
    def test_modern_secret_key_is_not_sent_as_a_bearer_token(self):
        headers = elevated_api_headers("sb_secret_example", content_type="application/json")

        self.assertEqual(headers["apikey"], "sb_secret_example")
        self.assertNotIn("Authorization", headers)
        self.assertEqual(headers["Content-Type"], "application/json")

    def test_legacy_service_role_key_remains_a_bearer_token(self):
        headers = elevated_api_headers("legacy-jwt")

        self.assertEqual(headers["apikey"], "legacy-jwt")
        self.assertEqual(headers["Authorization"], "Bearer legacy-jwt")
