import urllib.request
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from common.http_transport import bounded_read, normalized_https_origin, open_same_origin


class HardenedHttpTransportTests(SimpleTestCase):
    def test_origin_requires_plain_https_origin(self):
        self.assertEqual(normalized_https_origin("https://example.supabase.co/"), "https://example.supabase.co")
        for unsafe in (
            "http://example.supabase.co",
            "https://user@example.supabase.co",
            "https://example.supabase.co/storage/v1",
            "https://example.supabase.co?redirect=other",
            "file:///tmp/object",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(RuntimeError):
                normalized_https_origin(unsafe)

    def test_request_must_match_configured_origin_and_ignores_proxies(self):
        request = urllib.request.Request("https://example.supabase.co/storage/v1/bucket")
        opener = MagicMock()
        with patch("common.http_transport.urllib.request.build_opener", return_value=opener) as build:
            open_same_origin(request, origin="https://example.supabase.co", timeout=3)
        build.assert_called_once()
        opener.open.assert_called_once_with(request, timeout=3)

        with self.assertRaises(RuntimeError):
            open_same_origin(request, origin="https://other.supabase.co", timeout=3)

    def test_remote_responses_are_bounded(self):
        response = MagicMock()
        response.read.return_value = b"12345"
        self.assertEqual(bounded_read(response, 5), b"12345")
        response.read.return_value = b"123456"
        with self.assertRaises(RuntimeError):
            bounded_read(response, 5)
