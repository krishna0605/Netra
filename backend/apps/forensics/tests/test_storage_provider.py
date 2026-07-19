import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from common.storage_provider import SupabaseStorageProvider


class SupabaseStorageEgressTests(SimpleTestCase):
    def test_health_check_avoids_object_transfer_by_default(self):
        provider = SupabaseStorageProvider()

        with override_settings(
            SUPABASE_URL="https://exampleproject.supabase.co",
            SUPABASE_SERVICE_ROLE_KEY="test-service-key",
            NETRA_STORAGE_DEEP_HEALTHCHECK=False,
        ), patch.object(provider, "_request", return_value=b"[]") as request:
            result = provider.health_check()

        self.assertEqual(result["status"], "ok")
        self.assertIn("deep object transfer probe disabled", result["detail"])
        self.assertEqual(request.call_count, 1)
        self.assertTrue(request.call_args.args[0].full_url.endswith("/storage/v1/bucket"))

    def test_uploaded_object_is_reused_from_encrypted_cache(self):
        provider = SupabaseStorageProvider()
        content = b"encrypted-pcap-content"

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "upload.enc"
            source.write_bytes(content)
            with override_settings(
                NETRA_STORAGE_ROOT=root / "storage",
                SUPABASE_URL="https://exampleproject.supabase.co",
                SUPABASE_SERVICE_ROLE_KEY="test-service-key",
            ), patch.object(provider, "_request", return_value=b"{}") as request:
                uri = provider.upload_bucket_object("netra-evidence", "immutable/evidence.enc", source)
                stat = provider.stat(uri)
                copied = provider.copy_encrypted(uri, root / "copy.enc")
                opened = provider.open_encrypted(uri, "rb")
                try:
                    opened_content = opened.read()
                finally:
                    opened.close()

                copied_content = copied.read_bytes()

        self.assertEqual(request.call_count, 1)
        self.assertEqual(stat.size_bytes, len(content))
        self.assertEqual(stat.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(copied_content, content)
        self.assertEqual(opened_content, content)

    def test_cached_object_name_cannot_escape_storage_root(self):
        provider = SupabaseStorageProvider()

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with override_settings(NETRA_STORAGE_ROOT=root):
                cache_path = provider._cache_path("../bucket", "../../secret")

        self.assertTrue(cache_path.is_relative_to(root / ".supabase-cache"))
