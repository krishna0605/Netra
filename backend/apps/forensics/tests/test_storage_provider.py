import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from common.storage_provider import SupabaseStorageProvider
from common.storage_cache import EncryptedObjectCache, StorageCacheUnavailable


class SupabaseStorageEgressTests(SimpleTestCase):
    def test_health_check_avoids_object_transfer_by_default(self):
        provider = SupabaseStorageProvider()

        with override_settings(
            SUPABASE_URL="https://exampleproject.supabase.co",
            SUPABASE_SECRET_KEY="test-secret-key",
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
                SUPABASE_SECRET_KEY="test-secret-key",
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


class BoundedEncryptedCacheTests(SimpleTestCase):
    def _settings(self, root: Path, **values):
        defaults = {
            "NETRA_STORAGE_ROOT": root, "NETRA_STORAGE_CACHE_ENABLED": True,
            "NETRA_STORAGE_CACHE_MAX_BYTES": 64, "NETRA_STORAGE_CACHE_MIN_FREE_BYTES": 1,
            "NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS": 1,
            "NETRA_STORAGE_CACHE_TOUCH_INTERVAL_SECONDS": 0,
            "NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS": 5,
        }
        defaults.update(values)
        return override_settings(**defaults)

    def test_second_verified_access_causes_zero_downloads(self):
        with TemporaryDirectory() as directory, self._settings(Path(directory)):
            cache = EncryptedObjectCache()
            content = b"encrypted-content"
            digest = hashlib.sha256(content).hexdigest()
            calls = []

            def download(target):
                calls.append(target)
                target.write_bytes(content)

            first = cache.materialize("supabase://bucket/object", expected_sha256=digest, expected_size=len(content), downloader=download)
            second = cache.materialize("supabase://bucket/object", expected_sha256=digest, expected_size=len(content), downloader=download)
            self.assertEqual(first, second)
            self.assertEqual(len(calls), 1)

    def test_parallel_cache_miss_performs_one_download(self):
        with TemporaryDirectory() as directory, self._settings(Path(directory)):
            cache = EncryptedObjectCache()
            content = b"parallel-encrypted"
            digest = hashlib.sha256(content).hexdigest()
            calls = []

            def download(target):
                calls.append(1)
                time.sleep(0.05)
                target.write_bytes(content)

            def access(_index):
                return cache.materialize("supabase://bucket/parallel", expected_sha256=digest, expected_size=len(content), downloader=download)

            with ThreadPoolExecutor(max_workers=5) as pool:
                paths = list(pool.map(access, range(5)))
            self.assertEqual(len(set(paths)), 1)
            self.assertEqual(len(calls), 1)

    def test_corruption_is_replaced_once(self):
        with TemporaryDirectory() as directory, self._settings(Path(directory)):
            cache = EncryptedObjectCache()
            content = b"authenticated-ciphertext"
            digest = hashlib.sha256(content).hexdigest()
            calls = []

            def download(target):
                calls.append(1)
                target.write_bytes(content)

            path = cache.materialize("supabase://bucket/corrupt", expected_sha256=digest, expected_size=len(content), downloader=download)
            path.write_bytes(b"tampered")
            restored = cache.materialize("supabase://bucket/corrupt", expected_sha256=digest, expected_size=len(content), downloader=download)
            self.assertEqual(restored.read_bytes(), content)
            self.assertEqual(len(calls), 2)

    def test_capacity_evicts_least_recently_used_entry(self):
        with TemporaryDirectory() as directory, self._settings(Path(directory), NETRA_STORAGE_CACHE_MAX_BYTES=10):
            cache = EncryptedObjectCache()
            for name, content in (("old", b"123456"), ("new", b"abcdef")):
                digest = hashlib.sha256(content).hexdigest()
                cache.materialize(
                    f"supabase://bucket/{name}", expected_sha256=digest, expected_size=len(content),
                    downloader=lambda target, value=content: target.write_bytes(value),
                )
                time.sleep(0.01)
            status = cache.status()
            self.assertLessEqual(status.used_bytes, 10)
            self.assertEqual(status.entry_count, 1)

    def test_in_use_entry_is_not_evicted(self):
        with TemporaryDirectory() as directory, self._settings(Path(directory), NETRA_STORAGE_CACHE_MAX_BYTES=10):
            cache = EncryptedObjectCache()
            first = b"123456"
            first_hash = hashlib.sha256(first).hexdigest()
            cache.materialize(
                "supabase://bucket/in-use", expected_sha256=first_hash, expected_size=len(first),
                downloader=lambda target: target.write_bytes(first),
            )
            lease = cache.open_cached(
                "supabase://bucket/in-use", expected_sha256=first_hash, expected_size=len(first),
                downloader=lambda _target: self.fail("leased cache hit must not download"),
            )
            try:
                second = b"abcdef"
                with self.assertRaisesRegex(StorageCacheUnavailable, "temporarily unavailable"):
                    cache.materialize(
                        "supabase://bucket/new", expected_sha256=hashlib.sha256(second).hexdigest(),
                        expected_size=len(second), downloader=lambda target: target.write_bytes(second),
                    )
            finally:
                lease.close()

    def test_startup_removes_only_stale_partial_files(self):
        with TemporaryDirectory() as directory, self._settings(Path(directory)):
            cache = EncryptedObjectCache()
            cache._ensure()
            stale = cache.temporary / "stale.partial"
            fresh = cache.temporary / "fresh.partial"
            stale.write_bytes(b"old")
            fresh.write_bytes(b"new")
            os.utime(stale, (time.time() - 10, time.time() - 10))
            cache.prune(startup=True)
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists())
