import json
import tempfile
import unittest
from pathlib import Path

from infra.scripts.migrate_supabase_storage import MigrationError, Meter, load_manifest, save_manifest


class StorageMigrationSafetyTests(unittest.TestCase):
    def test_meter_stops_immediately_above_budget(self):
        meter = Meter(10)
        meter.add(10)

        with self.assertRaises(MigrationError):
            meter.add(1)

        self.assertEqual(meter.downloaded_bytes, 11)

    def test_manifest_cannot_be_reused_for_different_projects(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "manifest.json"
            save_manifest(path, load_manifest(path, "https://source.supabase.co", "https://target.supabase.co", 100))

            with self.assertRaises(MigrationError):
                load_manifest(path, "https://other.supabase.co", "https://target.supabase.co", 100)

    def test_manifest_write_is_valid_json(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "manifest.json"
            manifest = load_manifest(path, "https://source.supabase.co", "https://target.supabase.co", 100)
            manifest["meteredDownloadBytes"] = 42
            save_manifest(path, manifest)

            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["meteredDownloadBytes"], 42)


if __name__ == "__main__":
    unittest.main()
