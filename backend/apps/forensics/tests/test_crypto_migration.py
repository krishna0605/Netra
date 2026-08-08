from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, override_settings

from common.crypto_migration import load_state, save_state, validate_state_path
from common.vault_legacy import legacy_fernet, stream_decrypt_legacy_path


class LegacyStreamingReaderTests(SimpleTestCase):
    @override_settings(NETRA_EVIDENCE_KEY="historical-secret", NETRA_EVIDENCE_PREVIOUS_KEYS=[])
    def test_streaming_reader_authenticates_and_decrypts_legacy_token(self):
        plaintext = (b"forensic-payload-" * 100_000) + b"end"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "legacy.enc"
            target = root / "plain.bin"
            source.write_bytes(legacy_fernet().encrypt(plaintext))
            stream_decrypt_legacy_path(source, target, temporary_root=root / "tmp")
            self.assertEqual(target.read_bytes(), plaintext)

    @override_settings(NETRA_EVIDENCE_KEY="wrong", NETRA_EVIDENCE_PREVIOUS_KEYS=[])
    def test_streaming_reader_removes_plaintext_when_authentication_fails(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "legacy.enc"
            target = root / "plain.bin"
            source.write_bytes(b"not-a-fernet-token")
            with self.assertRaises(ValueError):
                stream_decrypt_legacy_path(source, target, temporary_root=root / "tmp")
            self.assertFalse(target.exists())


class CryptoMigrationSafetyTests(SimpleTestCase):
    def test_plan_mode_does_not_touch_storage_or_state(self):
        with TemporaryDirectory() as directory, mock.patch(
            "apps.forensics.management.commands.migrate_evidence_crypto.enumerate_legacy_artifacts",
            return_value=[],
        ), mock.patch("common.storage_provider.storage_provider.copy_encrypted") as copy:
            state = Path(directory) / "state.json"
            call_command("migrate_evidence_crypto", "--plan", "--state", str(state))
            copy.assert_not_called()
            self.assertFalse(state.exists())

    def test_state_inside_repository_is_rejected(self):
        from django.conf import settings

        with self.assertRaisesRegex(ValueError, "outside the Git workspace"):
            validate_state_path(Path(settings.REPO_ROOT) / "crypto-state.json")

    def test_state_is_minimal_and_secret_free(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = {"version": 1, "artifacts": {"one": {"status": "planned"}}, "bytesRead": 0}
            save_state(path, state)
            self.assertEqual(load_state(path), state)
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("NETRA_EVIDENCE_KEY", serialized)
            self.assertEqual(json.loads(serialized)["bytesRead"], 0)
