import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from common.storage_provider import LocalFilesystemStorageProvider
from common.vault import decrypt_file, encrypt_file, open_decrypted_artifact, read_encrypted_or_plain
from common.vault_legacy import legacy_fernet
from common.vault_v2 import ArtifactCryptoContext, V2_VERSION, encrypt_artifact_v2, verify_evidence_v2


class ArtifactCryptoV21Tests(SimpleTestCase):
    def _settings(self, root: Path):
        return override_settings(
            NETRA_STORAGE_ROOT=root / "storage",
            NETRA_TEMP_ROOT=root / "temporary",
            NETRA_STORAGE_PROVIDER="local",
            NETRA_EVIDENCE_ENCRYPTION="on",
            NETRA_EVIDENCE_KEY="phase-three-test-key-with-high-entropy-material",
            NETRA_EVIDENCE_KEY_ID="test-key-003",
            NETRA_EVIDENCE_PREVIOUS_KEYS=[],
            NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES=1024 * 1024,
        )

    def _context(self) -> ArtifactCryptoContext:
        return ArtifactCryptoContext(
            artifact_id="ev-crypto-test",
            artifact_type="evidence",
            case_id="CASE-CRYPTO-TEST",
            original_filename="synthetic.pcap",
            target_bucket="netra-evidence",
        )

    def test_v21_round_trip_and_manifest_authentication(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "synthetic.pcap"
            plaintext = (b"netra-evidence" * 90000) + b"tail"
            source.write_bytes(plaintext)
            with self._settings(root):
                saved = encrypt_artifact_v2(source, self._context())
                output = root / "decrypted.pcap"
                decrypt_file(saved["stored_path"], output)
                verification = verify_evidence_v2(saved["stored_path"])
                provider = LocalFilesystemStorageProvider()
                bucket, object_name = provider.parse_object_uri(saved["stored_path"])
                manifest = json.loads(provider.read_bucket_object(bucket, object_name))

            self.assertEqual(output.read_bytes(), plaintext)
            self.assertEqual(manifest["version"], V2_VERSION)
            self.assertEqual(manifest["artifactType"], "evidence")
            self.assertIn("manifestHmacSha256", manifest)
            self.assertTrue(verification["verified"])

    def test_tampered_manifest_fails_before_plaintext_is_created(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "synthetic.pcap"
            source.write_bytes(b"forensic-evidence")
            with self._settings(root):
                saved = encrypt_artifact_v2(source, self._context())
                provider = LocalFilesystemStorageProvider()
                bucket, object_name = provider.parse_object_uri(saved["stored_path"])
                manifest_path = provider._local_object_path(bucket, object_name)
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["caseId"] = "CASE-TAMPERED"
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                output = root / "must-not-exist.pcap"
                with self.assertRaises(ValueError):
                    decrypt_file(saved["stored_path"], output)

            self.assertFalse(output.exists())

    def test_writer_does_not_use_whole_file_read_bytes(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "synthetic.pcap"
            source.write_bytes(b"x" * (1024 * 1024 + 17))
            original = Path.read_bytes

            def guarded_read_bytes(path: Path):
                if path == source:
                    raise AssertionError("Writer attempted a whole-file read")
                return original(path)

            with self._settings(root), patch.object(Path, "read_bytes", guarded_read_bytes):
                saved = encrypt_artifact_v2(source, self._context())

            self.assertEqual(saved["size_bytes"], source.stat().st_size)

    def test_legacy_encrypt_entrypoint_is_disabled(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "plain"
            source.write_bytes(b"evidence")
            with self.assertRaisesRegex(RuntimeError, "Legacy v1 encryption is disabled"):
                encrypt_file(source, root / "legacy.enc")

    def test_legacy_reader_never_requests_unbounded_ciphertext(self):
        class GuardedReader:
            def __init__(self, handle):
                self.handle = handle

            def read(self, size=-1):
                if size is None or size < 0:
                    raise AssertionError("Legacy reader requested an unbounded read")
                return self.handle.read(size)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.handle.close()

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            encoded = root / "legacy.enc"
            plaintext = b"legacy-evidence" * 100000
            with self._settings(root):
                encoded.write_bytes(legacy_fernet().encrypt(plaintext))

                def guarded_open(_source, _mode):
                    return GuardedReader(encoded.open("rb"))

                with patch("common.vault_legacy.storage_provider.open_encrypted", guarded_open):
                    output = root / "decrypted.bin"
                    decrypt_file(encoded, output)

            self.assertEqual(output.read_bytes(), plaintext)

    def test_in_memory_reader_rejects_artifact_over_limit(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "large.txt"
            source.write_bytes(b"x" * 33)
            with self._settings(root), override_settings(NETRA_MAX_INMEMORY_ARTIFACT_BYTES=32):
                with self.assertRaisesRegex(OverflowError, "NETRA_MAX_INMEMORY_ARTIFACT_BYTES"):
                    read_encrypted_or_plain(source)

    def test_cleanup_stream_removes_plaintext_on_close(self):
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "plain.bin"
            source.write_bytes(b"bounded-response")
            with self._settings(root), override_settings(NETRA_EVIDENCE_ENCRYPTION="off"):
                stream = open_decrypted_artifact(source)
                temporary_path = stream.path
                self.assertEqual(stream.read(), b"bounded-response")
                stream.close()
            self.assertFalse(temporary_path.exists())
