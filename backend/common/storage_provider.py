from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from uuid import uuid4
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from common.hashing import sha256_file
from common.http_transport import bounded_read, normalized_https_origin, open_same_origin
from common.storage_cache import EncryptedObjectCache
from common.supabase_keys import elevated_api_headers


@dataclass(frozen=True)
class StorageStat:
    size_bytes: int
    sha256: str


class LocalFilesystemStorageProvider:
    scheme = "local://"

    def _object_root(self) -> Path:
        return settings.NETRA_STORAGE_ROOT / ".objects"

    def object_uri(self, bucket: str, object_name: str) -> str:
        return f"{self.scheme}.objects/{bucket}/{object_name}"

    def parse_object_uri(self, storage_uri: str | Path) -> tuple[str, str]:
        raw = str(storage_uri)
        prefix = f"{self.scheme}.objects/"
        if not raw.startswith(prefix):
            raise ValueError("Storage URI does not identify an immutable object.")
        bucket, separator, object_name = raw.removeprefix(prefix).partition("/")
        if not separator or not bucket or not object_name:
            raise ValueError("Immutable object URI is invalid.")
        return bucket, object_name

    def _local_object_path(self, bucket: str, object_name: str) -> Path:
        root = self._object_root().resolve()
        target = (root / bucket / Path(object_name)).resolve()
        target.relative_to(root)
        return target

    def uri_for(self, path: str | Path) -> str:
        target = Path(path).resolve()
        root = settings.NETRA_STORAGE_ROOT.resolve()
        try:
            relative = target.relative_to(root)
        except ValueError:
            return str(target)
        return f"{self.scheme}{relative.as_posix()}"

    def resolve(self, storage_uri: str | Path) -> Path:
        raw = str(storage_uri)
        if not raw.startswith(self.scheme):
            return Path(raw)
        relative = Path(raw.removeprefix(self.scheme))
        root = settings.NETRA_STORAGE_ROOT.resolve()
        target = (root / relative).resolve()
        target.relative_to(root)
        return target

    def open_encrypted(self, storage_uri: str | Path, mode: str = "rb"):
        return self.resolve(storage_uri).open(mode)

    def stat(self, storage_uri: str | Path) -> StorageStat:
        target = self.resolve(storage_uri)
        return StorageStat(size_bytes=target.stat().st_size, sha256=sha256_file(target))

    def delete(self, storage_uri: str | Path) -> None:
        self.resolve(storage_uri).unlink(missing_ok=True)

    def verify_hash(self, storage_uri: str | Path, expected_sha256: str) -> bool:
        target = self.resolve(storage_uri)
        return target.exists() and sha256_file(target) == expected_sha256

    def materialize_plaintext(self, storage_uri: str | Path, target_path: str | Path) -> Path:
        from common.vault import decrypt_file

        target = Path(target_path)
        decrypt_file(storage_uri, target)
        return target

    def copy_encrypted(self, source_uri: str | Path, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.resolve(source_uri), target)
        return target

    def health_check(self) -> dict:
        return {"status": "ok", "provider": "local-filesystem"}

    def upload_bucket_object(self, bucket: str, object_name: str, path: str | Path, *, upsert: bool = False) -> str:
        source = Path(path)
        target = self._local_object_path(bucket, object_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not upsert:
            raise FileExistsError(f"Immutable object already exists: {bucket}/{object_name}")
        with tempfile.NamedTemporaryFile(delete=False, dir=target.parent) as temporary:
            temporary_path = Path(temporary.name)
        try:
            shutil.copyfile(source, temporary_path)
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, target)
        finally:
            temporary_path.unlink(missing_ok=True)
        return self.object_uri(bucket, object_name)

    def download_bucket_object(self, bucket: str, object_name: str, target_path: str | Path, *, max_bytes: int) -> StorageStat:
        raise RuntimeError("Direct bucket operations require Supabase Storage.")

    def read_bucket_object(self, bucket: str, object_name: str, *, expected_sha256: str = "", expected_size: int | None = None) -> bytes:
        return self._local_object_path(bucket, object_name).read_bytes()

    def delete_bucket_object(self, bucket: str, object_name: str) -> None:
        self._local_object_path(bucket, object_name).unlink(missing_ok=True)


class SupabaseStorageProvider(LocalFilesystemStorageProvider):
    scheme = "supabase://"

    FOLDER_BUCKETS = {
        "pcaps": "SUPABASE_STORAGE_BUCKET_EVIDENCE",
        "capture_chunks": "SUPABASE_STORAGE_BUCKET_CAPTURE_CHUNKS",
        "analysis_chunks": "SUPABASE_STORAGE_BUCKET_ANALYSIS_CHUNKS",
        "zeek": "SUPABASE_STORAGE_BUCKET_ZEEK_LOGS",
        "logs": "SUPABASE_STORAGE_BUCKET_ZEEK_LOGS",
        "reports": "SUPABASE_STORAGE_BUCKET_REPORTS",
        "exports": "SUPABASE_STORAGE_BUCKET_EXPORTS",
        "filtered_pcaps": "SUPABASE_STORAGE_BUCKET_EXPORTS",
    }

    def _base_url(self) -> str:
        if not settings.SUPABASE_URL:
            raise RuntimeError("SUPABASE_URL is required when NETRA_STORAGE_PROVIDER=supabase.")
        return normalized_https_origin(settings.SUPABASE_URL)

    def _service_key(self) -> str:
        if not settings.SUPABASE_SECRET_KEY:
            raise RuntimeError("Evidence storage is not configured: backend Supabase service-role key is missing.")
        return settings.SUPABASE_SECRET_KEY

    def _headers(self, content_type: str = "application/octet-stream") -> dict[str, str]:
        return elevated_api_headers(self._service_key(), content_type=content_type)

    def _auth_headers(self) -> dict[str, str]:
        return elevated_api_headers(self._service_key())

    def _bucket_for_relative(self, relative: Path) -> str:
        root_folder = relative.parts[0] if relative.parts else "pcaps"
        setting_name = self.FOLDER_BUCKETS.get(root_folder, "SUPABASE_STORAGE_BUCKET_EVIDENCE")
        return getattr(settings, setting_name)

    def _parse_uri(self, storage_uri: str | Path) -> tuple[str, str]:
        raw = str(storage_uri)
        if not raw.startswith(self.scheme):
            return self._bucket_for_relative(Path(raw).resolve().relative_to(settings.NETRA_STORAGE_ROOT.resolve())), Path(raw).name
        remainder = raw.removeprefix(self.scheme)
        bucket, _, object_name = remainder.partition("/")
        if not bucket or not object_name:
            raise ValueError(f"Invalid Supabase storage URI: {raw}")
        return bucket, object_name

    def object_uri(self, bucket: str, object_name: str) -> str:
        return f"{self.scheme}{bucket}/{object_name}"

    def parse_object_uri(self, storage_uri: str | Path) -> tuple[str, str]:
        return self._parse_uri(storage_uri)

    def _object_url(self, bucket: str, object_name: str) -> str:
        quoted_bucket = urllib.parse.quote(bucket, safe="")
        quoted_object = urllib.parse.quote(object_name, safe="/")
        return f"{self._base_url()}/storage/v1/object/{quoted_bucket}/{quoted_object}"

    def _cache_path(self, bucket: str, object_name: str) -> Path:
        cache = EncryptedObjectCache()
        return cache.objects / cache.key(self.object_uri(bucket, object_name))

    def _cache_uploaded_file(self, bucket: str, object_name: str, source: Path) -> None:
        EncryptedObjectCache().store_uploaded(self.object_uri(bucket, object_name), source)

    def uri_for(self, path: str | Path) -> str:
        target = Path(path).resolve()
        root = settings.NETRA_STORAGE_ROOT.resolve()
        relative = target.relative_to(root)
        bucket = self._bucket_for_relative(relative)
        object_name = relative.as_posix()
        self._upload_file(bucket, object_name, target, upsert=True)
        return f"{self.scheme}{bucket}/{object_name}"

    def resolve(self, storage_uri: str | Path) -> Path:
        raw = str(storage_uri)
        if not raw.startswith(self.scheme):
            return super().resolve(storage_uri)
        bucket, object_name = self._parse_uri(raw)
        return self._materialize_cached(bucket, object_name)

    def _materialize_cached(
        self, bucket: str, object_name: str, *, expected_sha256: str = "", expected_size: int | None = None,
    ) -> Path:
        return EncryptedObjectCache().materialize(
            self.object_uri(bucket, object_name), expected_sha256=expected_sha256,
            expected_size=expected_size,
            downloader=lambda target: self._download_to_path_uncached(bucket, object_name, target),
        )

    def open_encrypted(self, storage_uri: str | Path, mode: str = "rb"):
        if str(storage_uri).startswith(self.scheme) and "r" in mode:
            bucket, object_name = self._parse_uri(storage_uri)
            return EncryptedObjectCache().open_cached(
                self.object_uri(bucket, object_name),
                downloader=lambda target: self._download_to_path_uncached(bucket, object_name, target),
            )
        return super().open_encrypted(storage_uri, mode)

    def stat(self, storage_uri: str | Path) -> StorageStat:
        if not str(storage_uri).startswith(self.scheme):
            return super().stat(storage_uri)
        cached = self.resolve(storage_uri)
        return StorageStat(size_bytes=cached.stat().st_size, sha256=sha256_file(cached))

    def delete(self, storage_uri: str | Path) -> None:
        if not str(storage_uri).startswith(self.scheme):
            return super().delete(storage_uri)
        bucket, object_name = self._parse_uri(storage_uri)
        url = self._object_url(bucket, object_name)
        request = urllib.request.Request(url, method="DELETE", headers=self._auth_headers())
        self._request(request, expected={200, 204, 404})
        EncryptedObjectCache().remove_uri(self.object_uri(bucket, object_name))

    def verify_hash(self, storage_uri: str | Path, expected_sha256: str) -> bool:
        try:
            return self.stat(storage_uri).sha256 == expected_sha256
        except Exception:
            return False

    def copy_encrypted(self, source_uri: str | Path, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        if str(source_uri).startswith(self.scheme):
            with self.open_encrypted(source_uri, "rb") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            return target
        return super().copy_encrypted(source_uri, destination)

    def upload_bucket_object(self, bucket: str, object_name: str, path: str | Path, *, upsert: bool = False) -> str:
        self._upload_file(bucket, object_name, Path(path), upsert=upsert)
        return self.object_uri(bucket, object_name)

    def download_bucket_object(self, bucket: str, object_name: str, target_path: str | Path, *, max_bytes: int) -> StorageStat:
        target = Path(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        url = self._object_url(bucket, object_name)
        request = urllib.request.Request(url, method="GET", headers=self._auth_headers())
        digest = hashlib.sha256()
        written = 0
        try:
            with open_same_origin(request, origin=self._base_url(), timeout=60) as response, target.open("wb") as handle:
                os.chmod(target, 0o600)
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise OverflowError("Quarantine object exceeds the authorized upload size.")
                    digest.update(chunk)
                    handle.write(chunk)
        except Exception:
            target.unlink(missing_ok=True)
            raise
        return StorageStat(size_bytes=written, sha256=digest.hexdigest())

    def read_bucket_object(self, bucket: str, object_name: str, *, expected_sha256: str = "", expected_size: int | None = None) -> bytes:
        return self._materialize_cached(
            bucket, object_name, expected_sha256=expected_sha256, expected_size=expected_size,
        ).read_bytes()

    def delete_bucket_object(self, bucket: str, object_name: str) -> None:
        self.delete(f"{self.scheme}{bucket}/{object_name}")

    def _upload_file(self, bucket: str, object_name: str, path: Path, *, upsert: bool = True) -> None:
        url = self._object_url(bucket, object_name)
        headers = self._headers()
        headers["Content-Length"] = str(path.stat().st_size)
        with path.open("rb") as body:
            request = urllib.request.Request(url, data=body, method="POST", headers=headers)
            if upsert:
                request.add_header("x-upsert", "true")
            self._request(request, expected={200, 201})
        # Workers share NETRA_STORAGE_ROOT in production. Caching the encrypted
        # upload prevents validation and analysis from downloading it again.
        self._cache_uploaded_file(bucket, object_name, path)

    def _download_bytes(self, bucket: str, object_name: str) -> bytes:
        return self.read_bucket_object(bucket, object_name)

    def _download_to_path_uncached(self, bucket: str, object_name: str, target: Path) -> None:
        url = self._object_url(bucket, object_name)
        request = urllib.request.Request(url, method="GET", headers=self._headers())
        with open_same_origin(request, origin=self._base_url(), timeout=60) as response, target.open("wb") as output:
            if response.status != 200:
                raise RuntimeError(f"Supabase Storage returned HTTP {response.status}.")
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                output.write(block)

    def health_check(self) -> dict:
        request = urllib.request.Request(f"{self._base_url()}/storage/v1/bucket", method="GET", headers=self._headers("application/json"))
        self._request(request, expected={200})
        if not settings.NETRA_STORAGE_DEEP_HEALTHCHECK:
            return {
                "status": "ok",
                "provider": "supabase-storage",
                "detail": "bucket access probe succeeded; deep object transfer probe disabled",
                "cache": EncryptedObjectCache().status().as_dict(),
            }
        bucket = settings.SUPABASE_STORAGE_BUCKET_EVIDENCE
        probe_name = f"health/netra-storage-probe-{uuid4().hex}.txt"
        probe = tempfile.NamedTemporaryFile(delete=False)
        try:
            probe.write(b"netra-storage-health")
            probe.close()
            self._upload_file(bucket, probe_name, Path(probe.name), upsert=True)
            content = self._download_bytes(bucket, probe_name)
            if content != b"netra-storage-health":
                raise RuntimeError("Supabase Storage health probe returned unexpected content.")
            self.delete(f"{self.scheme}{bucket}/{probe_name}")
        finally:
            Path(probe.name).unlink(missing_ok=True)
        return {"status": "ok", "provider": "supabase-storage", "detail": "bucket list and encrypted artifact probe succeeded"}

    def _request(self, request: urllib.request.Request, expected: set[int]) -> bytes:
        try:
            with open_same_origin(request, origin=self._base_url(), timeout=30) as response:
                content = bounded_read(response, 131072)
                if response.status not in expected:
                    raise RuntimeError(f"Supabase Storage returned HTTP {response.status}: {content[:200]!r}")
                return content
        except urllib.error.HTTPError as exc:
            detail = bounded_read(exc, 131072).decode("utf-8", errors="replace")
            if exc.code in expected:
                return detail.encode("utf-8")
            if "signature verification failed" in detail.lower() or exc.code in {401, 403}:
                raise RuntimeError("Evidence storage is not configured: backend Supabase service-role key is invalid or expired.") from exc
            raise RuntimeError(f"Supabase Storage HTTP {exc.code}: {detail}") from exc


def get_storage_provider():
    if getattr(settings, "NETRA_STORAGE_PROVIDER", "local") == "supabase":
        return SupabaseStorageProvider()
    return LocalFilesystemStorageProvider()


storage_provider = get_storage_provider()


def resolve_storage_path(storage_uri: str | Path) -> Path:
    return storage_provider.resolve(storage_uri)


def storage_uri(path: str | Path) -> str:
    return storage_provider.uri_for(path)
