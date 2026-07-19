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


@dataclass(frozen=True)
class StorageStat:
    size_bytes: int
    sha256: str


class LocalFilesystemStorageProvider:
    scheme = "local://"

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
        raise RuntimeError("Direct bucket operations require Supabase Storage.")

    def download_bucket_object(self, bucket: str, object_name: str, target_path: str | Path, *, max_bytes: int) -> StorageStat:
        raise RuntimeError("Direct bucket operations require Supabase Storage.")

    def read_bucket_object(self, bucket: str, object_name: str) -> bytes:
        raise RuntimeError("Direct bucket operations require Supabase Storage.")

    def delete_bucket_object(self, bucket: str, object_name: str) -> None:
        raise RuntimeError("Direct bucket operations require Supabase Storage.")


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
        return settings.SUPABASE_URL.rstrip("/")

    def _service_key(self) -> str:
        if not settings.SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError("Evidence storage is not configured: backend Supabase service-role key is missing.")
        return settings.SUPABASE_SERVICE_ROLE_KEY

    def _headers(self, content_type: str = "application/octet-stream") -> dict[str, str]:
        key = self._service_key()
        return {
            "Authorization": f"Bearer {key}",
            "apikey": key,
            "Content-Type": content_type,
        }

    def _auth_headers(self) -> dict[str, str]:
        key = self._service_key()
        return {
            "Authorization": f"Bearer {key}",
            "apikey": key,
        }

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

    def _object_url(self, bucket: str, object_name: str) -> str:
        quoted_bucket = urllib.parse.quote(bucket, safe="")
        quoted_object = urllib.parse.quote(object_name, safe="/")
        return f"{self._base_url()}/storage/v1/object/{quoted_bucket}/{quoted_object}"

    def _cache_path(self, bucket: str, object_name: str) -> Path:
        # Object names are external identifiers. Hash both components so a
        # malformed name cannot escape the private cache directory.
        bucket_key = hashlib.sha256(bucket.encode("utf-8")).hexdigest()[:16]
        object_key = hashlib.sha256(object_name.encode("utf-8")).hexdigest()
        return settings.NETRA_STORAGE_ROOT / ".supabase-cache" / bucket_key / object_key

    def _write_cache(self, bucket: str, object_name: str, content: bytes) -> Path:
        cache_path = self._cache_path(bucket, object_name)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False, dir=cache_path.parent) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, cache_path)
        return cache_path

    def _cache_uploaded_file(self, bucket: str, object_name: str, source: Path) -> None:
        cache_path = self._cache_path(bucket, object_name)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(delete=False, dir=cache_path.parent) as temporary:
            temporary_path = Path(temporary.name)
        try:
            shutil.copyfile(source, temporary_path)
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, cache_path)
        finally:
            temporary_path.unlink(missing_ok=True)

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
        cache_path = self._cache_path(bucket, object_name)
        if not cache_path.exists():
            self._write_cache(bucket, object_name, self._download_bytes_uncached(bucket, object_name))
        return cache_path

    def open_encrypted(self, storage_uri: str | Path, mode: str = "rb"):
        if str(storage_uri).startswith(self.scheme) and "r" in mode:
            return self.resolve(storage_uri).open(mode)
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
        self._cache_path(bucket, object_name).unlink(missing_ok=True)

    def verify_hash(self, storage_uri: str | Path, expected_sha256: str) -> bool:
        try:
            return self.stat(storage_uri).sha256 == expected_sha256
        except Exception:
            return False

    def copy_encrypted(self, source_uri: str | Path, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        if str(source_uri).startswith(self.scheme):
            shutil.copyfile(self.resolve(source_uri), target)
            return target
        return super().copy_encrypted(source_uri, destination)

    def upload_bucket_object(self, bucket: str, object_name: str, path: str | Path, *, upsert: bool = False) -> str:
        self._upload_file(bucket, object_name, Path(path), upsert=upsert)
        return f"{self.scheme}{bucket}/{object_name}"

    def download_bucket_object(self, bucket: str, object_name: str, target_path: str | Path, *, max_bytes: int) -> StorageStat:
        target = Path(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        url = self._object_url(bucket, object_name)
        request = urllib.request.Request(url, method="GET", headers=self._auth_headers())
        digest = hashlib.sha256()
        written = 0
        try:
            with urllib.request.urlopen(request, timeout=60) as response, target.open("wb") as handle:
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

    def read_bucket_object(self, bucket: str, object_name: str) -> bytes:
        return self._download_bytes(bucket, object_name)

    def delete_bucket_object(self, bucket: str, object_name: str) -> None:
        self.delete(f"{self.scheme}{bucket}/{object_name}")

    def _upload_file(self, bucket: str, object_name: str, path: Path, *, upsert: bool = True) -> None:
        url = self._object_url(bucket, object_name)
        request = urllib.request.Request(url, data=path.read_bytes(), method="POST", headers=self._headers())
        if upsert:
            request.add_header("x-upsert", "true")
        self._request(request, expected={200, 201})
        # Workers share NETRA_STORAGE_ROOT in production. Caching the encrypted
        # upload prevents validation and analysis from downloading it again.
        self._cache_uploaded_file(bucket, object_name, path)

    def _download_bytes(self, bucket: str, object_name: str) -> bytes:
        cache_path = self._cache_path(bucket, object_name)
        if cache_path.exists():
            return cache_path.read_bytes()
        content = self._download_bytes_uncached(bucket, object_name)
        self._write_cache(bucket, object_name, content)
        return content

    def _download_bytes_uncached(self, bucket: str, object_name: str) -> bytes:
        url = self._object_url(bucket, object_name)
        request = urllib.request.Request(url, method="GET", headers=self._headers())
        return self._request(request, expected={200})

    def health_check(self) -> dict:
        request = urllib.request.Request(f"{self._base_url()}/storage/v1/bucket", method="GET", headers=self._headers("application/json"))
        self._request(request, expected={200})
        if not settings.NETRA_STORAGE_DEEP_HEALTHCHECK:
            return {
                "status": "ok",
                "provider": "supabase-storage",
                "detail": "bucket access probe succeeded; deep object transfer probe disabled",
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
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read()
                if response.status not in expected:
                    raise RuntimeError(f"Supabase Storage returned HTTP {response.status}: {content[:200]!r}")
                return content
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
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
