from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable

from django.conf import settings

from common.file_lock import FileLock
from common.hashing import sha256_file


@dataclass(frozen=True)
class CacheStatus:
    enabled: bool
    root: str
    max_bytes: int
    used_bytes: int
    minimum_free_bytes: int
    entry_count: int
    stale_temporary_count: int

    def as_dict(self) -> dict:
        return {
            "enabled": self.enabled, "root": self.root, "maxBytes": self.max_bytes,
            "usedBytes": self.used_bytes, "minimumFreeBytes": self.minimum_free_bytes,
            "entryCount": self.entry_count, "staleTemporaryCount": self.stale_temporary_count,
            "persistentVolumeContract": "/app/storage", "deepStorageCheckEnabled": False,
        }


class _LeasedFile:
    def __init__(self, handle, lease: FileLock):
        self._handle = handle
        self._lease = lease

    def __getattr__(self, name):
        return getattr(self._handle, name)

    def close(self):
        try:
            return self._handle.close()
        finally:
            self._lease.release()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class EncryptedObjectCache:
    def __init__(self, root: Path | None = None):
        self.root = (root or (settings.NETRA_STORAGE_ROOT / ".supabase-cache")).resolve()
        self.objects = self.root / "objects"
        self.metadata = self.root / "metadata"
        self.locks = self.root / "locks"
        self.temporary = self.root / "temporary"

    @property
    def enabled(self) -> bool:
        return bool(settings.NETRA_STORAGE_CACHE_ENABLED)

    def _ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for directory in (self.objects, self.metadata, self.locks, self.temporary):
            directory.mkdir(parents=True, exist_ok=True)
        sentinel = self.root / "volume-sentinel.json"
        with FileLock(self.locks / "initialization.lock", timeout=settings.NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS):
            if not sentinel.exists():
                self._atomic_json(sentinel, {"version": 1, "root": str(settings.NETRA_STORAGE_ROOT)})

    @staticmethod
    def key(uri: str, expected_sha256: str = "") -> str:
        return hashlib.sha256(f"{uri}\0{expected_sha256}".encode("utf-8")).hexdigest()

    def _paths(self, key: str) -> tuple[Path, Path]:
        return self.objects / key, self.metadata / f"{key}.json"

    def _atomic_json(self, target: Path, value: dict) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=target.parent) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)

    def _read_meta(self, path: Path) -> dict | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, ValueError):
            return None

    def _valid(self, uri: str, expected_sha256: str, object_path: Path, meta_path: Path) -> bool:
        meta = self._read_meta(meta_path)
        if not object_path.is_file() or not meta or meta.get("uri") != uri:
            return False
        if expected_sha256 and meta.get("sha256") != expected_sha256:
            return False
        if object_path.stat().st_size != int(meta.get("sizeBytes", -1)):
            return False
        return sha256_file(object_path) == meta.get("sha256")

    def _existing_for_uri(self, uri: str, expected_sha256: str) -> Path | None:
        for meta_path in self.metadata.glob("*.json"):
            meta = self._read_meta(meta_path)
            if not meta or meta.get("uri") != uri:
                continue
            if expected_sha256 and meta.get("sha256") != expected_sha256:
                continue
            object_path, _ = self._paths(meta_path.stem)
            lease = FileLock(self.locks / f"{meta_path.stem}.lock", timeout=settings.NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS)
            if not lease.acquire():
                continue
            try:
                if self._valid(uri, expected_sha256, object_path, meta_path):
                    self._touch(meta_path, meta)
                    return object_path
            finally:
                lease.release()
        return None

    def _touch(self, meta_path: Path, meta: dict) -> None:
        now = time.time()
        if now - float(meta.get("lastAccessed", 0)) >= settings.NETRA_STORAGE_CACHE_TOUCH_INTERVAL_SECONDS:
            meta["lastAccessed"] = now
            self._atomic_json(meta_path, meta)

    def _used(self) -> int:
        return sum(path.stat().st_size for path in self.objects.glob("*") if path.is_file())

    def _free(self) -> int:
        return shutil.disk_usage(self.root).free

    def _remove_entry(self, key: str) -> None:
        object_path, meta_path = self._paths(key)
        object_path.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)

    def remove_uri(self, uri: str) -> None:
        self._ensure()
        for meta_path in self.metadata.glob("*.json"):
            meta = self._read_meta(meta_path)
            if meta and meta.get("uri") == uri:
                self._remove_entry(meta_path.stem)

    def _reserve(self, incoming: int, *, exclude: str = "") -> None:
        if incoming > settings.NETRA_STORAGE_CACHE_MAX_BYTES:
            raise OSError("Encrypted object exceeds the complete cache capacity.")
        while (
            self._used() + incoming > settings.NETRA_STORAGE_CACHE_MAX_BYTES
            or self._free() - incoming < settings.NETRA_STORAGE_CACHE_MIN_FREE_BYTES
        ):
            candidates = []
            for meta_path in self.metadata.glob("*.json"):
                meta = self._read_meta(meta_path)
                if meta and meta_path.stem != exclude:
                    candidates.append((float(meta.get("lastAccessed", 0)), meta_path.stem))
            evicted = False
            for _, key in sorted(candidates):
                lease = FileLock(self.locks / f"{key}.lock", timeout=0)
                if lease.acquire():
                    try:
                        self._remove_entry(key)
                        evicted = True
                        break
                    finally:
                        lease.release()
            if not evicted:
                raise OSError("Encrypted Storage cache cannot preserve its capacity and free-space reserve.")

    def materialize(
        self, uri: str, *, expected_sha256: str = "", expected_size: int | None = None,
        downloader: Callable[[Path], None],
    ) -> Path:
        if not self.enabled:
            raise RuntimeError("Encrypted Storage cache is disabled; uncached fallback is prohibited.")
        self._ensure()
        existing = self._existing_for_uri(uri, expected_sha256)
        if existing is not None:
            return existing
        key = self.key(uri, expected_sha256)
        object_path, meta_path = self._paths(key)
        with FileLock(self.locks / f"{key}.lock", timeout=settings.NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS):
            if self._valid(uri, expected_sha256, object_path, meta_path):
                meta = self._read_meta(meta_path) or {}
                self._touch(meta_path, meta)
                return object_path
            self._remove_entry(key)
            with FileLock(self.locks / "global.lock", timeout=settings.NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS):
                if expected_size is not None:
                    self._reserve(expected_size, exclude=key)
                with NamedTemporaryFile(delete=False, dir=self.temporary, suffix=".partial") as handle:
                    temporary = Path(handle.name)
                os.chmod(temporary, 0o600)
                try:
                    downloader(temporary)
                    actual_size = temporary.stat().st_size
                    digest = sha256_file(temporary)
                    if expected_size is not None and actual_size != expected_size:
                        raise ValueError("Downloaded encrypted object size does not match its manifest.")
                    if expected_sha256 and digest != expected_sha256:
                        raise ValueError("Downloaded encrypted object digest does not match its manifest.")
                    self._reserve(actual_size, exclude=key)
                    os.replace(temporary, object_path)
                    self._atomic_json(meta_path, {
                        "uri": uri, "sha256": digest, "sizeBytes": actual_size,
                        "lastAccessed": time.time(), "createdAt": time.time(),
                    })
                finally:
                    temporary.unlink(missing_ok=True)
        return object_path

    def store_uploaded(self, uri: str, source: Path, *, expected_sha256: str = "") -> Path:
        digest = expected_sha256 or sha256_file(source)
        return self.materialize(
            uri, expected_sha256=digest, expected_size=source.stat().st_size,
            downloader=lambda destination: shutil.copyfile(source, destination),
        )

    def open_cached(
        self, uri: str, *, downloader: Callable[[Path], None], expected_sha256: str = "",
        expected_size: int | None = None,
    ):
        path = self.materialize(
            uri, expected_sha256=expected_sha256, expected_size=expected_size, downloader=downloader,
        )
        lease = FileLock(self.locks / f"{path.name}.lock", timeout=settings.NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS)
        if not lease.acquire():
            raise TimeoutError("Timed out acquiring an encrypted cache entry lease.")
        try:
            return _LeasedFile(path.open("rb"), lease)
        except Exception:
            lease.release()
            raise

    def prune(self, *, startup: bool = False) -> CacheStatus:
        self._ensure()
        cutoff = time.time() - settings.NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS
        for temporary in self.temporary.glob("*.partial"):
            if temporary.stat().st_mtime < cutoff:
                temporary.unlink(missing_ok=True)
        if not startup:
            with FileLock(self.locks / "global.lock", timeout=settings.NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS):
                self._reserve(0)
        return self.status()

    def status(self) -> CacheStatus:
        self._ensure()
        stale_cutoff = time.time() - settings.NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS
        stale = sum(1 for path in self.temporary.glob("*.partial") if path.stat().st_mtime < stale_cutoff)
        objects = [path for path in self.objects.glob("*") if path.is_file()]
        return CacheStatus(
            enabled=self.enabled, root=str(self.root), max_bytes=settings.NETRA_STORAGE_CACHE_MAX_BYTES,
            used_bytes=sum(path.stat().st_size for path in objects),
            minimum_free_bytes=settings.NETRA_STORAGE_CACHE_MIN_FREE_BYTES,
            entry_count=len(objects), stale_temporary_count=stale,
        )


storage_cache = EncryptedObjectCache()
