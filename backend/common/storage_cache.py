from __future__ import annotations

import errno
import hashlib
import json
import logging
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


logger = logging.getLogger(__name__)

CACHE_ROOT_NOT_WRITABLE = "cache-root-not-writable"
CACHE_CAPACITY_EXHAUSTED = "cache-capacity-exhausted"
CACHE_LOCK_TIMEOUT = "cache-lock-timeout"
OBJECT_SOURCE_UNAVAILABLE = "object-source-unavailable"
CACHE_IO_ERROR = "cache-io-error"
CACHE_DISABLED = "cache-disabled"

_clamp_warnings: set[tuple[str, int, int]] = set()


class CacheCapacityError(OSError):
    """The bounded cache cannot satisfy its capacity and free-space reserve."""


class StorageCacheUnavailable(RuntimeError):
    """The encrypted cache cannot currently satisfy its safety contract."""

    def __init__(self, message: str, *, code: str = CACHE_IO_ERROR):
        super().__init__(message)
        self.code = code


def classify_cache_failure(exc: BaseException) -> str:
    """Map a fail-closed cache failure onto a stable, non-sensitive code.

    The code is a fixed enum so it is safe to store on the job record and show
    to an investigator. The underlying exception text can name filesystem paths
    and bucket layout, so it is only ever written to the service log.
    """
    if isinstance(exc, CacheCapacityError):
        return CACHE_CAPACITY_EXHAUSTED
    # TimeoutError and PermissionError are both OSError subclasses, so they are
    # matched before the generic OSError branch below.
    if isinstance(exc, TimeoutError):
        return CACHE_LOCK_TIMEOUT
    if isinstance(exc, PermissionError):
        return CACHE_ROOT_NOT_WRITABLE
    if isinstance(exc, OSError):
        if exc.errno in {errno.EACCES, errno.EPERM, errno.EROFS}:
            return CACHE_ROOT_NOT_WRITABLE
        if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", -1)}:
            return CACHE_CAPACITY_EXHAUSTED
        return CACHE_IO_ERROR
    if isinstance(exc, RuntimeError):
        # Storage-provider transfers surface as RuntimeError from
        # common.storage_provider; those describe the source object, not the cache.
        return OBJECT_SOURCE_UNAVAILABLE
    return CACHE_IO_ERROR


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
    # Ceilings expressed as a share of the mounted volume. Their sum stays below
    # 1.0 so the capacity cap and the free-space reserve are always jointly
    # satisfiable on any volume size.
    VOLUME_MAX_RATIO = 0.60
    VOLUME_MIN_FREE_RATIO = 0.20

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

    def _effective_limits(self) -> tuple[int, int]:
        """Clamp the configured cache bounds to what this volume can satisfy.

        The configured cap and free-space reserve are only ever lowered, never
        raised, so the bounded-cache contract still holds. Without this, a volume
        smaller than cap + reserve can never satisfy both conditions at once and
        every materialization fails permanently, including the very first one:
        an empty cache has nothing to evict, so ``_reserve`` gives up instead.
        """
        configured_max = int(settings.NETRA_STORAGE_CACHE_MAX_BYTES)
        configured_free = int(settings.NETRA_STORAGE_CACHE_MIN_FREE_BYTES)
        try:
            total = shutil.disk_usage(self.root).total
        except OSError:
            return configured_max, configured_free
        if total <= 0:
            return configured_max, configured_free
        maximum = min(configured_max, int(total * self.VOLUME_MAX_RATIO))
        minimum_free = min(configured_free, int(total * self.VOLUME_MIN_FREE_RATIO))
        if (maximum, minimum_free) != (configured_max, configured_free):
            signature = (str(self.root), maximum, minimum_free)
            if signature not in _clamp_warnings:
                _clamp_warnings.add(signature)
                logger.warning(
                    "Encrypted Storage cache bounds clamped to the volume at %s: "
                    "capacity %d -> %d bytes, free-space reserve %d -> %d bytes, volume total %d bytes.",
                    self.root, configured_max, maximum, configured_free, minimum_free, total,
                )
        return maximum, minimum_free

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
        maximum, minimum_free = self._effective_limits()
        if incoming > maximum:
            raise CacheCapacityError("Encrypted object exceeds the complete cache capacity.")
        while (
            self._used() + incoming > maximum
            or self._free() - incoming < minimum_free
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
                raise CacheCapacityError(
                    "Encrypted Storage cache cannot preserve its capacity and free-space reserve."
                )

    def materialize(
        self, uri: str, *, expected_sha256: str = "", expected_size: int | None = None,
        downloader: Callable[[Path], None],
    ) -> Path:
        try:
            return self._materialize(
                uri,
                expected_sha256=expected_sha256,
                expected_size=expected_size,
                downloader=downloader,
            )
        except StorageCacheUnavailable:
            raise
        except (OSError, RuntimeError, TimeoutError) as exc:
            code = classify_cache_failure(exc)
            # The full exception, including any path detail, belongs in the
            # service log only; callers receive the classified code.
            logger.exception("Encrypted Storage cache could not materialize an object (%s).", code)
            raise StorageCacheUnavailable(
                f"The encrypted Storage cache is temporarily unavailable [{code}].", code=code
            ) from exc

    def _materialize(
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
            logger.warning(
                "Encrypted Storage cache lease timed out after %s seconds (%s).",
                settings.NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS, CACHE_LOCK_TIMEOUT,
            )
            raise StorageCacheUnavailable(
                f"The encrypted Storage cache is temporarily unavailable [{CACHE_LOCK_TIMEOUT}].",
                code=CACHE_LOCK_TIMEOUT,
            )
        try:
            return _LeasedFile(path.open("rb"), lease)
        except Exception:
            lease.release()
            raise

    def preflight(self) -> dict:
        """Prove the cache root is usable before any evidence work begins.

        Creating the directories is not enough: a Railway volume mounted over
        ``/app/storage`` replaces the image directory along with its ownership,
        so the probe below writes, reads back, and removes a real file.
        """
        payload: dict = {"ok": False, "code": CACHE_IO_ERROR, "root": str(self.root), "enabled": self.enabled}
        if not self.enabled:
            payload["code"] = CACHE_DISABLED
            return payload
        probe: Path | None = None
        try:
            self._ensure()
            probe = self.temporary / f"preflight-{os.getpid()}.partial"
            probe.write_bytes(b"netra-cache-preflight")
            if probe.read_bytes() != b"netra-cache-preflight":
                raise OSError("Encrypted Storage cache preflight read-back did not match.")
            usage = shutil.disk_usage(self.root)
            maximum, minimum_free = self._effective_limits()
        except (OSError, RuntimeError, TimeoutError) as exc:
            code = classify_cache_failure(exc)
            logger.exception("Encrypted Storage cache preflight failed (%s).", code)
            payload["code"] = code
            return payload
        finally:
            if probe is not None:
                try:
                    probe.unlink(missing_ok=True)
                except OSError:  # nosec B110 - the probe is pruned as a stale temporary later.
                    pass
        payload.update({
            "ok": True,
            "code": "ok",
            "totalBytes": usage.total,
            "freeBytes": usage.free,
            "effectiveMaxBytes": maximum,
            "effectiveMinimumFreeBytes": minimum_free,
            "configuredMaxBytes": int(settings.NETRA_STORAGE_CACHE_MAX_BYTES),
            "configuredMinimumFreeBytes": int(settings.NETRA_STORAGE_CACHE_MIN_FREE_BYTES),
        })
        return payload

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
        # Report the bounds actually enforced by _reserve, not the configured
        # ceilings, so operators see the limits in force on this volume.
        maximum, minimum_free = self._effective_limits()
        return CacheStatus(
            enabled=self.enabled, root=str(self.root), max_bytes=maximum,
            used_bytes=sum(path.stat().st_size for path in objects),
            minimum_free_bytes=minimum_free,
            entry_count=len(objects), stale_temporary_count=stale,
        )


storage_cache = EncryptedObjectCache()
