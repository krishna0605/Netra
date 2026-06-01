from __future__ import annotations

import shutil
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


storage_provider = LocalFilesystemStorageProvider()


def resolve_storage_path(storage_uri: str | Path) -> Path:
    return storage_provider.resolve(storage_uri)


def storage_uri(path: str | Path) -> str:
    return storage_provider.uri_for(path)
