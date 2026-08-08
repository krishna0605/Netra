from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from uuid import uuid4


_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


class UnsafeArtifactPath(ValueError):
    """Raised before an artifact path can escape its configured directory."""


@dataclass(frozen=True)
class ArtifactPaths:
    folder: Path
    encrypted_target: Path


def generated_artifact_filename(prefix: str, suffix: str) -> str:
    normalized_suffix = suffix.lower()
    if not normalized_suffix.startswith("."):
        normalized_suffix = f".{normalized_suffix}"
    return f"{prefix}-{uuid4().hex}{normalized_suffix}"


def validate_artifact_filename(filename: object, *, allowed_extensions: frozenset[str]) -> str:
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise UnsafeArtifactPath("Artifact filename is invalid.")
    if (
        filename != filename.strip()
        or filename.endswith((".", " "))
        or _CONTROL_CHARACTERS.search(filename)
        or "/" in filename
        or "\\" in filename
        or ":" in filename
        or filename in {".", ".."}
        or ".." in filename
        or Path(filename).is_absolute()
        or PureWindowsPath(filename).is_absolute()
        or PureWindowsPath(filename).drive
        or not _SAFE_FILENAME.fullmatch(filename)
    ):
        raise UnsafeArtifactPath("Artifact filename must be a plain, safe filename without path components.")
    if Path(filename).suffix.lower() not in allowed_extensions:
        raise UnsafeArtifactPath("Artifact filename extension is not allowed for this route.")
    return filename


def resolve_artifact_paths(
    storage_root: Path,
    folder_name: str,
    filename: object,
    *,
    allowed_extensions: frozenset[str],
) -> ArtifactPaths:
    safe_filename = validate_artifact_filename(filename, allowed_extensions=allowed_extensions)
    root = Path(storage_root).resolve()
    folder = (root / folder_name).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    encrypted_target = (folder / f"{safe_filename}.enc").resolve()
    try:
        encrypted_target.relative_to(folder)
    except ValueError as exc:
        raise UnsafeArtifactPath("Artifact target is outside its configured directory.") from exc
    if encrypted_target.parent != folder:
        raise UnsafeArtifactPath("Nested artifact paths are not allowed.")
    return ArtifactPaths(folder=folder, encrypted_target=encrypted_target)
