"""Resumable, egress-metered Supabase Storage project migration.

Secrets are read only from NETRA_MIGRATION_* environment variables. The tool
never prints them and refuses to access the source until the quota reset has
been explicitly confirmed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_BUDGET_BYTES = 600 * 1024 * 1024
MINIMUM_AVAILABLE_EGRESS_BYTES = 768 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
MAX_ATTEMPTS = 3


class MigrationError(RuntimeError):
    pass


class Meter:
    def __init__(self, budget_bytes: int, initial_bytes: int = 0):
        self.budget_bytes = budget_bytes
        self.downloaded_bytes = initial_bytes

    def add(self, count: int) -> None:
        self.downloaded_bytes += count
        if self.downloaded_bytes > self.budget_bytes:
            raise MigrationError(
                f"Metered downloads reached {self.downloaded_bytes} bytes, above the {self.budget_bytes}-byte hard limit."
            )


class StorageApi:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip("/")
        self.key = key

    def _headers(self, *, content_type: str = "application/json") -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.key}",
            "apikey": self.key,
            "Content-Type": content_type,
        }

    def json_request(self, path: str, *, method: str = "GET", payload=None):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.url}{path}",
            method=method,
            data=body,
            headers=self._headers(),
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                content = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise MigrationError(f"Storage API {method} {path} failed with HTTP {exc.code}: {detail}") from exc
        return json.loads(content or b"null")

    def list_buckets(self) -> list[dict]:
        return self.json_request("/storage/v1/bucket") or []

    def ensure_bucket(self, source_bucket: dict, existing_names: set[str]) -> None:
        bucket_id = source_bucket.get("id") or source_bucket["name"]
        quoted_id = urllib.parse.quote(bucket_id, safe="")
        payload = {
            "id": bucket_id,
            "name": source_bucket.get("name") or bucket_id,
            "public": False,
            "fileSizeLimit": source_bucket.get("file_size_limit"),
            "allowedMimeTypes": source_bucket.get("allowed_mime_types"),
        }
        payload = {key: value for key, value in payload.items() if value is not None}
        if bucket_id in existing_names:
            payload.pop("id", None)
            payload.pop("name", None)
            self.json_request(f"/storage/v1/bucket/{quoted_id}", method="PUT", payload=payload)
        else:
            self.json_request("/storage/v1/bucket", method="POST", payload=payload)
            existing_names.add(bucket_id)

    def list_objects(self, bucket: str) -> list[dict]:
        objects: list[dict] = []
        prefixes = [""]
        quoted_bucket = urllib.parse.quote(bucket, safe="")
        while prefixes:
            prefix = prefixes.pop()
            offset = 0
            while True:
                page = self.json_request(
                    f"/storage/v1/object/list/{quoted_bucket}",
                    method="POST",
                    payload={
                        "prefix": prefix,
                        "limit": 1000,
                        "offset": offset,
                        "sortBy": {"column": "name", "order": "asc"},
                    },
                ) or []
                for item in page:
                    name = item.get("name")
                    if not name:
                        continue
                    full_name = f"{prefix}/{name}" if prefix else name
                    if item.get("id") is None:
                        prefixes.append(full_name)
                    else:
                        objects.append(item | {"name": full_name})
                if len(page) < 1000:
                    break
                offset += len(page)
        return sorted(objects, key=lambda item: item["name"])

    def download_to(self, bucket: str, object_name: str, destination: Path, meter: Meter) -> tuple[str, dict[str, str]]:
        object_path = "/".join(urllib.parse.quote(part, safe="") for part in object_name.split("/"))
        request = urllib.request.Request(
            f"{self.url}/storage/v1/object/{urllib.parse.quote(bucket, safe='')}/{object_path}",
            headers=self._headers(content_type="application/octet-stream"),
        )
        digest = hashlib.sha256()
        try:
            with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
                headers = {key.lower(): value for key, value in response.headers.items()}
                while chunk := response.read(CHUNK_BYTES):
                    meter.add(len(chunk))
                    output.write(chunk)
                    digest.update(chunk)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise MigrationError(f"Download failed for {bucket}/{object_name}: HTTP {exc.code}: {detail}") from exc
        return digest.hexdigest(), headers

    def upload_file(self, bucket: str, object_name: str, source: Path, *, headers: dict[str, str], metadata: dict) -> None:
        parsed = urllib.parse.urlsplit(self.url)
        object_path = "/".join(urllib.parse.quote(part, safe="") for part in object_name.split("/"))
        path = f"/storage/v1/object/{urllib.parse.quote(bucket, safe='')}/{object_path}"
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=120)
        connection.putrequest("POST", path)
        connection.putheader("Authorization", f"Bearer {self.key}")
        connection.putheader("apikey", self.key)
        connection.putheader("Content-Length", str(source.stat().st_size))
        connection.putheader("Content-Type", headers.get("content-type") or metadata.get("mimetype") or "application/octet-stream")
        connection.putheader("Cache-Control", headers.get("cache-control") or metadata.get("cacheControl") or "max-age=3600")
        connection.putheader("x-upsert", "false")
        if metadata:
            encoded_metadata = base64.b64encode(json.dumps(metadata, separators=(",", ":")).encode("utf-8")).decode("ascii")
            connection.putheader("x-metadata", encoded_metadata)
        connection.endheaders()
        with source.open("rb") as input_file:
            while chunk := input_file.read(CHUNK_BYTES):
                connection.send(chunk)
        response = connection.getresponse()
        detail = response.read().decode("utf-8", errors="replace")[:1000]
        connection.close()
        if response.status in {400, 409} and any(marker in detail.lower() for marker in ("already exists", "duplicate", "resource already")):
            # A previous interrupted attempt may have completed the upload but
            # not persisted the manifest. The mandatory hash verification below
            # decides whether this existing object is safe to reuse.
            return
        if response.status not in {200, 201}:
            raise MigrationError(f"Upload failed for {bucket}/{object_name}: HTTP {response.status}: {detail}")


def load_manifest(path: Path, source_url: str, target_url: str, budget_bytes: int) -> dict:
    if path.exists():
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("sourceUrl") != source_url or manifest.get("targetUrl") != target_url:
            raise MigrationError("The existing manifest belongs to different source or target projects.")
        return manifest
    return {
        "formatVersion": 1,
        "sourceUrl": source_url,
        "targetUrl": target_url,
        "budgetBytes": budget_bytes,
        "meteredDownloadBytes": 0,
        "objects": {},
        "buckets": {},
    }


def save_manifest(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise MigrationError(f"Required environment variable {name} is missing.")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-source-egress-reset", action="store_true")
    parser.add_argument("--available-egress-bytes", type=int, required=True)
    parser.add_argument("--budget-bytes", type=int, default=DEFAULT_BUDGET_BYTES)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--expected-source-objects", type=int)
    args = parser.parse_args()

    if not args.confirm_source_egress_reset:
        raise MigrationError("Refusing source access until --confirm-source-egress-reset is supplied.")
    if args.available_egress_bytes < MINIMUM_AVAILABLE_EGRESS_BYTES:
        raise MigrationError(f"At least {MINIMUM_AVAILABLE_EGRESS_BYTES} available egress bytes must be confirmed.")
    if args.budget_bytes > DEFAULT_BUDGET_BYTES:
        raise MigrationError(f"The hard payload budget cannot exceed {DEFAULT_BUDGET_BYTES} bytes.")

    source_url = required_environment("NETRA_MIGRATION_SOURCE_URL")
    source_key = required_environment("NETRA_MIGRATION_SOURCE_SERVICE_ROLE_KEY")
    target_url = required_environment("NETRA_MIGRATION_TARGET_URL")
    target_key = required_environment("NETRA_MIGRATION_TARGET_SERVICE_ROLE_KEY")
    if source_url.rstrip("/") == target_url.rstrip("/"):
        raise MigrationError("Source and target URLs must be different.")

    manifest = load_manifest(args.manifest.resolve(), source_url.rstrip("/"), target_url.rstrip("/"), args.budget_bytes)
    meter = Meter(args.budget_bytes, int(manifest.get("meteredDownloadBytes", 0)))
    source = StorageApi(source_url, source_key)
    target = StorageApi(target_url, target_key)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    source_buckets = sorted(source.list_buckets(), key=lambda item: item.get("id") or item.get("name") or "")
    target_names = {item.get("id") or item.get("name") for item in target.list_buckets()}
    inventory: list[tuple[dict, dict]] = []
    for bucket in source_buckets:
        bucket_id = bucket.get("id") or bucket.get("name")
        target.ensure_bucket(bucket, target_names)
        objects = source.list_objects(bucket_id)
        manifest["buckets"][bucket_id] = {
            "objectCount": len(objects),
            "sourceBytes": sum(int((item.get("metadata") or {}).get("size") or 0) for item in objects),
        }
        inventory.extend((bucket, item) for item in objects)
    if args.expected_source_objects is not None and len(inventory) != args.expected_source_objects:
        raise MigrationError(f"Expected {args.expected_source_objects} source objects, found {len(inventory)}.")
    save_manifest(args.manifest.resolve(), manifest)

    for bucket, item in inventory:
        bucket_id = bucket.get("id") or bucket.get("name")
        object_name = item["name"]
        manifest_key = f"{bucket_id}/{object_name}"
        if manifest["objects"].get(manifest_key, {}).get("status") == "verified":
            continue
        metadata = item.get("metadata") or {}
        last_error = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            temporary_path = None
            try:
                with tempfile.NamedTemporaryFile(prefix="netra-storage-", dir=args.work_dir, delete=False) as temporary:
                    temporary_path = Path(temporary.name)
                source_hash, source_headers = source.download_to(bucket_id, object_name, temporary_path, meter)
                target.upload_file(bucket_id, object_name, temporary_path, headers=source_headers, metadata=metadata)
                verification_path = None
                try:
                    with tempfile.NamedTemporaryFile(prefix="netra-verify-", dir=args.work_dir, delete=False) as verification:
                        verification_path = Path(verification.name)
                    target_hash, _ = target.download_to(bucket_id, object_name, verification_path, meter)
                finally:
                    if verification_path is not None:
                        verification_path.unlink(missing_ok=True)
                if source_hash != target_hash:
                    raise MigrationError(f"SHA-256 mismatch for {manifest_key}.")
                manifest["objects"][manifest_key] = {
                    "status": "verified",
                    "size": temporary_path.stat().st_size,
                    "sha256": source_hash,
                    "attempts": attempt,
                }
                manifest["meteredDownloadBytes"] = meter.downloaded_bytes
                save_manifest(args.manifest.resolve(), manifest)
                print(f"verified {manifest_key} ({temporary_path.stat().st_size} bytes)")
                break
            except Exception as exc:
                last_error = exc
                manifest["meteredDownloadBytes"] = meter.downloaded_bytes
                save_manifest(args.manifest.resolve(), manifest)
                if meter.downloaded_bytes >= meter.budget_bytes:
                    raise
                if attempt == MAX_ATTEMPTS:
                    raise
                time.sleep(attempt)
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
        if last_error and manifest["objects"].get(manifest_key, {}).get("status") != "verified":
            raise last_error

    manifest["meteredDownloadBytes"] = meter.downloaded_bytes
    manifest["status"] = "complete"
    save_manifest(args.manifest.resolve(), manifest)
    print(json.dumps({"status": "complete", "objects": len(inventory), "meteredDownloadBytes": meter.downloaded_bytes}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationError as exc:
        raise SystemExit(f"Migration stopped: {exc}") from exc
