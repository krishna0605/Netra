from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable
from uuid import uuid4

from django.conf import settings
from django.db import transaction

from apps.forensics.models import (
    AnalysisChunk,
    CaptureChunk,
    EvidenceFile,
    EvidenceManifest,
    Export,
    IntegrationDelivery,
    Report,
    ZeekLogSummary,
)
from common.custody import record_custody_event
from common.hashing import sha256_file
from common.storage_provider import storage_provider
from common.vault_legacy import stream_decrypt_legacy_path
from common.vault_v2 import ArtifactCryptoContext, encrypt_artifact_v2


@dataclass(frozen=True)
class LegacyArtifact:
    key: str
    model: str
    pk: str
    pointer_field: str
    source_uri: str
    case_id: str
    artifact_id: str
    artifact_type: str
    target_bucket: str
    expected_bytes: int
    original_filename: str
    nested_index: int | None = None


def _artifact(
    *, model: str, pk: object, field: str, uri: str, case_id: str, artifact_id: str,
    artifact_type: str, bucket: str, expected_bytes: int = 0, filename: str = "artifact.bin",
    nested_index: int | None = None,
) -> LegacyArtifact:
    suffix = f":{nested_index}" if nested_index is not None else ""
    return LegacyArtifact(
        key=f"{model}:{pk}:{field}{suffix}", model=model, pk=str(pk), pointer_field=field,
        source_uri=uri, case_id=case_id, artifact_id=artifact_id,
        artifact_type=artifact_type, target_bucket=bucket,
        expected_bytes=max(int(expected_bytes or 0), 0), original_filename=Path(filename).name,
        nested_index=nested_index,
    )


def enumerate_legacy_artifacts() -> list[LegacyArtifact]:
    """Inventory database pointers only; this function never contacts Storage."""
    rows: list[LegacyArtifact] = []
    for evidence in EvidenceFile.objects.exclude(stored_path="").iterator():
        if not evidence.stored_path.endswith("/manifest.v2.json"):
            rows.append(_artifact(
                model="EvidenceFile", pk=evidence.pk, field="stored_path", uri=evidence.stored_path,
                case_id=evidence.case_id, artifact_id=evidence.pk, artifact_type="evidence",
                bucket=settings.SUPABASE_STORAGE_BUCKET_EVIDENCE, expected_bytes=evidence.size_bytes,
                filename=evidence.filename,
            ))
    for chunk in CaptureChunk.objects.exclude(stored_path="").select_related("capture_job").iterator():
        if not chunk.stored_path.endswith("/manifest.v2.json"):
            rows.append(_artifact(
                model="CaptureChunk", pk=chunk.pk, field="stored_path", uri=chunk.stored_path,
                case_id=chunk.capture_job.case_id, artifact_id=chunk.pk, artifact_type="capture-chunk",
                bucket=settings.SUPABASE_STORAGE_BUCKET_CAPTURE_CHUNKS, expected_bytes=chunk.byte_count,
                filename=f"{chunk.pk}.pcap",
            ))
    for chunk in AnalysisChunk.objects.exclude(encrypted_source_path="").select_related("processing_job").iterator():
        if not chunk.encrypted_source_path.endswith("/manifest.v2.json"):
            rows.append(_artifact(
                model="AnalysisChunk", pk=chunk.pk, field="encrypted_source_path", uri=chunk.encrypted_source_path,
                case_id=chunk.processing_job.case_id, artifact_id=f"analysis-{chunk.pk}", artifact_type="analysis-chunk",
                bucket=settings.SUPABASE_STORAGE_BUCKET_ANALYSIS_CHUNKS, expected_bytes=chunk.byte_count,
                filename=f"analysis-{chunk.pk}.pcap",
            ))
    for report in Report.objects.exclude(stored_path="").iterator():
        if not report.stored_path.endswith("/manifest.v2.json"):
            rows.append(_artifact(
                model="Report", pk=report.pk, field="stored_path", uri=report.stored_path,
                case_id=report.case_id, artifact_id=report.pk, artifact_type="report",
                bucket=settings.SUPABASE_STORAGE_BUCKET_REPORTS, filename=f"{report.pk}.html",
            ))
    for export in Export.objects.exclude(stored_path="").iterator():
        if not export.stored_path.endswith("/manifest.v2.json"):
            rows.append(_artifact(
                model="Export", pk=export.pk, field="stored_path", uri=export.stored_path,
                case_id=export.case_id, artifact_id=export.pk, artifact_type="export",
                bucket=settings.SUPABASE_STORAGE_BUCKET_EXPORTS, filename=f"{export.pk}.bin",
            ))
    for delivery in IntegrationDelivery.objects.exclude(artifact_path="").exclude(case=None).iterator():
        if not delivery.artifact_path.endswith("/manifest.v2.json"):
            rows.append(_artifact(
                model="IntegrationDelivery", pk=delivery.pk, field="artifact_path", uri=delivery.artifact_path,
                case_id=delivery.case_id, artifact_id=f"integration-{delivery.pk}", artifact_type="integration-artifact",
                bucket=settings.SUPABASE_STORAGE_BUCKET_EXPORTS, filename=f"integration-{delivery.pk}.bin",
            ))
    for summary in ZeekLogSummary.objects.iterator():
        for index, item in enumerate(summary.logs if isinstance(summary.logs, list) else []):
            if not isinstance(item, dict):
                continue
            uri = str(item.get("stored_path") or item.get("storageUri") or "")
            if uri and not uri.endswith("/manifest.v2.json"):
                rows.append(_artifact(
                    model="ZeekLogSummary", pk=summary.pk, field="logs", uri=uri,
                    case_id=summary.case_id, artifact_id=f"zeek-{summary.pk}-{index}", artifact_type="zeek-log",
                    bucket=settings.SUPABASE_STORAGE_BUCKET_ZEEK_LOGS, filename=f"zeek-{summary.pk}-{index}.log",
                    nested_index=index,
                ))
    return rows


def validate_state_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    workspace = Path(settings.REPO_ROOT).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError:
        pass
    else:
        raise ValueError("Crypto migration state must be outside the Git workspace.")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "artifacts": {}, "bytesRead": 0}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("artifacts"), dict):
        raise ValueError("Crypto migration state is invalid or unsupported.")
    return data


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent, suffix=".state") as handle:
        temporary = Path(handle.name)
        json.dump(state, handle, sort_keys=True, separators=(",", ":"))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _model_for(name: str):
    return {
        "EvidenceFile": EvidenceFile,
        "CaptureChunk": CaptureChunk,
        "AnalysisChunk": AnalysisChunk,
        "Report": Report,
        "Export": Export,
        "IntegrationDelivery": IntegrationDelivery,
        "ZeekLogSummary": ZeekLogSummary,
    }[name]


def _current_pointer(row, artifact: LegacyArtifact) -> str:
    if artifact.nested_index is None:
        return str(getattr(row, artifact.pointer_field))
    logs = row.logs if isinstance(row.logs, list) else []
    if artifact.nested_index >= len(logs) or not isinstance(logs[artifact.nested_index], dict):
        return ""
    item = logs[artifact.nested_index]
    return str(item.get("stored_path") or item.get("storageUri") or "")


def _swap_pointer(artifact: LegacyArtifact, saved: dict, retain_until: str) -> None:
    model = _model_for(artifact.model)
    with transaction.atomic():
        row = model.objects.select_for_update().get(pk=artifact.pk)
        if _current_pointer(row, artifact) != artifact.source_uri:
            raise RuntimeError("Source pointer changed after planning; refusing to overwrite newer data.")
        if artifact.nested_index is None:
            setattr(row, artifact.pointer_field, saved["stored_path"])
            update_fields = [artifact.pointer_field, "updated_at"]
            for name, value in (
                ("sha256", saved["sha256"]),
                ("encrypted_sha256", saved["encrypted_sha256"]),
                ("plaintext_sha256", saved["plaintext_sha256"]),
                ("artifact_sha256", saved["sha256"]),
            ):
                if hasattr(row, name):
                    setattr(row, name, value)
                    update_fields.append(name)
            row.save(update_fields=update_fields)
        else:
            logs = list(row.logs)
            item = dict(logs[artifact.nested_index])
            key = "stored_path" if "stored_path" in item else "storageUri"
            item[key] = saved["stored_path"]
            item["sha256"] = saved["sha256"]
            item["encryptedSha256"] = saved["encrypted_sha256"]
            item["legacyRetainUntil"] = retain_until
            logs[artifact.nested_index] = item
            row.logs = logs
            row.save(update_fields=["logs", "updated_at"])
        if artifact.model == "EvidenceFile":
            EvidenceManifest.objects.filter(evidence_file_id=artifact.pk).update(
                storage_uri=saved["stored_path"], plaintext_sha256=saved["plaintext_sha256"],
                encrypted_sha256=saved["encrypted_sha256"], encryption_algorithm=saved["encryption_algorithm"],
                key_id=saved["key_id"], manifest_json=saved["v2_manifest"], manifest_hash=saved["manifest_hash"],
            )
        case = row.case if hasattr(row, "case") else row.capture_job.case if artifact.model == "CaptureChunk" else row.processing_job.case
        record_custody_event(
            case, "crypto-migration", "artifact-reencrypted",
            {"artifactType": artifact.artifact_type, "artifactId": artifact.artifact_id,
             "legacyRetainUntil": retain_until, "manifestHash": saved["manifest_hash"]},
            evidence=row if artifact.model == "EvidenceFile" else None,
            resource_type=artifact.artifact_type, resource_id=artifact.artifact_id,
        )


def execute_migration(
    artifacts: Iterable[LegacyArtifact], *, state_path: Path, max_source_bytes: int, retain_until: str,
) -> dict:
    state = load_state(state_path)
    work = state_path.parent / f"{state_path.stem}.work"
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o700)
    for artifact in artifacts:
        entry = state["artifacts"].setdefault(artifact.key, {**asdict(artifact), "status": "planned", "attempts": 0})
        if entry.get("status") == "committed":
            continue
        estimate = artifact.expected_bytes
        if estimate <= 0 and str(artifact.source_uri).startswith("supabase://"):
            entry["status"] = "blocked-missing-size"
            save_state(state_path, state)
            raise RuntimeError(f"{artifact.key} has no trusted size estimate; execution stopped before Storage read.")
        if state["bytesRead"] + estimate > max_source_bytes:
            entry["status"] = "budget-stopped"
            save_state(state_path, state)
            break
        source_cache = work / f"{uuid4().hex}.legacy"
        cached_name = entry.get("sourceCache")
        if cached_name:
            source_cache = work / Path(cached_name).name
        if not source_cache.exists():
            storage_provider.copy_encrypted(artifact.source_uri, source_cache)
            actual = source_cache.stat().st_size
            if state["bytesRead"] + actual > max_source_bytes:
                source_cache.unlink(missing_ok=True)
                entry["status"] = "budget-stopped"
                save_state(state_path, state)
                break
            state["bytesRead"] += actual
            entry["sourceCache"] = source_cache.name
            entry["sourceCiphertextSha256"] = sha256_file(source_cache)
            save_state(state_path, state)
        elif sha256_file(source_cache) != entry.get("sourceCiphertextSha256"):
            raise RuntimeError("Cached legacy ciphertext failed verification.")
        plaintext = work / f"{uuid4().hex}.plaintext"
        try:
            stream_decrypt_legacy_path(source_cache, plaintext, temporary_root=work)
            entry["attempts"] = int(entry.get("attempts", 0)) + 1
            if entry["attempts"] > 2:
                raise RuntimeError("Artifact retry limit exceeded.")
            generation = entry.setdefault("generationId", uuid4().hex)
            saved = encrypt_artifact_v2(
                plaintext,
                ArtifactCryptoContext(
                    artifact_id=artifact.artifact_id, artifact_type=artifact.artifact_type,
                    case_id=artifact.case_id, original_filename=artifact.original_filename,
                    target_bucket=artifact.target_bucket,
                ),
                generation_id=generation,
            )
            _swap_pointer(artifact, saved, retain_until)
            entry.update({"status": "committed", "manifestUri": saved["stored_path"], "manifestHash": saved["manifest_hash"], "retainUntil": retain_until})
            save_state(state_path, state)
        except FileExistsError:
            # A process interruption may leave an unreachable partial generation.
            # Preserve it for grace-period cleanup and retry under a new immutable generation.
            entry["generationId"] = uuid4().hex
            entry["status"] = "retryable-partial-generation"
            save_state(state_path, state)
            raise
        finally:
            plaintext.unlink(missing_ok=True)
    return state
