$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$sample = Join-Path $repoRoot "samples\pcaps\distcc_exec_backdoor.pcap"

if (-not (Test-Path $sample)) {
  throw "Replay validation sample not found: $sample"
}

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

docker cp $sample "${backendId}:/tmp/netra-phase2-replay.pcap" | Out-Null

$python = @'
from pathlib import Path
import time

from django.core.files.uploadedfile import SimpleUploadedFile

from apps.forensics.models import CaptureJob
from common.operations import create_capture_job, ensure_capture_case, start_replay
from common.storage import save_uploaded_file

case = ensure_capture_case("CYB-GJ-PHASE2-REPLAY-VALIDATION")
source = Path("/tmp/netra-phase2-replay.pcap")
saved = save_uploaded_file(
    SimpleUploadedFile(source.name, source.read_bytes(), content_type="application/vnd.tcpdump.pcap"),
    "capture_chunk",
)
Path(saved["analysis_path"]).unlink(missing_ok=True)

job = create_capture_job(
    case=case,
    mode=CaptureJob.Mode.REPLAY,
    duration_seconds=120,
    packet_limit=5000,
    chunk_interval_seconds=2,
    source_label="Phase 2 replay validation",
)
start_replay(job, saved["stored_path"], "max")

deadline = time.time() + 120
while time.time() < deadline:
    time.sleep(1)
    job.refresh_from_db()
    if job.status in {CaptureJob.Status.COMPLETED, CaptureJob.Status.FAILED, CaptureJob.Status.STOPPED}:
        break

if job.status != CaptureJob.Status.COMPLETED:
    raise SystemExit(f"Replay did not complete. status={job.status} error={job.error_message}")
if not job.final_evidence_file_id:
    raise SystemExit("Replay completed without final evidence.")
if job.chunk_count < 1:
    raise SystemExit("Replay completed without stored capture chunks.")

print(f"[PASS] replay finalized: job={job.id} chunks={job.chunk_count} evidence={job.final_evidence_file_id}")
'@

$tmpScript = Join-Path ([System.IO.Path]::GetTempPath()) ("netra-phase2-replay-validator-" + [guid]::NewGuid().ToString("N") + ".py")
try {
  [System.IO.File]::WriteAllText($tmpScript, $python, [System.Text.UTF8Encoding]::new($false))
  docker cp $tmpScript "${backendId}:/tmp/netra-phase2-replay-validator.py" | Out-Null
  docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py shell < /tmp/netra-phase2-replay-validator.py"
} finally {
  Remove-Item -LiteralPath $tmpScript -Force -ErrorAction SilentlyContinue
}
