$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$api = "http://localhost:8080/api"

function Get-NetraEnvValue([string]$Name) {
  $current = [Environment]::GetEnvironmentVariable($Name)
  if ($current) { return $current }
  if (-not (Test-Path $envFile)) { return "" }
  $line = Get-Content $envFile | Where-Object { $_ -match "^\s*$Name\s*=" } | Select-Object -First 1
  if (-not $line) { return "" }
  return (($line -split "=", 2)[1]).Trim().Trim('"').Trim("'")
}

Write-Host "Validating Phase 4 native sensor capture path..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

$sensorKey = Get-NetraEnvValue "NETRA_SENSOR_SHARED_KEY"
if (-not $sensorKey) {
  throw "NETRA_SENSOR_SHARED_KEY is required for sensor validation."
}

$sample = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
if (-not (Test-Path $sample)) {
  $sample = (Get-ChildItem (Join-Path $repoRoot "samples\pcaps") -Filter *.pcap | Select-Object -First 1).FullName
}
if (-not $sample) { throw "No sample PCAP found for sensor validation." }

python -m py_compile `
  sensor-agent\netra_sensor\capture.py `
  sensor-agent\netra_sensor\cli.py `
  sensor-agent\netra_sensor\config.py `
  sensor-agent\netra_sensor\dumpcap.py `
  sensor-agent\netra_sensor\heartbeat.py `
  sensor-agent\netra_sensor\uploader.py
Write-Host "[PASS] sensor-agent Python modules compile"

$stamp = Get-Date -Format "yyyyMMddHHmmss"
$sensorId = "sensor-phase4-validator-$stamp"
$caseId = "CYB-GJ-PHASE4-SENSOR-$stamp"

$setupPython = @"
from apps.forensics.models import CaptureJob, Sensor, SensorCommand
from common.operations import capture_job_payload, create_capture_job, ensure_capture_case

sensor, _ = Sensor.objects.update_or_create(
    id="$sensorId",
    defaults={
        "name": "Phase 4 Validator Sensor",
        "hostname": "phase4-validator",
        "platform": "windows-validator",
        "agent_version": "phase4-validator",
        "capture_engine": "dumpcap",
        "capture_engine_version": "validator",
        "status": Sensor.Status.ONLINE,
        "enabled": True,
        "interfaces_json": [{"name": "Validation Interface", "value": "validation0"}],
    },
)
from django.utils import timezone
sensor.last_heartbeat_at = timezone.now()
sensor.save(update_fields=["last_heartbeat_at", "updated_at"])
case = ensure_capture_case("$caseId", "Phase 4 Validator")
job = create_capture_job(
    case=case,
    mode=CaptureJob.Mode.LIVE_CAPTURE,
    sensor=sensor,
    interface_name="validation0",
    duration_seconds=10,
    packet_limit=5000,
    chunk_interval_seconds=2,
    source_label=sensor.name,
)
SensorCommand.objects.create(sensor=sensor, capture_job=job, command_type="capture.start", payload_json=capture_job_payload(job))
print(job.id)
"@

$tmpSetup = Join-Path ([System.IO.Path]::GetTempPath()) ("netra-phase4-sensor-setup-" + [guid]::NewGuid().ToString("N") + ".py")
try {
  [System.IO.File]::WriteAllText($tmpSetup, $setupPython, [System.Text.UTF8Encoding]::new($false))
  docker cp $tmpSetup "${backendId}:/tmp/netra-phase4-sensor-setup.py" | Out-Null
  $setupOutput = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py shell < /tmp/netra-phase4-sensor-setup.py"
} finally {
  Remove-Item -LiteralPath $tmpSetup -Force -ErrorAction SilentlyContinue
}

$jobId = ($setupOutput | Select-Object -Last 1).Trim()
if (-not $jobId -or $jobId -notlike "cap-*") { throw "Could not create capture job. Output: $setupOutput" }
Write-Host "[PASS] sensor capture job and command queued: $jobId"

$sensorHeaders = @{ "X-Netra-Sensor-Key" = $sensorKey }
$command = Invoke-RestMethod -Uri "$api/sensors/$sensorId/commands/next" -Headers $sensorHeaders
if (-not $command.command -or $command.command.jobId -ne $jobId) {
  throw "Sensor command polling did not return queued job $jobId."
}
Write-Host "[PASS] sensor command polling returns the queued capture"

$chunkRaw = & curl.exe -sS -X POST "$api/sensors/$sensorId/chunks" `
  -H "X-Netra-Sensor-Key: $sensorKey" `
  -F "jobId=$jobId" `
  -F "sequence=1" `
  -F "file=@$sample"
if ($LASTEXITCODE -ne 0) { throw "Sensor chunk upload failed with exit code $LASTEXITCODE." }
$chunk = $chunkRaw | ConvertFrom-Json
if (-not $chunk.chunkId -or $chunk.chunksReceived -lt 1) { throw "Sensor chunk upload did not create a chunk: $chunkRaw" }
Write-Host "[PASS] sensor chunk upload created encrypted capture chunk"

$completed = Invoke-RestMethod -Method Post -Uri "$api/sensors/$sensorId/captures/$jobId/complete" -Headers $sensorHeaders
if ($completed.status -ne "completed" -or -not $completed.finalEvidenceId) {
  throw "Sensor capture did not finalize into evidence. Status=$($completed.status) Error=$($completed.error)"
}
Write-Host "[PASS] sensor capture finalized into immutable evidence"

$status = Invoke-RestMethod -Uri "$api/capture/live/$jobId/status"
if ($status.status -ne "completed" -or $status.chunksReceived -lt 1 -or -not $status.finalEvidenceId) {
  throw "Completed capture status is incomplete."
}
Write-Host "[PASS] finalized capture status is visible through API"

$failCaseId = "CYB-GJ-PHASE4-SENSOR-FAIL-$stamp"
$failPython = @"
from apps.forensics.models import CaptureJob, Sensor, SensorCommand
from common.operations import capture_job_payload, create_capture_job, ensure_capture_case
sensor = Sensor.objects.get(id="$sensorId")
case = ensure_capture_case("$failCaseId", "Phase 4 Validator")
job = create_capture_job(
    case=case,
    mode=CaptureJob.Mode.LIVE_CAPTURE,
    sensor=sensor,
    interface_name="validation0",
    duration_seconds=5,
    packet_limit=100,
    chunk_interval_seconds=2,
    source_label=sensor.name,
)
SensorCommand.objects.create(sensor=sensor, capture_job=job, command_type="capture.start", payload_json=capture_job_payload(job))
print(job.id)
"@
$tmpFail = Join-Path ([System.IO.Path]::GetTempPath()) ("netra-phase4-sensor-fail-" + [guid]::NewGuid().ToString("N") + ".py")
try {
  [System.IO.File]::WriteAllText($tmpFail, $failPython, [System.Text.UTF8Encoding]::new($false))
  docker cp $tmpFail "${backendId}:/tmp/netra-phase4-sensor-fail.py" | Out-Null
  $failOutput = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py shell < /tmp/netra-phase4-sensor-fail.py"
} finally {
  Remove-Item -LiteralPath $tmpFail -Force -ErrorAction SilentlyContinue
}
$failJobId = ($failOutput | Select-Object -Last 1).Trim()
Invoke-RestMethod -Method Post -Uri "$api/sensors/$sensorId/captures/$failJobId/fail" -Headers $sensorHeaders -ContentType "application/json" -Body (@{ error = "validator forced sensor failure" } | ConvertTo-Json) | Out-Null
$failedStatus = Invoke-RestMethod -Uri "$api/capture/live/$failJobId/status"
if ($failedStatus.status -ne "failed" -or $failedStatus.error -notlike "*validator forced*") {
  throw "Sensor failure endpoint did not mark capture failed."
}
Write-Host "[PASS] sensor failure endpoint records clear failed capture status"

Write-Host "Phase 4 sensor validation passed." -ForegroundColor Green
