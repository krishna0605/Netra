$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8080/api"
$sourcePcap = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
$renamedPcap = Join-Path $env:TEMP ("capture-" + [guid]::NewGuid().ToString("N") + ".pcap")
$caseId = "CYB-GJ-PHASE5-" + (Get-Date -Format "yyyyMMddHHmmss")

Write-Host "Validating Phase 5 operational truth..." -ForegroundColor Cyan

$health = $null
for ($i = 1; $i -le 30; $i++) {
    try {
        $health = Invoke-RestMethod "$api/health"
        break
    } catch {
        Start-Sleep -Seconds 2
    }
}
if (-not $health) { throw "Same-origin API did not become ready." }
if ($health.status -ne "ok") { throw "API health check failed." }
Write-Host "[PASS] same-origin API responds"

Copy-Item -LiteralPath $sourcePcap -Destination $renamedPcap
try {
    $uploadJson = curl.exe -s `
      -F "caseId=$caseId" `
      -F "packetLimit=5000" `
      -F "file=@$renamedPcap" `
      "$api/evidence/upload"
    $upload = $uploadJson | ConvertFrom-Json
    if ($upload.error) { throw "Renamed evidence upload failed: $($upload.error)" }
} finally {
    Remove-Item -LiteralPath $renamedPcap -Force -ErrorAction SilentlyContinue
}
Write-Host "[PASS] renamed PCAP uploads without filename coupling"

$alerts = Invoke-RestMethod "$api/alerts?caseId=$caseId"
$brute = $alerts.results | Where-Object { $_.attackClass -eq "Credential Brute Force" } | Select-Object -First 1
if (-not $brute) { throw "Expected evidence-based SSH brute force finding after renamed upload." }
if ($brute.detectorType -ne "behavior-rule" -or -not $brute.observedSignals) { throw "Alert provenance fields are missing." }
Write-Host "[PASS] classification uses observed behavior signals"

$integrity = Invoke-RestMethod "$api/evidence/$($upload.id)/verify-integrity" -Method Post
if (-not $integrity.verified -or -not $integrity.encryptedArtifactVerified -or -not $integrity.manifestVerified) { throw "Integrity verification did not re-hash stored encrypted evidence." }
Write-Host "[PASS] encrypted evidence bytes and manifest verify"

$deep = Invoke-RestMethod "$api/system/health/deep"
if (-not $deep.checks.postgres.status -or -not $deep.checks.storage.status -or -not $deep.checks.encryption.status) { throw "Deep health probe response is incomplete." }
Write-Host "[PASS] deep health returns real probe details"

$workers = Invoke-RestMethod "$api/system/workers"
if (($workers.results | Measure-Object).Count -lt 7) { throw "Worker heartbeat endpoint is incomplete." }
Write-Host "[PASS] worker heartbeat endpoint reports expected services"

$replayJson = curl.exe -s `
  -F "caseId=$caseId-REPLAY" `
  -F "speed=max" `
  -F "chunkIntervalSeconds=5" `
  -F "packetLimit=5000" `
  -F "file=@$sourcePcap" `
  "$api/capture/replay/start"
$replay = $replayJson | ConvertFrom-Json
if (-not $replay.jobId -or $replay.status -notin @("queued", "running")) { throw "Real replay did not start." }
Write-Host "[PASS] real replay feed queued"

$completed = $false
for ($i = 1; $i -le 90; $i++) {
    Start-Sleep -Seconds 2
    $status = Invoke-RestMethod "$api/capture/replay/$($replay.jobId)/status"
    if ($status.status -eq "completed") {
        $completed = $true
        break
    }
    if ($status.status -eq "failed") { throw "Replay failed: $($status.error)" }
}
if (-not $completed) { throw "Replay did not complete within the validation window." }
if ($status.chunksReceived -lt 1 -or -not $status.finalEvidenceId) { throw "Replay did not create chunks and finalized evidence." }
Write-Host "[PASS] replay finalized encrypted immutable evidence"

$events = Invoke-RestMethod "$api/events?captureJobId=$($replay.jobId)"
if (($events.results | Measure-Object).Count -lt 3) { throw "Replay operational event outbox is incomplete." }
Write-Host "[PASS] persisted operational events are available for SSE"

Write-Host "Phase 5 validation passed." -ForegroundColor Green
