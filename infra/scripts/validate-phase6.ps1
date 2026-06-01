$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8080/api"
$pcap = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
$caseId = "CYB-GJ-PHASE6-" + (Get-Date -Format "yyyyMMddHHmmss")

Write-Host "Validating Phase 6 trusted-LAN no-login operation..." -ForegroundColor Cyan

$deep = $null
for ($i = 1; $i -le 30; $i++) {
  try {
    $deep = Invoke-RestMethod "$api/system/health/deep"
    break
  } catch {
    Start-Sleep -Seconds 2
  }
}
if (-not $deep) { throw "Same-origin API did not become ready." }
if ($deep.access.mode -ne "trusted-lan") { throw "Expected trusted-lan access mode, got '$($deep.access.mode)'." }
if ($deep.access.authentication -ne "disabled") { throw "Authentication should be disabled in Phase 6 LAN mode." }
if ($deep.access.publicInternet -ne "not-supported") { throw "Public internet status should be not-supported." }
Write-Host "[PASS] system monitor reports Trusted LAN access mode"

$uploadJson = curl.exe -s `
  -F "caseId=$caseId" `
  -F "investigator=Local Investigator" `
  -F "packetLimit=5000" `
  -F "file=@$pcap" `
  "$api/evidence/upload"
$upload = $uploadJson | ConvertFrom-Json
if ($upload.error) { throw "Upload without auth headers failed: $($upload.error)" }
if (-not $upload.id -or -not $upload.jobId) { throw "Upload response missing evidence or job ID." }
Write-Host "[PASS] PCAP upload works without auth headers"

$job = Invoke-RestMethod "$api/jobs/$($upload.jobId)/status"
if ($job.status -ne "completed") { throw "Upload processing job did not complete." }
Write-Host "[PASS] processing job completed"

$matches = Invoke-RestMethod "$api/detection/matches?caseId=$caseId"
if ($matches.results.Count -lt 1) { throw "No detection match found for uploaded PCAP." }
$matchId = $matches.results[0].id
$updated = Invoke-RestMethod -Method Patch -Uri "$api/detection/matches/$matchId/status" -ContentType "application/json" -Body (@{status="confirmed"; caseId=$caseId} | ConvertTo-Json)
if ($updated.status -ne "confirmed") { throw "Detection review update failed without auth headers." }
Write-Host "[PASS] detection review works without auth headers"

$report = Invoke-RestMethod -Method Post -Uri "$api/reports/$caseId/generate" -ContentType "application/json" -Body (@{language="English"} | ConvertTo-Json)
if (-not $report.filename) { throw "Report generation failed without auth headers." }
Write-Host "[PASS] report generation works"

$export = Invoke-RestMethod -Method Post -Uri "$api/exports" -ContentType "application/json" -Body (@{type="Alert CSV"; caseId=$caseId} | ConvertTo-Json)
if (-not $export.filename) { throw "Export generation failed without auth headers." }
Write-Host "[PASS] export generation works"

$download = Invoke-WebRequest -UseBasicParsing -Uri "$api/evidence/$($upload.id)/download" -TimeoutSec 30
if ($download.StatusCode -ne 200 -or $download.RawContentLength -lt 1) { throw "Evidence download failed without auth headers." }
Write-Host "[PASS] evidence download works"

$logs = Invoke-RestMethod "$api/audit/access-logs"
$localOperatorLog = $logs.results | Where-Object { $_.user -eq "Local Investigator" -and $_.role -eq "LAN Operator" } | Select-Object -First 1
if (-not $localOperatorLog) { throw "Access logs did not record Local Investigator / LAN Operator." }
Write-Host "[PASS] audit log records Local Investigator / LAN Operator"

$replayJson = curl.exe -s `
  -F "caseId=$caseId-REPLAY" `
  -F "speed=max" `
  -F "chunkIntervalSeconds=5" `
  -F "packetLimit=5000" `
  -F "file=@$pcap" `
  "$api/capture/replay/start"
$replay = $replayJson | ConvertFrom-Json
if (-not $replay.jobId -or $replay.status -notin @("queued", "running")) { throw "Replay feed failed to start without auth headers." }
$completed = $false
for ($i = 1; $i -le 90; $i++) {
  Start-Sleep -Seconds 2
  $status = Invoke-RestMethod "$api/capture/replay/$($replay.jobId)/status"
  if ($status.status -eq "completed") { $completed = $true; break }
  if ($status.status -eq "failed") { throw "Replay failed: $($status.error)" }
}
if (-not $completed -or $status.chunksReceived -lt 1 -or -not $status.finalEvidenceId) { throw "Replay did not finalize immutable evidence." }
Write-Host "[PASS] replay works without auth headers"

$interfaces = Invoke-RestMethod "$api/capture/interfaces"
if ($null -eq $interfaces.results) { throw "Capture interface endpoint failed without auth headers." }
$onlineSensor = ($interfaces.results | Where-Object { $_.sensorId -and $_.status -eq "online" } | Select-Object -First 1)
if ($onlineSensor) {
  Write-Host "[INFO] Online sensor detected; native capture can be started from /app/upload without auth headers."
} else {
  Write-Host "[WARN] No online sensor registered; native capture browser smoke is skipped."
}

$healthAgain = Invoke-RestMethod "$api/system/health/deep"
if ($healthAgain.access.mode -ne "trusted-lan") { throw "Trusted LAN access mode changed during validation." }
Write-Host "[PASS] dev role headers are not required"

Write-Host "Phase 6 validation passed." -ForegroundColor Green
