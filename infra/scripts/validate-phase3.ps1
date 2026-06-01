$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8000/api"
$pcap = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
$caseId = "CYB-GJ-PHASE3-HYDRA"

Write-Host "Validating Phase 3 vault, custody, operations, integrations, and safety in no-login mode..." -ForegroundColor Cyan

$uploadJson = curl.exe -s -F "caseId=$caseId" -F "file=@$pcap" "$api/evidence/upload"
$upload = $uploadJson | ConvertFrom-Json
if ($upload.error) { throw "Upload failed: $($upload.error)" }
if (-not $upload.encrypted_sha256) { throw "Encrypted artifact hash missing from upload." }
Write-Host "[PASS] upload encrypted evidence $($upload.id)"

$manifest = Invoke-RestMethod -Uri "$api/evidence/$($upload.id)/manifest"
if (-not $manifest.manifest.manifestHash) { throw "Evidence manifest missing hash." }
Write-Host "[PASS] evidence manifest available"

$integrity = Invoke-RestMethod -Method Post -Uri "$api/evidence/$($upload.id)/verify-integrity"
if (-not $integrity.verified) { throw "Evidence integrity verification failed." }
Write-Host "[PASS] evidence integrity verified"

$download = Invoke-WebRequest -UseBasicParsing -Uri "$api/evidence/$($upload.id)/download" -TimeoutSec 30
if ($download.StatusCode -ne 200 -or $download.RawContentLength -lt 1) { throw "Evidence download failed in trusted local mode." }
Write-Host "[PASS] evidence download works without auth headers"

$ledger = Invoke-RestMethod "$api/cases/$caseId/custody-ledger"
if (-not $ledger.verification.verified -or $ledger.count -lt 1) { throw "Custody ledger did not verify." }
Write-Host "[PASS] custody ledger verified"

$matches = Invoke-RestMethod "$api/detection/matches?caseId=$caseId"
if ($matches.results.Count -lt 1) { throw "No detection match available to confirm." }
$matchId = $matches.results[0].id
$confirm = Invoke-RestMethod -Method Patch -Uri "$api/detection/matches/$matchId/status" -ContentType "application/json" -Body (@{status="confirmed"; caseId=$caseId} | ConvertTo-Json)
if ($confirm.status -ne "confirmed") { throw "Detection confirmation failed." }
Write-Host "[PASS] alert confirmation works without auth headers"

$report = Invoke-RestMethod -Method Post -Uri "$api/reports/$caseId/generate" -ContentType "application/json" -Body (@{language="English"} | ConvertTo-Json)
if (-not $report.encrypted_sha256) { throw "Encrypted report artifact hash missing." }
Write-Host "[PASS] encrypted report generated"

$export = Invoke-RestMethod -Method Post -Uri "$api/exports" -ContentType "application/json" -Body (@{type="Evidence JSON"; caseId=$caseId} | ConvertTo-Json)
if (-not $export.encrypted_sha256) { throw "Encrypted export artifact hash missing." }
Write-Host "[PASS] encrypted evidence export generated"

$deep = Invoke-RestMethod "$api/system/health/deep"
if ($deep.status -ne "ok" -and $deep.status -ne "degraded") { throw "Deep health returned unexpected status $($deep.status)." }
Write-Host "[PASS] deep health reachable"

$dlq = Invoke-RestMethod "$api/system/dead-letter"
if ($null -eq $dlq.results) { throw "Dead-letter endpoint failed." }
Write-Host "[PASS] dead-letter endpoint reachable"

$siem = Invoke-RestMethod -Method Post -Uri "$api/integrations/siem/export" -ContentType "application/json" -Body (@{caseId=$caseId} | ConvertTo-Json)
if (-not $siem.filename) { throw "SIEM export failed." }
Write-Host "[PASS] SIEM export generated"

$packets = Invoke-RestMethod "$api/packets?caseId=$caseId&limit=5&offset=0"
if ($packets.limit -ne 5 -or $packets.results.Count -lt 1) { throw "Packet pagination failed." }
Write-Host "[PASS] packet pagination works"

$replayJson = curl.exe -s -F "caseId=CYB-GJ-PHASE3-LIVE" -F "speed=max" -F "chunkIntervalSeconds=5" -F "packetLimit=5000" -F "file=@$pcap" "$api/capture/replay/start"
$replay = $replayJson | ConvertFrom-Json
if (-not $replay.jobId -or $replay.status -notin @("queued", "running")) { throw "Replay feed failed to start." }
$replayCompleted = $false
for ($i = 1; $i -le 90; $i++) {
  Start-Sleep -Seconds 2
  $replayStatus = Invoke-RestMethod "$api/capture/replay/$($replay.jobId)/status"
  if ($replayStatus.status -eq "completed") { $replayCompleted = $true; break }
  if ($replayStatus.status -eq "failed") { throw "Replay failed: $($replayStatus.error)" }
}
if (-not $replayCompleted -or $replayStatus.chunksReceived -lt 1 -or -not $replayStatus.finalEvidenceId) { throw "Replay feed did not finalize immutable evidence." }
Write-Host "[PASS] real replay mode works"

Write-Host "Phase 3 validation passed." -ForegroundColor Green
