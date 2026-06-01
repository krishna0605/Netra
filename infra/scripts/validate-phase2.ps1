$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8000/api"
$pcap = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
$caseId = "CYB-GJ-PHASE2-HYDRA"

Write-Host "Validating Phase 2 persistence, search, audit, and trusted-LAN workflows..."

$health = Invoke-RestMethod "$api/health"
if (-not $health.packetTools.tshark) { throw "tshark is unavailable." }
if (-not $health.packetTools.zeek) { throw "zeek is unavailable." }

$uploadJson = curl.exe -s -F "caseId=$caseId" -F "file=@$pcap" "$api/evidence/upload"
$upload = $uploadJson | ConvertFrom-Json
if ($upload.error) { throw "Upload failed: $($upload.error)" }
if ($upload.analysis.topAttackClass -ne "Credential Brute Force") { throw "Unexpected class: $($upload.analysis.topAttackClass)" }
Write-Host "[PASS] upload persisted job $($upload.jobId)"

$job = Invoke-RestMethod "$api/jobs/$($upload.jobId)/status"
if ($job.status -ne "completed" -or $job.progress -ne 100) { throw "Job did not complete." }
Write-Host "[PASS] job status completed"

$cases = Invoke-RestMethod "$api/cases"
if (-not ($cases.results | Where-Object { $_.id -eq $caseId })) { throw "Persisted case missing from /cases." }
Write-Host "[PASS] persisted case visible"

$packets = Invoke-RestMethod "$api/packets?caseId=$caseId&protocol=SSH"
if ($packets.count -lt 1) { throw "No packet results for case/protocol filter." }
Write-Host "[PASS] packet search returned $($packets.count) rows via $($packets.searchBackend)"

$search = Invoke-RestMethod "$api/search?q=ssh&caseId=$caseId&type=packets"
if ($search.count -lt 1) { throw "Global search did not return SSH evidence." }
Write-Host "[PASS] search returned $($search.count) rows via $($search.searchBackend)"

$matches = Invoke-RestMethod "$api/detection/matches?caseId=$caseId"
if ($matches.results.Count -lt 1) { throw "No detection matches persisted." }
$matchId = $matches.results[0].id
$status = Invoke-RestMethod -Method Patch -Uri "$api/detection/matches/$matchId/status" -ContentType "application/json" -Body (@{status="confirmed"; caseId=$caseId} | ConvertTo-Json)
if ($status.status -ne "confirmed") { throw "Could not confirm detection match." }
Write-Host "[PASS] trusted LAN operator confirmed alert"

$report = Invoke-RestMethod -Method Post -Uri "$api/reports/$caseId/generate" -ContentType "application/json" -Body (@{language="English"} | ConvertTo-Json)
if (-not $report.filename) { throw "Report generation failed." }
Write-Host "[PASS] report generated $($report.filename)"

$export = Invoke-RestMethod -Method Post -Uri "$api/exports" -ContentType "application/json" -Body (@{type="Alert CSV"; caseId=$caseId} | ConvertTo-Json)
if (-not $export.filename) { throw "Export generation failed." }
Write-Host "[PASS] export generated $($export.filename)"

$logs = Invoke-RestMethod "$api/audit/access-logs"
if ($logs.results.Count -lt 1) { throw "Access logs are empty." }
Write-Host "[PASS] audit logs available"

$workers = Invoke-RestMethod "$api/system/workers"
if ($workers.results.Count -lt 7) { throw "Worker status is incomplete." }
Write-Host "[PASS] worker status available"

$replayJson = curl.exe -s -F "caseId=CYB-GJ-LIVE-0001" -F "speed=max" -F "chunkIntervalSeconds=5" -F "packetLimit=5000" -F "file=@$pcap" "$api/capture/replay/start"
$replay = $replayJson | ConvertFrom-Json
if (-not $replay.jobId -or $replay.status -notin @("queued", "running")) { throw "Replay feed did not start." }
$replayCompleted = $false
for ($i = 1; $i -le 90; $i++) {
  Start-Sleep -Seconds 2
  $replayStatus = Invoke-RestMethod "$api/capture/replay/$($replay.jobId)/status"
  if ($replayStatus.status -eq "completed") { $replayCompleted = $true; break }
  if ($replayStatus.status -eq "failed") { throw "Replay failed: $($replayStatus.error)" }
}
if (-not $replayCompleted -or $replayStatus.chunksReceived -lt 1 -or -not $replayStatus.finalEvidenceId) { throw "Replay did not finalize immutable evidence." }
Write-Host "[PASS] real replay feed works"

Write-Host "Phase 2 validation passed."
