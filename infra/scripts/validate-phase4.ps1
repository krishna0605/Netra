$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8000/api"
$pcap = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
$caseId = "CYB-GJ-PHASE4-" + (Get-Date -Format "yyyyMMddHHmmss")

Write-Host "Validating Phase 4 real-PCAP local workflow..." -ForegroundColor Cyan

function Wait-NetraJob([string]$jobId) {
  for ($i = 1; $i -le 120; $i++) {
    $job = Invoke-RestMethod "$api/jobs/$jobId/status"
    if ($job.status -eq "completed") { return $job }
    if ($job.status -eq "failed") { throw "Processing job $jobId failed." }
    Start-Sleep -Seconds 2
  }
  throw "Processing job $jobId did not complete in time."
}

$health = Invoke-RestMethod "$api/health"
if ($health.status -ne "ok") { throw "API health check failed." }
Write-Host "[PASS] API health is ok"

$removedDemoStatus = curl.exe -s -o NUL -w "%{http_code}" "$api/demo/scenario"
if ($removedDemoStatus -ne "404") { throw "Legacy demo endpoint should be removed, received HTTP $removedDemoStatus." }
Write-Host "[PASS] legacy demo endpoint is removed"

$uploadJson = curl.exe -s `
  -F "caseId=$caseId" `
  -F "investigator=Local Investigator" `
  -F "department=Gujarat Cyber Crime Cell" `
  -F "priority=Standard" `
  -F "packetLimit=5000" `
  -F "durationSeconds=300" `
  -F "bpfFilter=tcp port 22" `
  -F "file=@$pcap" `
  "$api/evidence/upload"
$upload = $uploadJson | ConvertFrom-Json
if ($upload.error) { throw "Real PCAP upload failed: $($upload.error)" }
if (-not $upload.id -or -not $upload.jobId -or -not $upload.sha256) { throw "Upload response missing evidence, job, or hash fields." }
Write-Host "[PASS] real PCAP upload creates evidence $($upload.id)"

$cases = Invoke-RestMethod "$api/cases"
$matchingCase = $cases.results | Where-Object { $_.id -eq $caseId } | Select-Object -First 1
if (-not $matchingCase) { throw "Uploaded case was not returned from /api/cases." }
Write-Host "[PASS] uploaded case appears in PostgreSQL-backed API"

$manifest = Invoke-RestMethod "$api/evidence/$($upload.id)/manifest"
if (-not $manifest.manifestHash) { throw "Evidence manifest missing." }
Write-Host "[PASS] encrypted evidence manifest exists"

$job = Wait-NetraJob $upload.jobId
if ($job.status -ne "completed") { throw "Processing job should be completed." }
Write-Host "[PASS] processing job completed"

$ledger = Invoke-RestMethod "$api/cases/$caseId/custody-ledger"
if ($ledger.count -lt 3 -or -not $ledger.verification.verified) { throw "Custody ledger missing expected events or failed verification." }
Write-Host "[PASS] custody ledger rows exist and verify"

$alerts = Invoke-RestMethod "$api/alerts?caseId=$caseId"
if (($alerts.results | Measure-Object).Count -lt 1) { throw "Expected hydra_ssh.pcap to create alert rows." }
Write-Host "[PASS] alert rows were generated from uploaded evidence"

$database = Invoke-RestMethod "$api/system/database"
if ([int]$database.tables -lt 1) { throw "Database endpoint did not report tables." }
Write-Host "[PASS] database endpoint reports $($database.mode) with $($database.tables) tables"

Write-Host "Phase 4 validation passed." -ForegroundColor Green
