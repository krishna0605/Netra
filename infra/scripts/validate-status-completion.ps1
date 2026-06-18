$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8080/api"

Write-Host "Validating Netra feature status matrix and completion endpoints..." -ForegroundColor Cyan

python -m py_compile backend\common\readiness.py backend\apps\forensics\views.py ml-services\anomaly-engine\netra_ml\modeling.py
Write-Host "[PASS] status and ML modules compile"

$health = Invoke-RestMethod "$api/health"
if ($health.status -ne "ok") { throw "API health is not ok." }

$matrix = Invoke-RestMethod "$api/system/status-matrix"
if (-not $matrix.results -or $matrix.results.Count -lt 15) { throw "Status matrix did not return the expected feature rows." }
$required = @("Supabase Storage", "PCAP upload analysis", "AI anomaly detection", "Sensor capture", "Production readiness")
foreach ($name in $required) {
  $row = $matrix.results | Where-Object { $_.area -eq $name } | Select-Object -First 1
  if (-not $row) { throw "Status matrix is missing area: $name" }
  if (-not $row.targetStatus) { throw "Status matrix row has no target status: $name" }
}
Write-Host "[PASS] status matrix contains core feature rows"

$ml = Invoke-RestMethod "$api/ml/model-status"
if (-not $ml.status) { throw "ML model status did not return a status." }
Write-Host "[PASS] ML model status endpoint is reachable: $($ml.status)"

$deployment = Invoke-RestMethod "$api/system/deployment-readiness"
if (-not $deployment.status) { throw "Deployment readiness endpoint did not return a status." }
Write-Host "[PASS] deployment readiness endpoint is reachable: $($deployment.status)"

$reportRoot = Join-Path $repoRoot "docs\benchmarks"
New-Item -ItemType Directory -Force -Path $reportRoot | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$jsonReport = Join-Path $reportRoot "netra-status-matrix-$stamp.json"
$mdReport = Join-Path $reportRoot "netra-status-matrix-$stamp.md"

$reportPayload = [ordered]@{
  generatedAt = (Get-Date).ToUniversalTime().ToString("o")
  apiBase = $api
  health = $health
  statusMatrix = $matrix
  mlModelStatus = $ml
  deploymentReadiness = $deployment
}
$reportPayload | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonReport -Encoding UTF8

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# Netra Feature Status Matrix")
$lines.Add("")
$lines.Add("Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))")
$lines.Add("")
$lines.Add("## Summary")
$lines.Add("")
$lines.Add("- API health: $($health.status)")
$lines.Add("- Matrix rows: $($matrix.results.Count)")
$lines.Add("- ML status: $($ml.status)")
$lines.Add("- Deployment readiness: $($deployment.status)")
$lines.Add("")
$lines.Add("## Feature Status")
$lines.Add("")
$lines.Add("| Area | Current Status | Target Status | Validation | Notes |")
$lines.Add("|---|---|---|---|---|")
foreach ($row in $matrix.results) {
  $notes = ""
  if ($row.notes) { $notes = ($row.notes -join "; ") }
  $safeNotes = $notes.Replace("|", "\|")
  $lines.Add("| $($row.area) | $($row.currentStatus) | $($row.targetStatus) | $($row.validation) | $safeNotes |")
}
$lines.Add("")
$lines.Add("## ML Model")
$lines.Add("")
$lines.Add("- Status: $($ml.status)")
$lines.Add("- Model available: $($ml.modelAvailable)")
$lines.Add("- Version: $($ml.version)")
$lines.Add("- Model type: $($ml.modelType)")
$lines.Add("- Training rows: $($ml.trainingRows)")
$lines.Add("")
$lines.Add("## Deployment Readiness")
$lines.Add("")
$lines.Add("- Status: $($deployment.status)")
if ($deployment.blockers) {
  $lines.Add("- Blockers: $($deployment.blockers -join "; ")")
}
$lines | Set-Content -Path $mdReport -Encoding UTF8

Write-Host "[PASS] status reports written:"
Write-Host "       $jsonReport"
Write-Host "       $mdReport"

Write-Host "Feature status completion validation passed." -ForegroundColor Green
