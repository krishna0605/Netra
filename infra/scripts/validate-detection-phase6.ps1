$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$manifest = Join-Path $repoRoot "samples\detection-benchmark-manifest.json"
$pcapRoot = Join-Path $repoRoot "samples\pcaps"
$outputRoot = Join-Path $repoRoot "docs\benchmarks"

Write-Host "Validating Phase 6 detection and anomaly benchmarking..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}
if (-not (Test-Path $manifest)) {
  throw "Benchmark manifest missing: $manifest"
}
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

python -m py_compile `
  backend\apps\forensics\management\commands\benchmark_detection.py `
  backend\common\analysis.py `
  ml-services\anomaly-engine\netra_ml\features.py `
  ml-services\anomaly-engine\netra_ml\scoring.py `
  ml-services\anomaly-engine\netra_ml\explanations.py
Write-Host "[PASS] detection benchmark and ML modules compile"

$work = "/tmp/netra-phase6-benchmark"
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "rm -rf $work && mkdir -p $work/pcaps $work/output" | Out-Null
docker cp $manifest "${backendId}:$work/manifest.json" | Out-Null

$manifestJson = Get-Content $manifest -Raw | ConvertFrom-Json
foreach ($case in $manifestJson.cases) {
  $source = Join-Path $pcapRoot $case.file
  if (-not (Test-Path $source)) { throw "Missing benchmark PCAP: $source" }
  docker cp $source "${backendId}:$work/pcaps/$($case.file)" | Out-Null
}
Write-Host "[PASS] benchmark corpus copied into backend container"

docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py benchmark_detection --manifest $work/manifest.json --pcap-root $work/pcaps --output-dir $work/output --fail-under-f1 0.40"
if ($LASTEXITCODE -ne 0) { throw "Detection benchmark failed with exit code $LASTEXITCODE." }

$containerFiles = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "ls -1 $work/output"
$jsonFile = ($containerFiles | Where-Object { $_ -like "*.json" } | Select-Object -Last 1).Trim()
$mdFile = ($containerFiles | Where-Object { $_ -like "*.md" } | Select-Object -Last 1).Trim()
if (-not $jsonFile -or -not $mdFile) { throw "Benchmark output files were not generated." }
docker cp "${backendId}:$work/output/$jsonFile" (Join-Path $outputRoot $jsonFile) | Out-Null
docker cp "${backendId}:$work/output/$mdFile" (Join-Path $outputRoot $mdFile) | Out-Null

$result = Get-Content (Join-Path $outputRoot $jsonFile) -Raw | ConvertFrom-Json
if ($result.caseCount -lt 4) { throw "Benchmark evaluated too few cases." }
if ($result.metrics.f1 -lt 0.40) { throw "Benchmark F1 below expected smoke threshold." }
Write-Host "[PASS] benchmark metrics generated: precision=$($result.metrics.precision) recall=$($result.metrics.recall) f1=$($result.metrics.f1)"
Write-Host "[PASS] reports saved to docs/benchmarks/$jsonFile and docs/benchmarks/$mdFile"

Write-Host "Phase 6 detection benchmark validation passed." -ForegroundColor Green
