$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$pcapRoot = Join-Path $repoRoot "samples\pcaps"
$outputRoot = Join-Path $repoRoot "docs\benchmarks"

Write-Host "Validating Phase 8 large-PCAP completeness markers..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

python -m py_compile backend\common\analysis.py backend\apps\forensics\management\commands\validate_analysis_capabilities.py
Write-Host "[PASS] large-PCAP analysis modules compile"

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$work = "/tmp/netra-phase8-large-pcap"
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "rm -rf $work && mkdir -p $work/pcaps $work/output" | Out-Null

$source = Join-Path $pcapRoot "normal2.pcap"
if (-not (Test-Path $source)) { throw "Missing large-PCAP validation file: $source" }
docker cp $source "${backendId}:$work/pcaps/normal2.pcap" | Out-Null
Write-Host "[PASS] large-PCAP validation file copied into backend container"

docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py validate_analysis_capabilities --mode large --pcap-root $work/pcaps --output-dir $work/output"
if ($LASTEXITCODE -ne 0) { throw "Phase 8 large-PCAP validation failed with exit code $LASTEXITCODE." }

$containerFiles = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "ls -1 $work/output"
foreach ($file in $containerFiles) {
  $name = $file.Trim()
  if ($name) { docker cp "${backendId}:$work/output/$name" (Join-Path $outputRoot $name) | Out-Null }
}

Write-Host "[PASS] Phase 8 capped metadata indexing and completeness markers validated"
Write-Host "Phase 8 large-PCAP validation passed." -ForegroundColor Green
