$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$pcapRoot = Join-Path $repoRoot "samples\pcaps"
$outputRoot = Join-Path $repoRoot "docs\benchmarks"

Write-Host "Validating Phase 7 DPI metadata findings..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

python -m py_compile backend\common\analysis.py backend\apps\forensics\management\commands\validate_analysis_capabilities.py
Write-Host "[PASS] DPI analysis modules compile"

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$work = "/tmp/netra-phase7-dpi"
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "rm -rf $work && mkdir -p $work/pcaps $work/output" | Out-Null

foreach ($pcap in @("hydra_ftp.pcap", "smtp.pcap")) {
  $source = Join-Path $pcapRoot $pcap
  if (-not (Test-Path $source)) { throw "Missing DPI validation PCAP: $source" }
  docker cp $source "${backendId}:$work/pcaps/$pcap" | Out-Null
}
Write-Host "[PASS] DPI validation PCAPs copied into backend container"

docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py validate_analysis_capabilities --mode dpi --pcap-root $work/pcaps --output-dir $work/output"
if ($LASTEXITCODE -ne 0) { throw "Phase 7 DPI validation failed with exit code $LASTEXITCODE." }

$containerFiles = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "ls -1 $work/output"
foreach ($file in $containerFiles) {
  $name = $file.Trim()
  if ($name) { docker cp "${backendId}:$work/output/$name" (Join-Path $outputRoot $name) | Out-Null }
}

Write-Host "[PASS] Phase 7 DPI metadata findings validated"
Write-Host "Phase 7 DPI validation passed." -ForegroundColor Green
