$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$outputRoot = Join-Path $repoRoot "docs\benchmarks"

Write-Host "Validating Phase 10 legal evidence and compliance readiness..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

python -m py_compile backend\common\readiness.py backend\common\artifacts.py backend\apps\forensics\views.py backend\apps\forensics\management\commands\validate_readiness_capabilities.py
Write-Host "[PASS] Phase 10 legal-readiness modules compile"

$docPath = Join-Path $repoRoot "docs\production-monitoring-legal-readiness.md"
if (-not (Test-Path $docPath)) { throw "Missing legal readiness operations document: $docPath" }
Write-Host "[PASS] production monitoring/legal readiness document exists"

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$work = "/tmp/netra-phase10-legal"
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "rm -rf $work && mkdir -p $work/output" | Out-Null
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py validate_readiness_capabilities --mode legal --output-dir $work/output"
if ($LASTEXITCODE -ne 0) { throw "Phase 10 legal validation failed with exit code $LASTEXITCODE." }

$containerFiles = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "ls -1 $work/output"
foreach ($file in $containerFiles) {
  $name = $file.Trim()
  if ($name) { docker cp "${backendId}:$work/output/$name" (Join-Path $outputRoot $name) | Out-Null }
}

Write-Host "[PASS] Phase 10 validation artifact copied to docs\benchmarks"
Write-Host "Phase 10 legal evidence readiness validation passed." -ForegroundColor Green
