$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$outputRoot = Join-Path $repoRoot "docs\benchmarks"
$api = "http://localhost:8080/api"

Write-Host "Validating Phase 9 operational monitoring and incident readiness..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

python -m py_compile backend\common\readiness.py backend\apps\forensics\management\commands\validate_readiness_capabilities.py
Write-Host "[PASS] Phase 9 readiness modules compile"

$readiness = Invoke-RestMethod "$api/system/incident-readiness"
if (-not $readiness.status) { throw "Incident readiness endpoint did not return a status." }
if (-not $readiness.summary) { throw "Incident readiness endpoint did not return summary metrics." }
if (-not $readiness.checks) { throw "Incident readiness endpoint did not return readiness checks." }
Write-Host "[PASS] incident readiness API returns status, summary, and checks"

$deep = Invoke-RestMethod "$api/system/health/deep"
if (-not $deep.incidentReadiness) { throw "Deep health response is missing incidentReadiness." }
if (-not $deep.incidentReadiness.summary) { throw "Deep health incidentReadiness is missing summary metrics." }
Write-Host "[PASS] deep health includes incident readiness"

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$work = "/tmp/netra-phase9-operations"
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "rm -rf $work && mkdir -p $work/output" | Out-Null
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py validate_readiness_capabilities --mode operations --output-dir $work/output"
if ($LASTEXITCODE -ne 0) { throw "Phase 9 operations validation failed with exit code $LASTEXITCODE." }

$containerFiles = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "ls -1 $work/output"
foreach ($file in $containerFiles) {
  $name = $file.Trim()
  if ($name) { docker cp "${backendId}:$work/output/$name" (Join-Path $outputRoot $name) | Out-Null }
}

Write-Host "[PASS] Phase 9 validation artifact copied to docs\benchmarks"
Write-Host "Phase 9 operational readiness validation passed." -ForegroundColor Green
