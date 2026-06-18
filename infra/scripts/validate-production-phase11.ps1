$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8080/api"
$prodCompose = Join-Path $repoRoot "infra\docker\docker-compose.supabase.production.yml"
$prodExample = Join-Path $repoRoot ".env.supabase.production.example"
$doc = Join-Path $repoRoot "docs\production-deployment-readiness.md"
$checklist = Join-Path $repoRoot "docs\release-checklist.md"

Write-Host "Validating Phase 11 deployment readiness..." -ForegroundColor Cyan

python -m py_compile backend\common\cors.py backend\common\readiness.py backend\apps\forensics\views.py
Write-Host "[PASS] deployment readiness modules compile"

foreach ($path in @($prodCompose, $prodExample, $doc, $checklist)) {
  if (-not (Test-Path $path)) { throw "Missing required Phase 11 artifact: $path" }
}
Write-Host "[PASS] production compose, env template, and release docs exist"

$services = docker compose -f $prodCompose --env-file $prodExample config --services
foreach ($legacy in @("postgres", "kafka", "elasticsearch")) {
  if ($services -contains $legacy) { throw "Production compose must not define local $legacy service." }
}
if ($services -notcontains "frontend" -or $services -notcontains "backend") {
  throw "Production compose must define frontend and backend services."
}
Write-Host "[PASS] production compose excludes local PostgreSQL, Kafka, and Elasticsearch"

$config = docker compose -f $prodCompose --env-file $prodExample config
if ($config -match 'published: "?8000"?') {
  throw "Production compose must not publish backend port 8000 directly."
}
if ($config -match 'DJANGO_DEBUG: "?1"?') {
  throw "Production compose must force DJANGO_DEBUG=0."
}
Write-Host "[PASS] production compose keeps backend internal and disables Django debug"

$frontendPaths = @(
  (Join-Path $repoRoot "frontend\src"),
  (Join-Path $repoRoot "frontend\dist")
) | Where-Object { Test-Path $_ }
foreach ($path in $frontendPaths) {
  $matches = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | Select-String -Pattern "SUPABASE_SERVICE_ROLE_KEY|service_role" -ErrorAction SilentlyContinue
  if ($matches) { throw "Frontend contains service-role reference in $path" }
}
Write-Host "[PASS] frontend source/build contains no service-role references"

$health = Invoke-RestMethod "$api/health"
if ($health.status -ne "ok") { throw "Current API health is not ok." }
$deployment = Invoke-RestMethod "$api/system/deployment-readiness"
if (-not $deployment.status -or -not $deployment.checks) { throw "Deployment readiness endpoint did not return status/checks." }
if ($deployment.status -eq "blocked") {
  Write-Host "[WARN] Current running stack is not production-ready yet: $($deployment.requiredFailures -join ', ')" -ForegroundColor Yellow
} else {
  Write-Host "[PASS] current running stack deployment readiness is $($deployment.status)"
}

$deep = Invoke-RestMethod "$api/system/health/deep"
if (-not $deep.incidentReadiness) { throw "Deep health is missing incident readiness." }
Write-Host "[PASS] deep health still includes incident readiness"

Write-Host "Phase 11 deployment readiness validation passed." -ForegroundColor Green
