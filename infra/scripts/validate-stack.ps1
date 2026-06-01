$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.yml"
Set-Location $repoRoot

Write-Host "Checking Netra containers..." -ForegroundColor Cyan
docker compose -f $composeFile ps

Write-Host ""
Write-Host "Checking backend health..." -ForegroundColor Cyan
Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8000/api/health" -TimeoutSec 5

Write-Host ""
Write-Host "Checking dashboard summary..." -ForegroundColor Cyan
Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8000/api/dashboard/summary" -TimeoutSec 5

Write-Host ""
Write-Host "Netra validation checks completed." -ForegroundColor Green
