param(
    [switch]$Logs,
    [int]$PostgresPort = 0
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot
$baseCompose = Join-Path $repoRoot "infra\docker\docker-compose.local-postgres.yml"
$opsCompose = Join-Path $repoRoot "infra\docker\docker-compose.ops.yml"

if ($PostgresPort -le 0 -and $env:NETRA_LOCAL_POSTGRES_PORT) {
    $PostgresPort = [int]$env:NETRA_LOCAL_POSTGRES_PORT
}
if ($PostgresPort -le 0) {
    $postgresProcessIds = @(Get-Process postgres -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    if ($postgresProcessIds.Count -gt 0) {
        $listener = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.OwningProcess -in $postgresProcessIds } |
            Sort-Object LocalPort |
            Select-Object -First 1
        if ($listener) {
            $PostgresPort = [int]$listener.LocalPort
        }
    }
}
if ($PostgresPort -le 0) {
    $PostgresPort = 5432
}
$env:NETRA_LOCAL_POSTGRES_PORT = "$PostgresPort"

Write-Host "Starting Netra laptop operations stack..." -ForegroundColor Cyan
Write-Host "Native PostgreSQL: netra@localhost:$PostgresPort"
Write-Host "Console: http://localhost:8080"

docker compose -f $baseCompose -f $opsCompose up --build -d --remove-orphans

$ready = $false
for ($i = 1; $i -le 60; $i++) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8080/api/health" -TimeoutSec 3
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

docker compose -f $baseCompose -f $opsCompose ps
if ($ready) {
    Write-Host "Netra is ready." -ForegroundColor Green
} else {
    Write-Host "Containers started, but the same-origin API health check is not ready." -ForegroundColor Yellow
}
Write-Host "Evidence intake: http://localhost:8080/app/upload"
Write-Host "System monitor:  http://localhost:8080/app/system"
Write-Host "Sensor setup:    npm run netra:sensor:install"
Write-Host "Sensor start:    npm run netra:sensor:start"

if ($Logs) {
    docker compose -f $baseCompose -f $opsCompose logs -f --tail=120
}
