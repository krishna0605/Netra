param(
    [switch]$Logs,
    [int]$PostgresPort = 0
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
Set-Location $repoRoot
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.local-postgres.yml"

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

Write-Host ""
Write-Host "Starting Netra with native Windows PostgreSQL..." -ForegroundColor Cyan
Write-Host "Database: netra@localhost:$PostgresPort via host.docker.internal"
Write-Host "Docker services: frontend, backend, elasticsearch, kafka, workers"
Write-Host ""

if (Get-Command pg_isready -ErrorAction SilentlyContinue) {
    $ready = & pg_isready -h localhost -p $PostgresPort -U netra -d netra
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Native PostgreSQL is not ready for netra/netra on localhost:$PostgresPort." -ForegroundColor Yellow
        Write-Host "Create the database first, then run this command again."
        Write-Host "See docs\local-postgres-setup.md"
        exit 1
    }
} else {
    Write-Host "pg_isready was not found. Continuing; Docker will fail clearly if PostgreSQL is unavailable." -ForegroundColor Yellow
}

docker compose -f $composeFile up --build -d --remove-orphans

Write-Host ""
Write-Host "Waiting for Django API health..." -ForegroundColor Cyan
$healthUrl = "http://localhost:8000/api/health"
$ready = $false
for ($i = 1; $i -le 60; $i++) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 3
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

Write-Host ""
docker compose -f $composeFile ps

Write-Host ""
if ($ready) {
    Write-Host "Netra is ready with local PostgreSQL." -ForegroundColor Green
} else {
    Write-Host "Containers started, but the API health check did not respond yet." -ForegroundColor Yellow
    Write-Host "Run 'npm run netra:logs' to inspect startup logs."
}

Write-Host ""
Write-Host "Open these URLs:" -ForegroundColor Cyan
Write-Host "  Frontend:        http://localhost:8080"
Write-Host "  Evidence intake: http://localhost:8080/app/upload"
Write-Host "  Backend API:     http://localhost:8000/api/health"
Write-Host "  Database status: http://localhost:8000/api/system/database"
Write-Host "  Elasticsearch:   http://localhost:9200"
Write-Host ""
Write-Host "pgAdmin connection:" -ForegroundColor Cyan
Write-Host "  Host: localhost"
Write-Host "  Port: $PostgresPort"
Write-Host "  Database: netra"
Write-Host "  Username: netra"
Write-Host "  Password: netra"
Write-Host ""

if ($Logs) {
    docker compose -f $composeFile logs -f --tail=120
}
