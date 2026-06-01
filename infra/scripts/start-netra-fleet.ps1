param([switch]$Logs, [int]$PostgresPort = 0)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot
$base = Join-Path $repoRoot "infra\docker\docker-compose.local-postgres.yml"
$lan = Join-Path $repoRoot "infra\docker\docker-compose.lan.yml"
$fleet = Join-Path $repoRoot "infra\docker\docker-compose.fleet.yml"

if ($PostgresPort -le 0 -and $env:NETRA_LOCAL_POSTGRES_PORT) { $PostgresPort = [int]$env:NETRA_LOCAL_POSTGRES_PORT }
if ($PostgresPort -le 0) {
  $postgresIds = @(Get-Process postgres -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
  $listener = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -in $postgresIds } |
    Sort-Object LocalPort |
    Select-Object -First 1
  if ($listener) { $PostgresPort = [int]$listener.LocalPort }
}
if ($PostgresPort -le 0) { $PostgresPort = 5432 }
$env:NETRA_LOCAL_POSTGRES_PORT = "$PostgresPort"

Write-Host "Starting Netra Phase 7 fleet stack..." -ForegroundColor Cyan
Write-Host "Native PostgreSQL: netra@localhost:$PostgresPort"
docker compose -f $base -f $lan -f $fleet up --build -d --remove-orphans --scale parser-worker=2

for ($i = 1; $i -le 90; $i++) {
  try {
    Invoke-RestMethod "http://localhost:8080/api/health" -TimeoutSec 3 | Out-Null
    break
  } catch { Start-Sleep -Seconds 2 }
}

docker compose -f $base -f $lan -f $fleet exec -T backend python manage.py bootstrap_search
docker compose -f $base -f $lan -f $fleet exec -T backend python manage.py bootstrap_kafka
docker compose -f $base -f $lan -f $fleet restart capture-worker pcap-ingestion-worker parser-worker decoder-worker session-worker detection-worker anomaly-worker analysis-finalizer-worker report-export-worker
docker compose -f $base -f $lan -f $fleet ps

Write-Host ""
Write-Host "Netra fleet console: http://localhost:8080" -ForegroundColor Green
Write-Host "Sensor fleet:        http://localhost:8080/app/sensors"
Write-Host "Capture schedules:   http://localhost:8080/app/schedules"
Write-Host "Retention controls:  http://localhost:8080/app/retention"
Write-Host "Sensor agent:        npm run netra:sensor:start"
Write-Host "Firewall: allow inbound TCP 8080 only on Private networks for LAN clients." -ForegroundColor Yellow

if ($Logs) { docker compose -f $base -f $lan -f $fleet logs -f --tail=120 }
