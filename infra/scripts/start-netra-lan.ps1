param(
    [switch]$Logs,
    [int]$PostgresPort = 0
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

$baseCompose = Join-Path $repoRoot "infra\docker\docker-compose.local-postgres.yml"
$lanCompose = Join-Path $repoRoot "infra\docker\docker-compose.lan.yml"

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
$env:NETRA_ACCESS_MODE = "trusted-lan"
$env:NETRA_DEV_ROLE_HEADERS = "0"

$lanIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.PrefixOrigin -ne "WellKnown"
    } |
    Sort-Object InterfaceAlias, IPAddress |
    Select-Object -ExpandProperty IPAddress)

Write-Host "Starting Netra trusted LAN stack..." -ForegroundColor Cyan
Write-Host "Native PostgreSQL: netra@localhost:$PostgresPort"
Write-Host "Local console:     http://localhost:8080"
if ($lanIps.Count -gt 0) {
    Write-Host "LAN console URLs:" -ForegroundColor Cyan
    foreach ($ip in $lanIps) {
        Write-Host "  http://$ip`:8080"
    }
} else {
    Write-Host "No LAN IPv4 address detected yet. Connect to a private network and rerun this command." -ForegroundColor Yellow
}

docker compose -f $baseCompose -f $lanCompose up --build -d --remove-orphans

$ready = $false
for ($i = 1; $i -le 60; $i++) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:8080/api/system/health/deep" -TimeoutSec 3
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

docker compose -f $baseCompose -f $lanCompose ps
if ($ready) {
    Write-Host "Netra trusted LAN mode is ready." -ForegroundColor Green
} else {
    Write-Host "Containers started, but the same-origin deep health check is not ready." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Evidence intake: http://localhost:8080/app/upload"
Write-Host "System monitor:  http://localhost:8080/app/system"
Write-Host ""
Write-Host "Windows Firewall note:" -ForegroundColor Yellow
Write-Host "Allow inbound TCP 8080 only on Private networks if other laptops cannot open the LAN URL."
Write-Host 'Admin PowerShell example: New-NetFirewallRule -DisplayName "Netra LAN 8080" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 -Profile Private'

if ($Logs) {
    docker compose -f $baseCompose -f $lanCompose logs -f --tail=120
}
