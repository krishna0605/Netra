$ErrorActionPreference = "Stop"

$api = "http://localhost:8000/api"

Write-Host "Validating Netra local PostgreSQL mode..." -ForegroundColor Cyan

$health = Invoke-RestMethod "$api/system/health/deep"
if ($health.status -ne "ok") { throw "Deep health is not ok: $($health.status)" }

$database = Invoke-RestMethod "$api/system/database"
if ($database.mode -ne "local-postgres") { throw "Expected local-postgres mode, got $($database.mode)" }
if ($database.host -ne "host.docker.internal") { throw "Expected host.docker.internal, got $($database.host)" }
if ([int]$database.tables -lt 1) { throw "No database tables reported." }

Write-Host "[PASS] backend is connected to native PostgreSQL through host.docker.internal"
Write-Host "[PASS] database $($database.name) has $($database.tables) visible tables"
Write-Host "Local PostgreSQL validation passed." -ForegroundColor Green
