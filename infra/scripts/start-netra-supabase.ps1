$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

$envFile = Join-Path $repoRoot ".env.supabase.local"
if (-not (Test-Path $envFile)) {
  throw "Missing .env.supabase.local. Copy .env.supabase.example to .env.supabase.local and fill in Supabase secrets first."
}

function Get-NetraEnvValue([string]$Name) {
  $current = [Environment]::GetEnvironmentVariable($Name)
  if ($current) { return $current }
  $line = Get-Content $envFile | Where-Object { $_ -match "^\s*$Name\s*=" } | Select-Object -First 1
  if (-not $line) { return "" }
  return (($line -split "=", 2)[1]).Trim().Trim('"').Trim("'")
}

$supabase = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$services = @("frontend", "backend")
$workerServices = @(
  "capture-worker",
  "pcap-ingestion-worker",
  "parser-worker",
  "decoder-worker",
  "session-worker",
  "detection-worker",
  "anomaly-worker",
  "analysis-finalizer-worker",
  "report-export-worker",
  "scheduler-worker",
  "retention-worker"
)

$workersEnabled = (Get-NetraEnvValue "NETRA_SUPABASE_START_WORKERS") -eq "1"
if ($workersEnabled) {
  $services += $workerServices
}

Write-Host "Starting Netra in Supabase data-plane mode..." -ForegroundColor Cyan
docker compose --env-file $envFile -f $supabase up --build -d --remove-orphans @services

for ($i = 1; $i -le 90; $i++) {
  try {
    Invoke-RestMethod "http://localhost:8080/api/health" -TimeoutSec 3 | Out-Null
    break
  } catch {
    Start-Sleep -Seconds 2
  }
}

docker compose --env-file $envFile -f $supabase ps

Write-Host ""
Write-Host "Netra Supabase console: http://localhost:8080" -ForegroundColor Green
Write-Host "Login route:             http://localhost:8080/login"
Write-Host "Data plane:              Supabase project kirctxhxcmnncpuxjknw"
Write-Host "Local DB/Kafka/Search:   stopped; Supabase Postgres, pgmq, and Postgres search are used"
Write-Host "Workers:                 $($(if ($workersEnabled) { 'enabled' } else { 'disabled for lightweight Supabase login/upload testing' }))"
Write-Host "Reminder: rotate the pasted service-role key before any shared demo." -ForegroundColor Yellow
