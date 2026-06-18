param(
  [string]$EnvFile = ".env.supabase.production.local",
  [switch]$WithWorkers
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

$envPath = Join-Path $repoRoot $EnvFile
if (-not (Test-Path $envPath)) {
  throw "Missing $EnvFile. Copy .env.supabase.production.example to $EnvFile and fill in rotated production secrets."
}

function Get-NetraEnvValue([string]$Name) {
  $current = [Environment]::GetEnvironmentVariable($Name)
  if ($current) { return $current }
  $line = Get-Content $envPath | Where-Object { $_ -match "^\s*$Name\s*=" } | Select-Object -First 1
  if (-not $line) { return "" }
  return (($line -split "=", 2)[1]).Trim().Trim('"').Trim("'")
}

$required = @(
  "DJANGO_SECRET_KEY",
  "DJANGO_ALLOWED_HOSTS",
  "DATABASE_URL",
  "SUPABASE_URL",
  "SUPABASE_ANON_KEY",
  "SUPABASE_SERVICE_ROLE_KEY",
  "NETRA_EVIDENCE_KEY",
  "NETRA_SENSOR_SHARED_KEY",
  "NETRA_WEBHOOK_SIGNING_SECRET",
  "NETRA_FRONTEND_ORIGINS",
  "NETRA_PUBLIC_BASE_URL",
  "VITE_SUPABASE_URL",
  "VITE_SUPABASE_ANON_KEY"
)

foreach ($name in $required) {
  $value = Get-NetraEnvValue $name
  if (-not $value -or $value -like "replace-*") {
    throw "$name is missing or still uses a placeholder in $EnvFile."
  }
}

$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.production.yml"
$services = @("frontend", "backend")
if ($WithWorkers -or (Get-NetraEnvValue "NETRA_SUPABASE_START_WORKERS") -eq "1") {
  $services += @("capture-worker", "pcap-ingestion-worker", "parser-worker", "decoder-worker", "session-worker", "detection-worker", "anomaly-worker", "analysis-finalizer-worker", "report-export-worker")
  $profileArgs = @("--profile", "workers")
} else {
  $profileArgs = @()
}

Write-Host "Starting Netra production profile..." -ForegroundColor Cyan
docker compose --env-file $envPath -f $composeFile @profileArgs up --build -d --remove-orphans @services

for ($i = 1; $i -le 90; $i++) {
  try {
    Invoke-RestMethod "http://localhost:8080/api/health" -TimeoutSec 3 | Out-Null
    break
  } catch {
    Start-Sleep -Seconds 2
  }
}

docker compose --env-file $envPath -f $composeFile @profileArgs ps
Write-Host ""
Write-Host "Netra production profile: $(Get-NetraEnvValue 'NETRA_PUBLIC_BASE_URL')" -ForegroundColor Green
Write-Host "Run validation: npm run netra:validate:production"
