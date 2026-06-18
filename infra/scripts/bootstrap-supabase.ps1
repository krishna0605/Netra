$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

$envFile = Join-Path $repoRoot ".env.supabase.local"
if (-not (Test-Path $envFile)) {
  throw "Missing .env.supabase.local."
}

$supabase = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"

docker compose --env-file $envFile -f $supabase exec -T backend python manage.py migrate --run-syncdb
docker compose --env-file $envFile -f $supabase exec -T backend python manage.py bootstrap_supabase
