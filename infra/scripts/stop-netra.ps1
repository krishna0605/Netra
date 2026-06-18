$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.yml"
$supabaseComposeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$supabaseEnvFile = Join-Path $repoRoot ".env.supabase.local"
Set-Location $repoRoot

docker compose -f $composeFile down
if (Test-Path $supabaseComposeFile) {
  if (Test-Path $supabaseEnvFile) {
    docker compose --env-file $supabaseEnvFile -f $supabaseComposeFile down
  } else {
    docker compose -f $supabaseComposeFile down
  }
}
