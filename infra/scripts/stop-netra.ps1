$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\compose.netra-production.yml"
$supabaseEnvFile = Join-Path $repoRoot ".env.supabase.local"
Set-Location $repoRoot

if (Test-Path $composeFile) {
  if (Test-Path $supabaseEnvFile) {
    docker compose --env-file $supabaseEnvFile -f $composeFile down
  } else {
    docker compose -f $composeFile down
  }
}
