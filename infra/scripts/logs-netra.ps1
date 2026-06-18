$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.yml"
$supabaseComposeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$supabaseEnvFile = Join-Path $repoRoot ".env.supabase.local"
Set-Location $repoRoot

if (Test-Path $supabaseComposeFile) {
  $supabaseArgs = @()
  if (Test-Path $supabaseEnvFile) {
    $supabaseArgs += @("--env-file", $supabaseEnvFile)
  }
  $supabaseArgs += @("-f", $supabaseComposeFile)
  $supabaseContainers = docker compose @supabaseArgs ps -q
  if ($supabaseContainers) {
    docker compose @supabaseArgs logs -f --tail=120
    exit
  }
}

docker compose -f $composeFile logs -f --tail=120
