$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.yml"
Set-Location $repoRoot

docker compose -f $composeFile down
