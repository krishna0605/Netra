$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $root
docker compose -f infra/docker/docker-compose.local-postgres.yml -f infra/docker/docker-compose.lan.yml -f infra/docker/docker-compose.fleet.yml exec -T backend python manage.py bootstrap_search
