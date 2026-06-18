$ErrorActionPreference = "Stop"

Write-Host "Validating Netra evidence normalization..."

$container = docker ps --format "{{.Names}}" | Select-String -Pattern "^netra-supabase-backend-1$|^netra-backend-1$" | Select-Object -First 1
if (-not $container) {
  throw "No running Netra backend container found. Start Netra first, for example: npm run netra:start:supabase"
}

docker exec $container.ToString() python manage.py validate_evidence_normalization

Write-Host "Evidence normalization validation passed."
