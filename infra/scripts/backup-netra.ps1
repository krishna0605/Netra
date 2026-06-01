param(
    [string]$Destination = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if (-not $Destination) {
    $Destination = Join-Path $repoRoot ("backups\netra-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$backupRoot = New-Item -ItemType Directory -Force -Path $Destination
$postgresPort = if ($env:NETRA_LOCAL_POSTGRES_PORT) { $env:NETRA_LOCAL_POSTGRES_PORT } else { "5432" }

if (-not (Get-Command pg_dump -ErrorAction SilentlyContinue)) {
    throw "pg_dump is not on PATH. Add PostgreSQL command-line tools to PATH."
}
$env:PGPASSWORD = if ($env:NETRA_POSTGRES_PASSWORD) { $env:NETRA_POSTGRES_PASSWORD } else { "netra" }
pg_dump -h localhost -p $postgresPort -U netra -d netra -Fc -f (Join-Path $backupRoot "netra-postgres.dump")

docker run --rm -v netra_netra-storage:/source:ro -v "${backupRoot}:/backup" alpine:3.20 sh -c "cd /source && tar -czf /backup/netra-storage.tar.gz ."

@{
    createdAt = (Get-Date).ToString("o")
    postgresPort = $postgresPort
    database = "netra"
    storageArchive = "netra-storage.tar.gz"
    databaseDump = "netra-postgres.dump"
    note = "Encrypted evidence artifacts only. Keep NETRA_EVIDENCE_KEY separately."
} | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $backupRoot "backup-manifest.json")

Write-Host "Netra backup created: $backupRoot" -ForegroundColor Green
