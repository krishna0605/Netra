param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDirectory
)

$ErrorActionPreference = "Stop"
$backupRoot = Resolve-Path $BackupDirectory
$databaseDump = Join-Path $backupRoot "netra-postgres.dump"
$storageArchive = Join-Path $backupRoot "netra-storage.tar.gz"
$postgresPort = if ($env:NETRA_LOCAL_POSTGRES_PORT) { $env:NETRA_LOCAL_POSTGRES_PORT } else { "5432" }

if (-not (Test-Path $databaseDump) -or -not (Test-Path $storageArchive)) {
    throw "Backup directory must contain netra-postgres.dump and netra-storage.tar.gz."
}
if (-not (Get-Command pg_restore -ErrorAction SilentlyContinue)) {
    throw "pg_restore is not on PATH. Add PostgreSQL command-line tools to PATH."
}

$answer = Read-Host "Restore database rows and encrypted storage from $backupRoot? Type RESTORE to continue"
if ($answer -ne "RESTORE") {
    throw "Restore cancelled."
}

$env:PGPASSWORD = if ($env:NETRA_POSTGRES_PASSWORD) { $env:NETRA_POSTGRES_PASSWORD } else { "netra" }
pg_restore -h localhost -p $postgresPort -U netra -d netra --clean --if-exists $databaseDump
docker run --rm -v netra_netra-storage:/target -v "${backupRoot}:/backup:ro" alpine:3.20 sh -c "cd /target && tar -xzf /backup/netra-storage.tar.gz"

Write-Host "Netra restore completed." -ForegroundColor Green
