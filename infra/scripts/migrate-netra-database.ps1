[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("Export", "Import", "Validate")]
  [string]$Action,

  [Parameter(Mandatory = $true)]
  [string]$WorkDirectory,

  [switch]$ConfirmSourceEgressReset,

  [long]$AvailableEgressBytes = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$minimumAvailableEgressBytes = 768MB
$expectedPublicTableCount = 49
$sourceUrlVariable = "NETRA_MIGRATION_SOURCE_DATABASE_URL"
$targetUrlVariable = "NETRA_MIGRATION_TARGET_DATABASE_URL"

function Get-RequiredEnvironmentValue([string]$Name) {
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) {
    throw "Required environment variable $Name is missing."
  }
  return $value
}

function Invoke-DatabaseCommand([string]$Executable, [string]$DatabaseUrl, [string[]]$Arguments) {
  $previousPgDatabase = $env:PGDATABASE
  try {
    $env:PGDATABASE = $DatabaseUrl
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "$Executable failed with exit code $LASTEXITCODE."
    }
  } finally {
    $env:PGDATABASE = $previousPgDatabase
  }
}

function Invoke-PsqlScalar([string]$DatabaseUrl, [string]$Sql) {
  $previousPgDatabase = $env:PGDATABASE
  try {
    $env:PGDATABASE = $DatabaseUrl
    $result = & psql --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 --command $Sql
    if ($LASTEXITCODE -ne 0) {
      throw "psql validation query failed with exit code $LASTEXITCODE."
    }
    return ($result | Out-String).Trim()
  } finally {
    $env:PGDATABASE = $previousPgDatabase
  }
}

foreach ($tool in @("pg_dump", "pg_restore", "psql")) {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    throw "$tool is required. Install the PostgreSQL 17 client tools before running this migration."
  }
}

$sourceDatabaseUrl = Get-RequiredEnvironmentValue $sourceUrlVariable
$targetDatabaseUrl = Get-RequiredEnvironmentValue $targetUrlVariable
if ($sourceDatabaseUrl -eq $targetDatabaseUrl) {
  throw "Source and target database URLs must be different."
}

$resolvedWorkDirectory = [System.IO.Path]::GetFullPath($WorkDirectory)
[System.IO.Directory]::CreateDirectory($resolvedWorkDirectory) | Out-Null
$publicDump = Join-Path $resolvedWorkDirectory "netra-public-data.dump"
$authUsersDump = Join-Path $resolvedWorkDirectory "netra-auth-users.dump"
$authIdentitiesDump = Join-Path $resolvedWorkDirectory "netra-auth-identities.dump"
$publicSql = Join-Path $resolvedWorkDirectory "netra-public-data.sql"
$authUsersSql = Join-Path $resolvedWorkDirectory "netra-auth-users.sql"
$authIdentitiesSql = Join-Path $resolvedWorkDirectory "netra-auth-identities.sql"
$truncatePublicSqlFile = Join-Path $resolvedWorkDirectory "netra-truncate-public.sql"

if ($Action -in @("Export", "Validate")) {
  if (-not $ConfirmSourceEgressReset) {
    throw "Refusing source access until -ConfirmSourceEgressReset is supplied."
  }
  if ($AvailableEgressBytes -lt $minimumAvailableEgressBytes) {
    throw "At least $minimumAvailableEgressBytes available egress bytes must be confirmed."
  }
}

if ($Action -eq "Export") {
  Invoke-DatabaseCommand "pg_dump" $sourceDatabaseUrl @(
    "--format=custom",
    "--data-only",
    "--schema=public",
    "--exclude-table=public.django_session",
    "--no-owner",
    "--no-privileges",
    "--file=$publicDump"
  )
  Invoke-DatabaseCommand "pg_dump" $sourceDatabaseUrl @(
    "--format=custom",
    "--data-only",
    "--table=auth.users",
    "--no-owner",
    "--no-privileges",
    "--file=$authUsersDump"
  )
  Invoke-DatabaseCommand "pg_dump" $sourceDatabaseUrl @(
    "--format=custom",
    "--data-only",
    "--table=auth.identities",
    "--no-owner",
    "--no-privileges",
    "--file=$authIdentitiesDump"
  )
  Write-Output "Created public, Auth user, and Auth identity archives in $resolvedWorkDirectory."
  exit 0
}

if ($Action -eq "Import") {
  if (
    -not (Test-Path -LiteralPath $publicDump) -or
    -not (Test-Path -LiteralPath $authUsersDump) -or
    -not (Test-Path -LiteralPath $authIdentitiesDump)
  ) {
    throw "The public, Auth user, and Auth identity archives must all exist in $resolvedWorkDirectory."
  }
  $targetTableCount = [int](Invoke-PsqlScalar $targetDatabaseUrl @"
select count(*)
from information_schema.tables
where table_schema = 'public'
  and table_type = 'BASE TABLE'
  and (table_name like 'forensics\_%' escape '\' or table_name like 'auth\_%' escape '\' or table_name like 'django\_%' escape '\');
"@)
  if ($targetTableCount -ne $expectedPublicTableCount) {
    throw "Expected $expectedPublicTableCount target public tables before import, found $targetTableCount."
  }
  $targetAuthRows = [int](Invoke-PsqlScalar $targetDatabaseUrl "select (select count(*) from auth.users) + (select count(*) from auth.identities);")
  if ($targetAuthRows -ne 0) {
    throw "Target Auth is not empty. Refusing to overwrite $targetAuthRows user/identity rows."
  }

  $truncatePublicSql = @'
do $netra_truncate$
declare
  table_list text;
begin
  select string_agg(format('%I.%I', table_schema, table_name), ', ' order by table_name)
  into table_list
  from information_schema.tables
  where table_schema = 'public'
    and table_type = 'BASE TABLE'
    and (table_name like 'forensics\_%' escape '\' or table_name like 'auth\_%' escape '\' or table_name like 'django\_%' escape '\');
  if table_list is not null then
    execute 'truncate table ' || table_list || ' restart identity cascade';
  end if;
end
$netra_truncate$;
'@
  Set-Content -LiteralPath $truncatePublicSqlFile -Value $truncatePublicSql -Encoding UTF8
  Invoke-DatabaseCommand "pg_restore" $targetDatabaseUrl @(
    "--data-only",
    "--no-owner",
    "--no-privileges",
    "--file=$publicSql",
    $publicDump
  )
  Invoke-DatabaseCommand "psql" $targetDatabaseUrl @(
    "--no-psqlrc",
    "--single-transaction",
    "--set", "ON_ERROR_STOP=1",
    "--command=set session_replication_role = replica;",
    "--file=$truncatePublicSqlFile",
    "--file=$publicSql"
  )
  Invoke-DatabaseCommand "pg_restore" $targetDatabaseUrl @(
    "--data-only",
    "--no-owner",
    "--no-privileges",
    "--file=$authUsersSql",
    $authUsersDump
  )
  Invoke-DatabaseCommand "pg_restore" $targetDatabaseUrl @(
    "--data-only",
    "--no-owner",
    "--no-privileges",
    "--file=$authIdentitiesSql",
    $authIdentitiesDump
  )
  Invoke-DatabaseCommand "psql" $targetDatabaseUrl @(
    "--no-psqlrc",
    "--single-transaction",
    "--set", "ON_ERROR_STOP=1",
    "--command=set session_replication_role = replica;",
    "--command=truncate table auth.identities, auth.users cascade;",
    "--file=$authUsersSql",
    "--file=$authIdentitiesSql"
  )
  $targetSessions = [int](Invoke-PsqlScalar $targetDatabaseUrl "select (select count(*) from auth.sessions) + (select count(*) from auth.refresh_tokens) + (select count(*) from public.django_session);")
  if ($targetSessions -ne 0) {
    throw "Fresh-session invariant failed: found $targetSessions migrated session rows."
  }
  Write-Output "Imported public durable data and Auth users/identities with sessions left empty."
  exit 0
}

$countSql = @'
select count(*)
from information_schema.tables
where table_schema = 'public'
  and table_type = 'BASE TABLE'
  and (table_name like 'forensics\_%' escape '\' or table_name like 'auth\_%' escape '\' or table_name like 'django\_%' escape '\');
'@
$sourceTableCount = [int](Invoke-PsqlScalar $sourceDatabaseUrl $countSql)
$targetTableCount = [int](Invoke-PsqlScalar $targetDatabaseUrl $countSql)
$sourceAuthUsers = [int](Invoke-PsqlScalar $sourceDatabaseUrl "select count(*) from auth.users;")
$targetAuthUsers = [int](Invoke-PsqlScalar $targetDatabaseUrl "select count(*) from auth.users;")
$sourceAuthIdentities = [int](Invoke-PsqlScalar $sourceDatabaseUrl "select count(*) from auth.identities;")
$targetAuthIdentities = [int](Invoke-PsqlScalar $targetDatabaseUrl "select count(*) from auth.identities;")
$targetSessionRows = [int](Invoke-PsqlScalar $targetDatabaseUrl "select (select count(*) from auth.sessions) + (select count(*) from auth.refresh_tokens) + (select count(*) from public.django_session);")

$validation = [ordered]@{
  sourcePublicTableCount = $sourceTableCount
  targetPublicTableCount = $targetTableCount
  sourceAuthUsers = $sourceAuthUsers
  targetAuthUsers = $targetAuthUsers
  sourceAuthIdentities = $sourceAuthIdentities
  targetAuthIdentities = $targetAuthIdentities
  targetSessionRows = $targetSessionRows
}
$validation | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $resolvedWorkDirectory "database-validation.json") -Encoding UTF8
if ($sourceTableCount -ne $expectedPublicTableCount -or $targetTableCount -ne $expectedPublicTableCount) {
  throw "Public table count validation failed."
}
if ($sourceAuthUsers -ne $targetAuthUsers -or $sourceAuthIdentities -ne $targetAuthIdentities -or $targetSessionRows -ne 0) {
  throw "Auth validation failed."
}
$validation | ConvertTo-Json
