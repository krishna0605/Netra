$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$api = "http://localhost:8080/api"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$envFile = Join-Path $repoRoot ".env.supabase.local"
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"

function Get-NetraEnvValue([string]$Name) {
  $current = [Environment]::GetEnvironmentVariable($Name)
  if ($current) { return $current }
  if (-not (Test-Path $envFile)) { return "" }
  $line = Get-Content $envFile | Where-Object { $_ -match "^\s*$Name\s*=" } | Select-Object -First 1
  if (-not $line) { return "" }
  return (($line -split "=", 2)[1]).Trim().Trim('"').Trim("'")
}

function Set-NetraRole([string]$Email, [string]$Role) {
  $emailLiteral = $Email.Replace("\", "\\").Replace("'", "\'")
  $roleLiteral = $Role.Replace("\", "\\").Replace("'", "\'")
  $py = @"
from django.contrib.auth import get_user_model
from apps.forensics.models import UserProfile
User = get_user_model()
email = '$emailLiteral'
role = '$roleLiteral'
user, _ = User.objects.get_or_create(username=email, defaults=dict(email=email))
profile, _ = UserProfile.objects.get_or_create(user=user, defaults=dict(display_name=user.username))
profile.role = role
profile.save()
print(profile.role)
"@
  $result = docker compose --env-file $envFile -f $composeFile exec -T backend python manage.py shell -c $py
  if ($LASTEXITCODE -ne 0 -or ($result -join "`n") -notmatch $Role) {
    throw "Failed to set $Email to $Role"
  }
}

function Invoke-MultipartUpload([string]$Token, [string]$CaseId, [string]$FilePath) {
  $raw = & curl.exe -sS -w "`n%{http_code}" -X POST "$api/evidence/upload" `
    -H "Authorization: Bearer $Token" `
    -F "caseId=$CaseId" `
    -F "file=@$FilePath"
  if ($LASTEXITCODE -ne 0) { throw "curl upload failed with exit code $LASTEXITCODE" }
  $lines = $raw -split "`n"
  $status = [int]$lines[-1]
  $body = ($lines[0..($lines.Length - 2)] -join "`n")
  return @{ status = $status; body = $body; json = ($body | ConvertFrom-Json) }
}

Write-Host "Validating Netra Phase 1 security and RBAC..." -ForegroundColor Cyan

$testEmail = Get-NetraEnvValue "SUPABASE_TEST_EMAIL"
$testPassword = Get-NetraEnvValue "SUPABASE_TEST_PASSWORD"
if (-not $testEmail -or -not $testPassword) {
  throw "Set SUPABASE_TEST_EMAIL and SUPABASE_TEST_PASSWORD in the environment or .env.supabase.local before running this validation."
}

$health = Invoke-RestMethod "$api/system/health/deep"
if ($health.access.authentication -ne "supabase-auth") { throw "Supabase Auth is not active." }
if ($health.checks.security.devRoleHeaders) { throw "Development role headers must be disabled in Supabase mode." }
if (-not $health.checks.security.serviceRoleBackendOnly) { throw "Service-role key must be backend-only." }
Write-Host "[PASS] security health reports Supabase Auth, backend-only service key, and disabled dev headers"

$loginBody = @{ email = $testEmail; password = $testPassword } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri "$api/auth/login" -ContentType "application/json" -Body $loginBody
if (-not $login.access) { throw "Supabase login did not return an access token." }
$headers = @{ Authorization = "Bearer $($login.access)" }
$jsonHeaders = @{ Authorization = "Bearer $($login.access)"; "Content-Type" = "application/json" }
Write-Host "[PASS] Supabase login works"

Set-NetraRole $testEmail "Admin"
$me = Invoke-RestMethod "$api/auth/me" -Headers $headers
if ($me.role -ne "Admin") { throw "Expected Admin role after profile update, got $($me.role)" }
Write-Host "[PASS] Supabase user maps to local Admin authorization profile"

$managedEmail = "netra-phase1-viewer-$((Get-Date).ToString('yyyyMMddHHmmss'))@example.local"
$created = Invoke-RestMethod -Method Post -Uri "$api/users" -Headers $jsonHeaders -Body (@{ email = $managedEmail; name = "Phase 1 Viewer"; role = "Viewer" } | ConvertTo-Json)
if ($created.role -ne "Viewer") { throw "Admin user management did not create Viewer profile." }
Write-Host "[PASS] Admin can manage user roles"

$sample = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
if (-not (Test-Path $sample)) {
  $sample = (Get-ChildItem (Join-Path $repoRoot "samples\pcaps") -Filter *.pcap | Select-Object -First 1).FullName
}
if (-not $sample) { throw "No sample PCAP found for RBAC upload validation." }

Set-NetraRole $testEmail "Viewer"
$viewerUpload = Invoke-MultipartUpload $login.access "CYB-GJ-PHASE1-VIEWER-$((Get-Date).ToString('yyyyMMddHHmmss'))" $sample
if ($viewerUpload.status -ne 403) { throw "Viewer upload should return 403, got $($viewerUpload.status): $($viewerUpload.body)" }
$logs = Invoke-RestMethod "$api/audit/access-logs" -Headers $headers
$deniedUpload = $logs.results | Where-Object { $_.result -eq "denied" -and $_.action -eq "permission:upload" } | Select-Object -First 1
if (-not $deniedUpload) { throw "Denied Viewer upload was not written to access logs." }
Write-Host "[PASS] Viewer cannot upload and denied action is audit logged"

Set-NetraRole $testEmail "Investigator"
$caseId = "CYB-GJ-PHASE1-INV-$((Get-Date).ToString('yyyyMMddHHmmss'))"
$investigatorUpload = Invoke-MultipartUpload $login.access $caseId $sample
if ($investigatorUpload.status -ge 400 -or -not $investigatorUpload.json.jobId) { throw "Investigator upload failed: $($investigatorUpload.body)" }
Write-Host "[PASS] Investigator can upload evidence"

$report = Invoke-RestMethod -Method Post -Uri "$api/reports/$caseId/generate" -Headers $jsonHeaders -Body (@{ language = "en" } | ConvertTo-Json)
if ($report.status -ne "ready") { throw "Investigator report generation failed." }
$export = Invoke-RestMethod -Method Post -Uri "$api/exports" -Headers $jsonHeaders -Body (@{ caseId = $caseId; type = "json" } | ConvertTo-Json)
if ($export.status -ne "ready") { throw "Investigator export generation failed." }
Write-Host "[PASS] Investigator can generate reports and exports"

Set-NetraRole $testEmail "Viewer"
$viewerReportDenied = $false
try {
  Invoke-RestMethod -Method Post -Uri "$api/reports/$caseId/generate" -Headers $jsonHeaders -Body (@{ language = "en" } | ConvertTo-Json) | Out-Null
} catch {
  if ($_.Exception.Response.StatusCode.value__ -eq 403) { $viewerReportDenied = $true }
}
if (-not $viewerReportDenied) { throw "Viewer report generation should be denied with 403." }
Write-Host "[PASS] Viewer cannot generate reports"

$posture = Invoke-RestMethod "$api/compliance/security-posture" -Headers $headers
if ($posture.authentication -ne "supabase-auth" -or $posture.rbac -ne "enabled" -or $posture.devRoleHeaders) {
  throw "Security posture endpoint does not report Supabase Auth + RBAC correctly."
}
Write-Host "[PASS] security posture reports Supabase Auth and RBAC safely"

Set-NetraRole $testEmail "Admin"
$frontendPaths = @(
  (Join-Path $repoRoot "frontend\src"),
  (Join-Path $repoRoot "frontend\dist")
) | Where-Object { Test-Path $_ }
foreach ($path in $frontendPaths) {
  $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
  $matches = $files | Select-String -Pattern "SUPABASE_SERVICE_ROLE_KEY|service_role" -ErrorAction SilentlyContinue
  if ($matches) { throw "Frontend contains service-role reference in $path" }
}
Write-Host "[PASS] frontend source/build does not contain service-role references"

Write-Host "Phase 1 security validation passed." -ForegroundColor Green
