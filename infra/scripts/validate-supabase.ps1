param(
  [switch]$Strict
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$api = "http://localhost:8080/api"
$rootUrl = "http://localhost:8080"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$envFile = Join-Path $repoRoot ".env.supabase.local"

function Get-NetraEnvValue([string]$Name) {
  $current = [Environment]::GetEnvironmentVariable($Name)
  if ($current) { return $current }
  if (-not (Test-Path $envFile)) { return "" }
  $line = Get-Content $envFile | Where-Object { $_ -match "^\s*$Name\s*=" } | Select-Object -First 1
  if (-not $line) { return "" }
  return (($line -split "=", 2)[1]).Trim().Trim('"').Trim("'")
}

function Wait-ForCapture([string]$JobId, [hashtable]$Headers, [int]$Seconds = 90) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  do {
    $status = Invoke-RestMethod "$api/capture/replay/$JobId/status" -Headers $Headers
    if ($status.status -in @("completed", "failed", "stopped")) { return $status }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)
  return $status
}

Write-Host "Validating Netra Supabase mode..." -ForegroundColor Cyan

$health = Invoke-RestMethod "$api/health"
if ($health.status -ne "ok") { throw "Health endpoint failed." }
Write-Host "[PASS] API health is reachable"

$database = Invoke-RestMethod "$api/system/database"
if ($database.provider -ne "supabase") { throw "Database provider is not supabase: $($database.provider)" }
if ($database.tables -lt 10) { throw "Expected migrated Netra tables in Supabase." }
Write-Host "[PASS] Supabase database provider and tables are visible"

$deep = Invoke-RestMethod "$api/system/health/deep"
if ($deep.checks.postgres.status -ne "ok") { throw "Supabase Postgres probe failed." }
if ($deep.checks.kafka.provider -ne "supabase-pgmq") { throw "Queue provider is not Supabase PGMQ." }
if ($deep.checks.storage.provider -ne "supabase-storage") { throw "Storage provider is not Supabase Storage." }
if ($deep.checks.storage.status -ne "ok") { throw "Supabase Storage probe failed: $($deep.checks.storage.detail)" }
Write-Host "[PASS] deep health reports Supabase Postgres, Storage, and PGMQ"

$indexes = Invoke-RestMethod "$api/system/indexes"
if ($indexes.provider -ne "postgres") { throw "Supabase mode must use Postgres search, got: $($indexes.provider)" }
Write-Host "[PASS] search endpoint uses Supabase/Postgres, not Elasticsearch"

$queue = Invoke-RestMethod "$api/system/kafka"
if ($queue.provider -ne "supabase-pgmq") { throw "Queue endpoint must report Supabase PGMQ." }
if ($queue.status -ne "ok" -or $queue.detail -notlike "*send/read/archive*") { throw "Supabase PGMQ probe did not complete send/read/archive: $($queue.detail)" }
Write-Host "[PASS] queue endpoint uses Supabase PGMQ, not Kafka"

$realtime = Invoke-RestMethod "$api/system/realtime"
if ($realtime.provider -ne "supabase-realtime") { throw "Realtime provider is not Supabase Realtime." }
if ($realtime.status -ne "ok") { throw "Supabase Realtime is not fully configured. Missing: $($realtime.missingTables -join ', ')" }
Write-Host "[PASS] Supabase Realtime publication is configured for operational tables"

$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
if (Test-Path $envFile) {
  $composeServices = docker compose --env-file $envFile -f $composeFile config --services
  foreach ($legacy in @("postgres", "kafka", "elasticsearch")) {
    if ($composeServices -contains $legacy) { throw "Supabase compose still defines local $legacy service." }
  }
  Write-Host "[PASS] Supabase compose excludes local PostgreSQL, Kafka, and Elasticsearch services"
}

$testEmail = Get-NetraEnvValue "SUPABASE_TEST_EMAIL"
$testPassword = Get-NetraEnvValue "SUPABASE_TEST_PASSWORD"

if ($testEmail -and $testPassword) {
  $loginBody = @{ email = $testEmail; password = $testPassword } | ConvertTo-Json
  $login = Invoke-RestMethod -Method Post -Uri "$api/auth/login" -ContentType "application/json" -Body $loginBody
  if (-not $login.access) { throw "Supabase test login did not return an access token." }
  Write-Host "[PASS] configured Supabase test login works"
  $headers = @{ Authorization = "Bearer $($login.access)" }
  $jsonHeaders = @{ Authorization = "Bearer $($login.access)"; "Content-Type" = "application/json" }
  $sample = Join-Path $repoRoot "samples\pcaps\hydra_ssh.pcap"
  if (-not (Test-Path $sample)) {
    $sample = (Get-ChildItem (Join-Path $repoRoot "samples\pcaps") -Filter *.pcap | Select-Object -First 1).FullName
  }
  if (-not $sample) { throw "No sample PCAP found for upload validation." }
  $caseId = "CYB-GJ-SUPABASE-" + (Get-Date -Format "yyyyMMddHHmmss")
  $uploadRaw = & curl.exe -sS -X POST "$api/evidence/upload" `
    -H "Authorization: Bearer $($login.access)" `
    -F "caseId=$caseId" `
    -F "file=@$sample"
  if ($LASTEXITCODE -ne 0) { throw "curl upload failed with exit code $LASTEXITCODE." }
  $upload = $uploadRaw | ConvertFrom-Json
  if ($upload.error) { throw "PCAP upload failed: $($upload.error) $($upload.detail)" }
  if (-not $upload.caseId -or -not $upload.jobId) { throw "PCAP upload did not return case/job ids." }
  Write-Host "[PASS] authenticated PCAP upload completed"
  $summary = Invoke-RestMethod "$api/dashboard/summary?caseId=$caseId" -Headers $headers
  if ($summary.packets -lt 1) { throw "Uploaded case did not produce packet analysis." }
  Write-Host "[PASS] uploaded case produced packet analysis"
  $integrity = Invoke-RestMethod -Method Post -Uri "$api/evidence/$($upload.id)/verify-integrity" -Headers $headers
  if (-not $integrity.verified -or -not $integrity.encryptedArtifactVerified -or -not $integrity.manifestVerified) { throw "Evidence integrity verification failed." }
  Write-Host "[PASS] evidence integrity verification completed"
  $report = Invoke-RestMethod -Method Post -Uri "$api/reports/$caseId/generate" -Headers $headers -ContentType "application/json" -Body (@{ language = "en" } | ConvertTo-Json)
  if ($report.status -ne "ready") { throw "Report generation failed." }
  Write-Host "[PASS] report generation completed"
  $reportDownload = Invoke-WebRequest -Uri "$api/reports/$($report.reportId)/download" -Headers $headers -UseBasicParsing
  if ($reportDownload.StatusCode -ne 200 -or $reportDownload.Content -notlike "*Forensic Network Investigation Report*") { throw "Report download did not return generated HTML." }
  Write-Host "[PASS] report download completed"
  $export = Invoke-RestMethod -Method Post -Uri "$api/exports" -Headers $headers -ContentType "application/json" -Body (@{ caseId = $caseId; type = "json" } | ConvertTo-Json)
  if ($export.status -ne "ready") { throw "Evidence export generation failed." }
  Write-Host "[PASS] evidence export generation completed"
  $exportDownload = Invoke-WebRequest -Uri "$api/exports/$($export.id)/download" -Headers $headers -UseBasicParsing
  $exportContent = if ($exportDownload.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($exportDownload.Content) } else { [string]$exportDownload.Content }
  if ($exportDownload.StatusCode -ne 200 -or $exportContent -notlike "*custodyLedger*") { throw "Evidence export download did not include custody ledger data." }
  Write-Host "[PASS] evidence export download completed"
  $csvExport = Invoke-RestMethod -Method Post -Uri "$api/exports" -Headers $headers -ContentType "application/json" -Body (@{ caseId = $caseId; type = "Alert CSV" } | ConvertTo-Json)
  if ($csvExport.status -ne "ready") { throw "Alert CSV export generation failed." }
  Write-Host "[PASS] alert CSV export generation completed"
  $ledger = Invoke-RestMethod -Uri "$api/cases/$caseId/custody-ledger" -Headers $headers
  if (-not $ledger.verification.verified -or $ledger.verification.eventCount -lt 8) { throw "Custody ledger did not verify after evidence/report/export actions." }
  Write-Host "[PASS] custody ledger verifies report/export/integrity actions"

  $replayCaseId = "CYB-GJ-SUPABASE-REPLAY-" + (Get-Date -Format "yyyyMMddHHmmss")
  $replayRaw = & curl.exe -sS -X POST "$api/capture/replay/start" `
    -H "Authorization: Bearer $($login.access)" `
    -F "caseId=$replayCaseId" `
    -F "speed=max" `
    -F "chunkIntervalSeconds=2" `
    -F "packetLimit=5000" `
    -F "file=@$sample"
  if ($LASTEXITCODE -ne 0) { throw "curl replay failed with exit code $LASTEXITCODE." }
  $replay = $replayRaw | ConvertFrom-Json
  if (-not $replay.jobId) { throw "Replay did not return a capture job id: $replayRaw" }
  $replayStatus = Wait-ForCapture $replay.jobId $headers 120
  if ($replayStatus.status -ne "completed" -or -not $replayStatus.finalEvidenceId) { throw "Replay did not finalize evidence. Status: $($replayStatus.status) Error: $($replayStatus.error)" }
  Write-Host "[PASS] replay PCAP feed finalized into real evidence"

  $sensorKey = Get-NetraEnvValue "NETRA_SENSOR_SHARED_KEY"
  if (-not $sensorKey) { throw "NETRA_SENSOR_SHARED_KEY is required to validate sensor ingestion." }
  $sensorId = "sensor-supabase-validator-" + (Get-Date -Format "yyyyMMddHHmmss")
  $sensorHeaders = @{ "X-Netra-Sensor-Key" = $sensorKey }
  $sensorBody = @{
    id = $sensorId
    name = "Supabase Validator Sensor"
    hostname = "validator-host"
    platform = "windows-validator"
    agentVersion = "validator"
    captureEngine = "dumpcap"
    interfaces = @(@{ name = "Validation Interface"; value = "validation0" })
  } | ConvertTo-Json -Depth 5
  $sensor = Invoke-RestMethod -Method Post -Uri "$api/sensors/register" -Headers $sensorHeaders -ContentType "application/json" -Body $sensorBody
  if ($sensor.id -ne $sensorId) { throw "Sensor registration failed." }
  $captureCaseId = "CYB-GJ-SUPABASE-SENSOR-" + (Get-Date -Format "yyyyMMddHHmmss")
  $captureBody = @{
    caseId = $captureCaseId
    sensorId = $sensorId
    interfaceName = "validation0"
    durationSeconds = 10
    packetLimit = 5000
    chunkIntervalSeconds = 2
    bpfFilter = ""
  } | ConvertTo-Json
  $capture = Invoke-RestMethod -Method Post -Uri "$api/capture/live/start" -Headers $jsonHeaders -Body $captureBody
  if (-not $capture.jobId) { throw "Live capture command did not return a job id." }
  $command = Invoke-RestMethod -Uri "$api/sensors/$sensorId/commands/next" -Headers $sensorHeaders
  if (-not $command.command -or $command.command.jobId -ne $capture.jobId) { throw "Sensor command polling did not return the queued capture job." }
  $chunkRaw = & curl.exe -sS -X POST "$api/sensors/$sensorId/chunks" `
    -H "X-Netra-Sensor-Key: $sensorKey" `
    -F "jobId=$($capture.jobId)" `
    -F "sequence=1" `
    -F "file=@$sample"
  if ($LASTEXITCODE -ne 0) { throw "sensor chunk upload failed with exit code $LASTEXITCODE." }
  $chunk = $chunkRaw | ConvertFrom-Json
  if (-not $chunk.chunkId) { throw "Sensor chunk upload did not create a chunk: $chunkRaw" }
  $completedCapture = Invoke-RestMethod -Method Post -Uri "$api/sensors/$sensorId/captures/$($capture.jobId)/complete" -Headers $sensorHeaders
  if ($completedCapture.status -ne "completed" -or -not $completedCapture.finalEvidenceId) { throw "Sensor capture did not finalize evidence." }
  Write-Host "[PASS] sensor capture command, chunk upload, and finalization work"

  $webhookCode = @'
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, format, *args):
        pass
HTTPServer(("0.0.0.0", 9900), Handler).serve_forever()
'@
  $webhookJob = Start-Job -ScriptBlock { param($code) $code | python - } -ArgumentList $webhookCode
  try {
    Start-Sleep -Seconds 2
    $integrationBody = @{
      systemName = "Validator Webhook " + (Get-Date -Format "HHmmss")
      mode = "webhook-json"
      url = "http://host.docker.internal:9900/alerts"
      secret = "validator-secret"
    } | ConvertTo-Json
    $integration = Invoke-RestMethod -Method Post -Uri "$api/integrations" -Headers $jsonHeaders -Body $integrationBody
    $testDelivery = Invoke-RestMethod -Method Post -Uri "$api/integrations/$($integration.id)/test" -Headers $headers
    if ($testDelivery.result -ne "success") { throw "Webhook test did not succeed." }
    $alertDelivery = Invoke-RestMethod -Method Post -Uri "$api/integrations/$($integration.id)/send-alerts" -Headers $jsonHeaders -Body (@{ caseId = $caseId } | ConvertTo-Json)
    if ($alertDelivery.attempted -gt 0 -and $alertDelivery.delivered -lt 1) { throw "Webhook alert delivery attempted but none succeeded." }
    Write-Host "[PASS] webhook integration records real successful HTTP delivery"
  } finally {
    Stop-Job $webhookJob -ErrorAction SilentlyContinue | Out-Null
    Remove-Job $webhookJob -Force -ErrorAction SilentlyContinue | Out-Null
  }

  $siem = Invoke-RestMethod -Method Post -Uri "$api/integrations/siem/export" -Headers $jsonHeaders -Body (@{ caseId = $caseId } | ConvertTo-Json)
  if ($siem.status -ne "ready" -or -not $siem.downloadUrl) { throw "SIEM CEF export did not return a downloadable artifact." }
  $cefDownload = Invoke-WebRequest -Uri "$rootUrl$($siem.downloadUrl)" -Headers $headers -UseBasicParsing
  $cefContent = if ($cefDownload.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($cefDownload.Content) } else { [string]$cefDownload.Content }
  if ($cefDownload.StatusCode -ne 200 -or $cefContent -notlike "CEF:*") { throw "SIEM CEF export download did not return CEF content." }
  Write-Host "[PASS] SIEM CEF export is persisted and downloadable"
} else {
  $message = "Set SUPABASE_TEST_EMAIL and SUPABASE_TEST_PASSWORD to validate login, upload, report, and export automatically."
  if ($Strict) {
    throw $message
  }
  Write-Host "[WARN] $message" -ForegroundColor Yellow
}

Write-Host "Supabase validation passed." -ForegroundColor Green
