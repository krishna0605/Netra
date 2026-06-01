$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8080/api"
$pcap = Join-Path $root "samples\pcaps\hydra_ssh.pcap"
$stamp = Get-Date -Format "yyyyMMddHHmmss"

Write-Host "Validating Phase 7 fleet operation..." -ForegroundColor Cyan
$posture = Invoke-RestMethod "$api/compliance/security-posture"
if ($posture.accessMode -ne "trusted-lan" -or $posture.authentication -ne "disabled" -or $posture.rbac -ne "disabled") { throw "Trusted LAN posture is inaccurate." }
Write-Host "[PASS] trusted-LAN posture reports auth and RBAC disabled"

$capacity = Invoke-RestMethod "$api/system/capacity"
if (-not $capacity.storage -or $null -eq $capacity.kafka.lag) { throw "Capacity endpoint is incomplete." }
Write-Host "[PASS] capacity endpoint reports storage and Kafka lag"

$group = Invoke-RestMethod -Method Post -Uri "$api/sensor-groups" -ContentType "application/json" -Body (@{name="Phase7 Group $stamp"; description="Validator group"; color="#2563eb"} | ConvertTo-Json)
if (-not $group.id) { throw "Sensor group creation failed." }
$sensorKey = if ($env:NETRA_SENSOR_SHARED_KEY) { $env:NETRA_SENSOR_SHARED_KEY } else { "netra-phase5-local-sensor-key" }
$sensorId = "sensor-phase7-$stamp"
$sensor = Invoke-RestMethod -Method Post -Uri "$api/sensors/register" -Headers @{"X-Netra-Sensor-Key"=$sensorKey} -ContentType "application/json" -Body (@{id=$sensorId; name="Phase7 Validator Sensor"; hostname="phase7-validator"; platform="windows-test"; agentVersion="phase7"; captureEngine="dumpcap"; interfaces=@(@{name="Validation Interface"; value="validation0"})} | ConvertTo-Json -Depth 5)
Invoke-RestMethod -Method Patch -Uri "$api/sensors/$sensorId" -ContentType "application/json" -Body (@{groupId=$group.id; location="Validation Lab"; tags=@("validator","fleet")} | ConvertTo-Json) | Out-Null
$fleet = Invoke-RestMethod "$api/sensors?groupId=$($group.id)"
if ($fleet.results.Count -lt 1 -or $fleet.results[0].location -ne "Validation Lab") { throw "Fleet metadata did not persist." }
Write-Host "[PASS] fleet groups and sensor metadata persist"

$startAt = (Get-Date).AddMinutes(10).ToString("o")
$schedule = Invoke-RestMethod -Method Post -Uri "$api/capture-schedules" -ContentType "application/json" -Body (@{name="Phase7 Scheduled Capture"; sensorId=$sensorId; scheduleType="one-time"; startAt=$startAt; timezone="Asia/Kolkata"; durationSeconds=30; packetLimit=1000; chunkIntervalSeconds=5; interfaceName="validation0"; bpfFilter="tcp port 22"; caseIdPrefix="CYB-GJ-PHASE7"} | ConvertTo-Json)
if (-not $schedule.id -or -not $schedule.nextRunAt) { throw "Capture schedule creation failed." }
Write-Host "[PASS] bounded capture schedule created"

$uploadJson = curl.exe -s -F "caseId=CYB-GJ-PHASE7-$stamp" -F "file=@$pcap" "$api/evidence/upload"
$upload = $uploadJson | ConvertFrom-Json
if (-not $upload.jobId) { throw "Async upload failed: $($upload.error)" }
for ($i=1; $i -le 120; $i++) {
  Start-Sleep -Seconds 2
  $job = Invoke-RestMethod "$api/jobs/$($upload.jobId)/status"
  if ($job.status -eq "completed") { break }
  if ($job.status -eq "failed") { throw "Async processing job failed." }
}
if ($job.status -ne "completed") { throw "Async processing did not complete in time." }
if ($job.processingPath -notin @("async-workers","sync-fallback")) { throw "Processing path was not recorded." }
Write-Host "[PASS] uploaded evidence completed with recorded processing path"

$indexes = Invoke-RestMethod "$api/system/indexes/retention"
if ($indexes.aliases -notcontains "netra-packets") { throw "Search aliases not reported." }
Write-Host "[PASS] search alias and lifecycle posture is exposed"

$preview = Invoke-RestMethod -Method Post -Uri "$api/retention/preview"
if ($preview.mode -ne "preview") { throw "Retention preview failed." }
Write-Host "[PASS] retention preview is safe and auditable"

$caseId = "CYB-GJ-PHASE7-$stamp"
$hold = Invoke-RestMethod -Method Post -Uri "$api/cases/$caseId/legal-hold" -ContentType "application/json" -Body (@{reason="Phase 7 validation"} | ConvertTo-Json)
if (-not $hold.legalHold) { throw "Legal hold was not applied." }
Invoke-RestMethod -Method Delete -Uri "$api/cases/$caseId/legal-hold" | Out-Null
Write-Host "[PASS] case legal hold can be applied and released"

Write-Host "Phase 7 validation passed." -ForegroundColor Green
