$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$api = "http://localhost:8000/api"
$matrix = @(
  @{ File = "normal.pcap"; Expected = "Normal Baseline"; MaxRisk = "low" },
  @{ File = "hydra_ssh.pcap"; Expected = "Credential Brute Force"; MaxRisk = "high" },
  @{ File = "hydra_ftp.pcap"; Expected = "Credential Brute Force"; MaxRisk = "high" },
  @{ File = "mirai.pcap"; Expected = "IoT Botnet / Scanning"; MaxRisk = "critical" },
  @{ File = "zeus.pcap"; Expected = "Port Scan / Reconnaissance"; MaxRisk = "high" },
  @{ File = "vsftpd.pcap"; Expected = "Port Scan / Reconnaissance"; MaxRisk = "high" },
  @{ File = "tomcat.pcap"; Expected = "Web Service Exploitation"; MaxRisk = "high" },
  @{ File = "distcc_exec_backdoor.pcap"; Expected = "Remote Command Execution"; MaxRisk = "critical" },
  @{ File = "netbios_ssn.pcap"; Expected = "Port Scan / Reconnaissance"; MaxRisk = "high" },
  @{ File = "smtp.pcap"; Expected = "Suspicious SMTP Transfer"; MaxRisk = "medium" }
)

Write-Host "Validating Phase 1 golden PCAP matrix..."
Write-Host "API: $api"

$health = Invoke-RestMethod "$api/health"
if (-not $health.packetTools.tshark) { throw "tshark is not available in backend health." }
if (-not $health.packetTools.zeek) { throw "zeek is not available in backend health." }

$failures = 0
foreach ($item in $matrix) {
  $path = Join-Path $repoRoot "samples\pcaps\$($item.File)"
  if (-not (Test-Path $path)) {
    Write-Host "[FAIL] $($item.File) missing"
    $failures += 1
    continue
  }
  $caseId = "CYB-GJ-" + ($item.File -replace "\.pcap$", "").ToUpper()
  $responseJson = curl.exe -s -F "caseId=$caseId" -F "file=@$path" "$api/evidence/upload"
  $response = $responseJson | ConvertFrom-Json
  if ($response.error) {
    Write-Host "[FAIL] $($item.File) upload failed: $($response.error)"
    $failures += 1
    continue
  }
  $actual = $response.analysis.topAttackClass
  $risk = $response.riskLevel
  $alerts = $response.analysis.alerts
  $anomalies = $response.analysis.anomalies
  $zeek = $response.analysis.zeek.status
  if ($actual -ne $item.Expected) {
    Write-Host "[FAIL] $($item.File) expected '$($item.Expected)' got '$actual' risk=$risk alerts=$alerts anomalies=$anomalies zeek=$zeek"
    $failures += 1
  } else {
    Write-Host "[PASS] $($item.File) class='$actual' risk=$risk alerts=$alerts anomalies=$anomalies zeek=$zeek"
  }
}

if ($failures -gt 0) {
  throw "$failures Phase 1 validation case(s) failed."
}

Write-Host "Phase 1 validation passed."
