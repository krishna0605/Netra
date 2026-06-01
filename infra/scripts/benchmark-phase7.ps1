$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$out = Join-Path $root ("docs\benchmarks\phase7-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".md")
New-Item -ItemType Directory -Force (Split-Path $out) | Out-Null
$capacity = Invoke-RestMethod "http://localhost:8080/api/system/capacity"
$throughput = Invoke-RestMethod "http://localhost:8080/api/system/throughput"
$workers = Invoke-RestMethod "http://localhost:8080/api/system/workers"
$lines = @(
  "# Netra Phase 7 Local Benchmark",
  "",
  "Generated: $(Get-Date -Format o)",
  "",
  "## Capacity Snapshot",
  "",
  "- Capacity status: $($capacity.status)",
  "- Storage used percent: $($capacity.storage.usedPercent)",
  "- Kafka lag: $($capacity.kafka.lag)",
  "- Sensors total: $($capacity.sensors.total)",
  "- Sensors capturing: $($capacity.sensors.capturing)",
  "",
  "## Throughput Snapshot",
  "",
  "- Chunks per minute: $($throughput.chunksPerMinute)",
  "- Packets indexed per minute: $($throughput.packetsIndexedPerMinute)",
  "- Worker rows: $($workers.results.Count)",
  "",
  "## Notes",
  "",
  "Run this command while replay feeds or bounded captures are active for representative throughput."
)
$lines | Set-Content -Encoding UTF8 $out
Write-Host "Benchmark snapshot written to $out" -ForegroundColor Green
