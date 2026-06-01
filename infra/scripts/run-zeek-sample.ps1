param(
    [string]$Pcap = "samples\pcaps\hydra_ssh.pcap"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.yml"
$pcapPath = Resolve-Path (Join-Path $repoRoot $Pcap)
$fileName = Split-Path -Leaf $pcapPath
$outputDir = Join-Path $repoRoot "storage\zeek\$($fileName -replace '[^a-zA-Z0-9_.-]', '_')"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
Set-Location $repoRoot

Write-Host "Running Zeek on $Pcap..." -ForegroundColor Cyan
docker compose -f $composeFile run --rm `
  -v "${pcapPath}:/tmp/input.pcap:ro" `
  -v "${outputDir}:/tmp/zeek-out" `
  backend sh -c "cd /tmp/zeek-out && /usr/local/zeek/bin/zeek -C -r /tmp/input.pcap"

Write-Host ""
Write-Host "Zeek logs written to: $outputDir" -ForegroundColor Green
Get-ChildItem -LiteralPath $outputDir | Select-Object Name,Length,LastWriteTime
