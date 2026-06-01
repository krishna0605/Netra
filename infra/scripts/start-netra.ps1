param(
    [switch]$Logs
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
Set-Location $repoRoot
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.yml"

Write-Host ""
Write-Host "Starting Netra full stack..." -ForegroundColor Cyan
Write-Host "Services: frontend, backend, postgres, elasticsearch, kafka, capture/parser/decoder/session/detection/anomaly/report workers"
Write-Host ""

docker compose -f $composeFile up --build -d --remove-orphans

Write-Host ""
Write-Host "Waiting for Django API health..." -ForegroundColor Cyan

$healthUrl = "http://localhost:8000/api/health"
$ready = $false

for ($i = 1; $i -le 60; $i++) {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 3
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

Write-Host ""
docker compose -f $composeFile ps

Write-Host ""
if ($ready) {
    Write-Host "Netra is ready." -ForegroundColor Green
} else {
    Write-Host "Netra containers started, but the API health check did not respond yet." -ForegroundColor Yellow
    Write-Host "Run 'npm run netra:logs' to inspect startup logs."
}

Write-Host ""
Write-Host "Open these URLs:" -ForegroundColor Cyan
Write-Host "  Frontend:      http://localhost:8080"
Write-Host "  Dashboard:     http://localhost:8080/app/dashboard"
Write-Host "  Upload:        http://localhost:8080/app/upload"
Write-Host "  Backend API:   http://localhost:8000/api/health"
Write-Host "  Elasticsearch: http://localhost:9200"
Write-Host ""
Write-Host "Upload a PCAP from PowerShell:" -ForegroundColor Cyan
Write-Host '  curl.exe -F "caseId=CYB-GJ-HYDRA-0001" -F "file=@samples\pcaps\hydra_ssh.pcap" http://localhost:8000/api/evidence/upload'
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "  npm run netra:logs"
Write-Host "  npm run netra:stop"
Write-Host ""

if ($Logs) {
    docker compose -f $composeFile logs -f --tail=120
}
