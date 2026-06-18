$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"
$manifest = Join-Path $repoRoot "samples\detection-benchmark-manifest.json"
$pcapRoot = Join-Path $repoRoot "samples\pcaps"
$outputRoot = Join-Path $repoRoot "docs\benchmarks"

Write-Host "Training and benchmarking Netra ML anomaly model..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

python -m py_compile ml-services\anomaly-engine\netra_ml\modeling.py ml-services\anomaly-engine\netra_ml\scoring.py backend\apps\forensics\management\commands\train_anomaly_model.py
Write-Host "[PASS] ML training modules compile"

$work = "/tmp/netra-ml-benchmark"
docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "rm -rf $work && mkdir -p $work/pcaps $work/output /app/ml-services/anomaly-engine/models" | Out-Null
docker cp $manifest "${backendId}:$work/manifest.json" | Out-Null
foreach ($pcap in (Get-ChildItem $pcapRoot -Filter *.pcap)) {
  docker cp $pcap.FullName "${backendId}:$work/pcaps/$($pcap.Name)" | Out-Null
}

docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py train_anomaly_model --manifest $work/manifest.json --pcap-root $work/pcaps --model-dir /app/ml-services/anomaly-engine/models --output-dir $work/output"
if ($LASTEXITCODE -ne 0) { throw "ML anomaly benchmark failed with exit code $LASTEXITCODE." }

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
$modelRoot = Join-Path $repoRoot "ml-services\anomaly-engine\models"
New-Item -ItemType Directory -Force -Path $modelRoot | Out-Null
$containerFiles = docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "ls -1 $work/output"
foreach ($file in $containerFiles) {
  $name = $file.Trim()
  if ($name) { docker cp "${backendId}:$work/output/$name" (Join-Path $outputRoot $name) | Out-Null }
}
docker cp "${backendId}:/app/ml-services/anomaly-engine/models/anomaly-model.pkl" (Join-Path $modelRoot "anomaly-model.pkl") | Out-Null
docker cp "${backendId}:/app/ml-services/anomaly-engine/models/anomaly-model.json" (Join-Path $modelRoot "anomaly-model.json") | Out-Null

Write-Host "[PASS] ML anomaly model trained and artifacts copied to ml-services\anomaly-engine\models"
Write-Host "[PASS] ML benchmark report copied to docs\benchmarks"
Write-Host "Netra ML benchmark passed." -ForegroundColor Green
