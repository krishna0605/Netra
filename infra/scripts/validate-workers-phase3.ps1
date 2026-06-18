$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"

if (-not (Test-Path $envFile)) {
  throw "Missing .env.supabase.local. Start Supabase mode before validating workers."
}

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

function Invoke-BackendPython([string]$Code) {
  $tmpScript = Join-Path ([System.IO.Path]::GetTempPath()) ("netra-phase3-worker-" + [guid]::NewGuid().ToString("N") + ".py")
  try {
    [System.IO.File]::WriteAllText($tmpScript, $Code, [System.Text.UTF8Encoding]::new($false))
    docker cp $tmpScript "${backendId}:/tmp/netra-phase3-worker.py" | Out-Null
    docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py shell < /tmp/netra-phase3-worker.py"
  } finally {
    Remove-Item -LiteralPath $tmpScript -Force -ErrorAction SilentlyContinue
  }
}

Write-Host "Validating Supabase worker operations..." -ForegroundColor Cyan

Invoke-BackendPython @'
from apps.forensics.models import DeadLetterEvent, WorkerStageReceipt
from common.kafka import publish_event
from django.db import connection

success_job = "phase3-worker-success"
failure_job = "phase3-worker-dlq"

WorkerStageReceipt.objects.filter(job_id__in=[success_job, failure_job]).delete()
DeadLetterEvent.objects.filter(job_id__in=[success_job, failure_job]).delete()
with connection.cursor() as cursor:
    cursor.execute("select exists(select 1 from information_schema.tables where table_schema = 'pgmq' and table_name = 'q_worker-validation')")
    if cursor.fetchone()[0]:
        cursor.execute('delete from pgmq."q_worker-validation"')

publish_event("netra.worker.validation", {"type": "phase3.worker.validation", "jobId": success_job, "caseId": "CYB-GJ-PHASE3-WORKERS"})
publish_event("netra.worker.validation", {"type": "phase3.worker.validation", "jobId": success_job, "caseId": "CYB-GJ-PHASE3-WORKERS"})
publish_event("netra.worker.validation", {"type": "phase3.worker.validation", "jobId": failure_job, "caseId": "CYB-GJ-PHASE3-WORKERS", "forceWorkerError": True, "error": "Phase 3 forced worker failure"})
print("[PASS] validation messages published to Supabase pgmq")
'@

docker compose --env-file $envFile -f $composeFile exec -T backend python manage.py run_netra_worker parser --topic netra.worker.validation --max-messages 1 --idle-timeout 30
if ($LASTEXITCODE -ne 0) { throw "Parser worker failed while processing the first validation message." }
docker compose --env-file $envFile -f $composeFile exec -T backend python manage.py run_netra_worker parser --topic netra.worker.validation --max-messages 1 --idle-timeout 30
if ($LASTEXITCODE -ne 0) { throw "Parser worker failed while processing the duplicate idempotency message." }
docker compose --env-file $envFile -f $composeFile exec -T backend python manage.py run_netra_worker parser --topic netra.worker.validation --max-messages 1 --idle-timeout 30
if ($LASTEXITCODE -ne 0) { throw "Parser worker failed while processing the forced DLQ message." }

Invoke-BackendPython @'
from apps.forensics.models import DeadLetterEvent, WorkerHeartbeat, WorkerStageReceipt

success_job = "phase3-worker-success"
failure_job = "phase3-worker-dlq"

receipt_count = WorkerStageReceipt.objects.filter(job_id=success_job, worker_name="parser").count()
if receipt_count != 1:
    raise SystemExit(f"Expected exactly one idempotent parser receipt, found {receipt_count}.")

dlq = DeadLetterEvent.objects.filter(job_id=failure_job, worker_name="parser").order_by("-created_at").first()
if not dlq:
    raise SystemExit("Expected a dead-letter event for the forced worker failure.")
if dlq.topic != "netra.worker.validation":
    raise SystemExit(f"Dead-letter retry topic is wrong: {dlq.topic}")
if dlq.retry_count < 3:
    raise SystemExit(f"Expected retry count >= 3, got {dlq.retry_count}")

heartbeat = WorkerHeartbeat.objects.filter(worker_name="parser").order_by("-last_seen_at").first()
if not heartbeat:
    raise SystemExit("Parser worker heartbeat was not recorded.")
if heartbeat.status != "healthy":
    raise SystemExit(f"Parser heartbeat is not healthy: {heartbeat.status}")

print(f"[PASS] worker idempotency, retry, DLQ, and heartbeat verified: receipt={receipt_count} dlq={dlq.id}")
'@

$workers = Invoke-RestMethod "http://localhost:8080/api/system/workers"
if ($workers.queueProvider -ne "supabase-pgmq") {
  throw "Worker status endpoint is not reporting Supabase PGMQ."
}
if (-not (($workers.results | Where-Object { $_.name -eq "parser" }).status)) {
  throw "Parser worker is missing from /api/system/workers."
}

Write-Host "[PASS] /api/system/workers reports Supabase queue worker status"
Write-Host "Supabase worker validation passed." -ForegroundColor Green
