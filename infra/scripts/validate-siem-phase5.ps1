$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $repoRoot "infra\docker\docker-compose.supabase.yml"
$envFile = Join-Path $repoRoot ".env.supabase.local"

Write-Host "Validating Phase 5 SIEM integration path..." -ForegroundColor Cyan

$backendId = docker compose --env-file $envFile -f $composeFile ps -q backend
if (-not $backendId) {
  throw "Supabase backend container is not running. Start it with npm run netra:start:supabase."
}

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

HTTPServer(("0.0.0.0", 9901), Handler).serve_forever()
'@

$webhookJob = Start-Job -ScriptBlock { param($code) $code | python - } -ArgumentList $webhookCode
try {
  Start-Sleep -Seconds 2
  $stamp = Get-Date -Format "yyyyMMddHHmmss"
  $python = @"
import json
from django.test import RequestFactory, override_settings

from apps.forensics.models import Alert, Case, Export, IntegrationConnection, IntegrationCredential, IntegrationDelivery
from apps.forensics.views import _deliver_webhook, export_download, siem_export
from common.vault import read_encrypted_or_plain

case_id = "CYB-GJ-PHASE5-SIEM-$stamp"
case, _ = Case.objects.update_or_create(
    id=case_id,
    defaults={
        "title": "Phase 5 SIEM validation case",
        "investigator": "Phase 5 Validator",
        "status": Case.Status.OPEN,
        "priority": Case.Priority.URGENT,
    },
)
alert, _ = Alert.objects.update_or_create(
    id=f"alert-{case_id}",
    defaults={
        "case": case,
        "rule_id": "phase5-siem-rule",
        "attack_class": "Credential Brute Force",
        "severity": "high",
        "confidence": 91,
        "source_ip": "10.10.0.5",
        "destination": "10.10.0.10:22",
        "status": "confirmed",
        "explanation": "Validator alert for SIEM delivery.",
        "recommended_action": "Review authentication logs.",
    },
)

success_conn, _ = IntegrationConnection.objects.update_or_create(
    system_name="Phase 5 Validator Webhook $stamp",
    defaults={
        "status": "pending",
        "api_mode": "webhook-json",
        "config": {"url": "http://host.docker.internal:9901/alerts", "mode": "webhook-json"},
    },
)
IntegrationCredential.objects.update_or_create(
    integration=success_conn,
    defaults={"secret_label": "webhook-hmac", "secret_value": "phase5-validator-secret"},
)
payload = {
    "source": "netra",
    "caseId": case_id,
    "alertId": alert.id,
    "attackClass": alert.attack_class,
    "severity": alert.severity,
    "confidence": alert.confidence,
    "sourceIp": alert.source_ip,
    "destination": alert.destination,
}
delivery = _deliver_webhook(success_conn, payload, "alert", case=case)
if delivery.result != "success" or not delivery.response_summary.startswith("HTTP 200"):
    raise SystemExit(f"Expected successful webhook delivery, got {delivery.result}: {delivery.response_summary}")
success_conn.status = "connected"
success_conn.save(update_fields=["status", "updated_at"])

failed_conn, _ = IntegrationConnection.objects.update_or_create(
    system_name="Phase 5 Validator Failed Webhook $stamp",
    defaults={
        "status": "pending",
        "api_mode": "webhook-json",
        "config": {"url": "http://host.docker.internal:9/unreachable", "mode": "webhook-json"},
    },
)
failed = _deliver_webhook(failed_conn, payload, "alert", case=case)
if failed.result == "success":
    raise SystemExit("Unreachable webhook unexpectedly succeeded.")
retry = _deliver_webhook(failed_conn, failed.payload_json, failed.delivery_type, case=case)
if retry.result == "success":
    raise SystemExit("Retry to unreachable webhook unexpectedly succeeded.")
failed_conn.status = "failed"
failed_conn.save(update_fields=["status", "updated_at"])

if IntegrationDelivery.objects.filter(integration=success_conn, result="success").count() < 1:
    raise SystemExit("Successful delivery row missing.")
if IntegrationDelivery.objects.filter(integration=failed_conn, result="failed").count() < 2:
    raise SystemExit("Failed delivery/retry rows missing.")

factory = RequestFactory()
request = factory.post(
    "/api/integrations/siem/export",
    data=json.dumps({"caseId": case_id}),
    content_type="application/json",
)
with override_settings(NETRA_ACCESS_MODE="trusted-lan"):
    response = siem_export(request)
if response.status_code != 201:
    raise SystemExit(f"SIEM export failed with HTTP {response.status_code}: {getattr(response, 'content', b'')!r}")
export_payload = json.loads(response.content.decode("utf-8"))
export = Export.objects.get(id=export_payload["id"])
content = read_encrypted_or_plain(export.stored_path).decode("utf-8", errors="replace")
if not content.startswith("CEF:0|Netra|Network Forensics|3|"):
    raise SystemExit("Generated SIEM export is not valid CEF text.")
download_request = factory.get(f"/api/exports/{export.id}/download")
with override_settings(NETRA_ACCESS_MODE="trusted-lan"):
    download_response = export_download(download_request, export.id)
download_body = download_response.content.decode("utf-8", errors="replace")
if download_response.status_code != 200 or not download_body.startswith("CEF:"):
    raise SystemExit("CEF download endpoint did not return persisted CEF content.")

print(f"[PASS] siem validated case={case_id} successDelivery={delivery.id} failedDelivery={failed.id} export={export.id}")
"@
  $tmpScript = Join-Path ([System.IO.Path]::GetTempPath()) ("netra-phase5-siem-validator-" + [guid]::NewGuid().ToString("N") + ".py")
  try {
    [System.IO.File]::WriteAllText($tmpScript, $python, [System.Text.UTF8Encoding]::new($false))
    docker cp $tmpScript "${backendId}:/tmp/netra-phase5-siem-validator.py" | Out-Null
    docker compose --env-file $envFile -f $composeFile exec -T backend sh -c "python manage.py shell < /tmp/netra-phase5-siem-validator.py"
    if ($LASTEXITCODE -ne 0) { throw "Phase 5 SIEM Django validation failed with exit code $LASTEXITCODE." }
  } finally {
    Remove-Item -LiteralPath $tmpScript -Force -ErrorAction SilentlyContinue
  }
} finally {
  Stop-Job $webhookJob -ErrorAction SilentlyContinue | Out-Null
  Remove-Job $webhookJob -Force -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "Phase 5 SIEM validation passed." -ForegroundColor Green
