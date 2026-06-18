# Netra Production Monitoring And Legal Evidence Readiness

This guide covers Phase 9 and Phase 10 operational controls for the Supabase-backed Netra workflow.

## Operational Readiness

Netra exposes a consolidated readiness probe:

```powershell
Invoke-RestMethod http://localhost:8080/api/system/incident-readiness
```

The response summarizes:

- cases and evidence files
- failed jobs
- unresolved dead-letter events
- denied access attempts in the last 24 hours
- operational event volume
- generated reports and exports
- worker heartbeat readiness
- retention run status

The same payload is embedded in:

```powershell
Invoke-RestMethod http://localhost:8080/api/system/health/deep
```

Operator rule:

```txt
status = ready       no immediate blockers
status = attention   investigate dead letters, failed jobs, or stale workers before starting new capture work
```

## Audit Export

Case-scoped audit export:

```powershell
Invoke-RestMethod "http://localhost:8080/api/audit/export?caseId=<CASE_ID>"
```

System-wide audit export:

```powershell
Invoke-RestMethod "http://localhost:8080/api/audit/export"
```

The export includes:

- access logs
- custody ledger events
- custody verification result
- operational events
- dead-letter summaries
- report/export metadata

The export intentionally excludes:

- Supabase service-role keys
- JWTs
- passwords
- raw PCAP bytes
- decrypted packet payloads

## Legal Review Checklist

For a case:

```powershell
Invoke-RestMethod "http://localhost:8080/api/cases/<CASE_ID>/legal-review/checklist"
```

Checklist controls:

| Control | Meaning |
|---|---|
| case-created | Case row exists and has metadata. |
| evidence-present | At least one evidence file is linked. |
| evidence-manifest | Evidence has plaintext/encrypted hash manifest. |
| custody-ledger-verified | Hash-linked ledger verifies. |
| alert-review | Alerts have been resolved or there were no alerts. |
| report-generated | HTML report artifact exists. |
| evidence-exported | JSON/CSV/CEF export exists. |
| access-logged | Access actions were recorded. |
| legal-hold | Optional case preservation flag. |

Generated HTML reports include this checklist so the report itself reflects legal-readiness state.

## Legal Hold

Enable:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8080/api/cases/<CASE_ID>/legal-hold" `
  -ContentType "application/json" `
  -Body '{"reason":"Preserve evidence pending supervisor review"}'
```

Remove:

```powershell
Invoke-RestMethod -Method Delete "http://localhost:8080/api/cases/<CASE_ID>/legal-hold"
```

Each legal-hold change writes:

- case history
- access log
- custody ledger event

## Backup And Restore

For Supabase mode, database backups are managed by Supabase. Before a shared demo or production-like run:

1. Export a Supabase database backup from the Supabase Dashboard or CLI.
2. Keep Storage buckets private.
3. Keep Netra evidence encryption key outside the repository.
4. Export a case audit bundle for each important case.
5. Test report/export download after restore.

Local Docker/native PostgreSQL scripts remain available for legacy local mode:

```powershell
npm run netra:backup
npm run netra:restore -- <backup-folder>
```

Those scripts are not the primary backup path for Supabase mode.

## Incident Response Checklist

When Technical Status shows `attention`:

1. Open Technical Status.
2. Review incident readiness recommendations.
3. Check dead-letter queue.
4. Check failed processing jobs.
5. Verify Supabase Storage and queue health.
6. Export audit bundle for affected case.
7. Place case on legal hold if evidence must be preserved.
8. Re-run validation:

```powershell
npm run netra:validate:operations
npm run netra:validate:legal
```

## Security Notes

- Rotate the Supabase service-role key before any shared demo if it was exposed.
- Keep service-role key on backend only.
- Keep Storage buckets private.
- Do not expose decrypted evidence artifacts.
- Do not claim TLS payload decryption; Netra reviews encrypted traffic metadata only.
