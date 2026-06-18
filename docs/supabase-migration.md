# Netra Supabase Mode

Supabase mode replaces local PostgreSQL, local evidence storage, Kafka, Elasticsearch, and SSE as the primary data plane.

Netra still runs backend and worker containers because PCAP analysis needs native tools such as `tshark`, Zeek, `dumpcap`, and `mergecap`.

## Verified Project

```txt
Project ref: kirctxhxcmnncpuxjknw
Region: ap-northeast-1
Database: PostgreSQL 17
```

The project was empty when inspected: no public tables, no migrations, and no Edge Functions.

## Local Secret File

Copy the template:

```powershell
Copy-Item .env.supabase.example .env.supabase.local
```

Fill in:

```txt
SUPABASE_ANON_KEY
SUPABASE_SERVICE_ROLE_KEY
DATABASE_URL
SUPABASE_DIRECT_DATABASE_URL
NETRA_EVIDENCE_KEY
NETRA_SENSOR_SHARED_KEY
DJANGO_SECRET_KEY
VITE_SUPABASE_ANON_KEY
```

Do not commit `.env.supabase.local`.

The service-role key pasted in chat should be rotated in Supabase before a shared demo.

## Start Netra

```powershell
npm run netra:start:supabase
```

This starts:

- frontend
- backend API
- optional Netra workers only when `NETRA_SUPABASE_START_WORKERS=1`

It does not start:

- local PostgreSQL
- Kafka
- Elasticsearch

## Bootstrap Supabase

The backend startup runs this automatically:

```powershell
npm run netra:bootstrap:supabase
```

It performs:

- Django migrations
- enables `pgcrypto`, `pg_trgm`, `pgmq`, and `pg_cron`
- creates private Storage buckets
- verifies private Storage buckets with upload/download/delete probes
- creates PGMQ queues
- adds Netra tables to the Supabase Realtime publication

## Supabase Auth

Create users in Supabase Dashboard:

```txt
Authentication > Users > Add user
```

Frontend login:

```txt
http://localhost:8080/login
```

Only the anon key is used in the browser. The service-role key is backend-only.

## Storage Buckets

All buckets must remain private:

```txt
netra-evidence
netra-capture-chunks
netra-analysis-chunks
netra-zeek-logs
netra-reports
netra-exports
```

Netra still encrypts evidence before uploading to Supabase Storage.

## Runtime Defaults

Supabase mode is upload-first and synchronous by default for demo reliability:

```txt
NETRA_PROCESSING_MODE=hybrid
NETRA_QUEUE_PROVIDER=supabase-pgmq
NETRA_SEARCH_PROVIDER=postgres
VITE_SUPABASE_REALTIME_ENABLED=1
```

Set `NETRA_SUPABASE_START_WORKERS=1` only after the upload-to-report path is healthy.

Realtime behavior in Supabase mode:

- Browser subscriptions are enabled for operational tables only.
- Subscribed tables are processing jobs, alerts, anomalies, capture jobs, worker heartbeats, and operational events.
- High-volume packet/session rows are not subscribed to directly.
- Polling remains the fallback if a browser Realtime connection drops.

Queue behavior in Supabase mode:

- Kafka is not required.
- `publish_event()` writes to Supabase Queues through `pgmq`.
- `/api/system/kafka` is kept as a compatibility endpoint, but reports `provider: supabase-pgmq`.
- The queue health probe performs a real `send -> read -> archive` cycle.
- Report/export workers can consume queued `report.generate` and `export.generate` messages when workers are enabled.
- Synchronous upload, report, and export remain the default officer path.

## Security Note

The frontend must use only the publishable/anon key. The backend must use the service-role key only from `.env.supabase.local`.

Supabase Advisor currently reports that Netra public tables have RLS disabled. Do not blindly enable RLS without policies, because Django backend writes may continue to work but browser Data API/Realtimes behavior can change. Before shared deployment, add a dedicated RLS migration/policy pass or move Netra operational tables to a private schema and expose only the minimum Realtime tables.

## Validation

```powershell
npm run netra:validate:supabase
```

Optional login validation:

```powershell
$env:SUPABASE_TEST_EMAIL="investigator@example.com"
$env:SUPABASE_TEST_PASSWORD="..."
npm run netra:validate:supabase
```

When test credentials are provided, validation also uploads a sample PCAP, checks analysis output, generates a report, and generates an evidence export.
