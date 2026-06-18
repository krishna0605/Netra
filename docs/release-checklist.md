# Netra Release Checklist

Use this checklist before handing Netra to judges, officers, or another operator.

## 1. Build And Static Checks

```powershell
python -m py_compile backend\common\cors.py backend\common\readiness.py backend\apps\forensics\views.py
cd frontend
npm run build
cd ..
```

Expected:

- Backend modules compile.
- Frontend build succeeds.
- No service-role key appears in frontend source or build output.

## 2. Secrets

- [ ] `SUPABASE_SERVICE_ROLE_KEY` was rotated after development exposure.
- [ ] `.env.supabase.production.local` is not committed.
- [ ] `DJANGO_SECRET_KEY` is strong and non-default.
- [ ] `NETRA_EVIDENCE_KEY` is strong, backed up offline, and mapped to `NETRA_EVIDENCE_KEY_ID`.
- [ ] `NETRA_SENSOR_SHARED_KEY` is unique to this installation.
- [ ] `NETRA_WEBHOOK_SIGNING_SECRET` is unique to this installation.
- [ ] No secrets are included in reports, audit exports, screenshots, or browser logs.

## 3. Supabase

- [ ] Supabase Auth contains only approved users.
- [ ] Public signup is disabled unless explicitly required.
- [ ] Private Storage buckets exist and are private.
- [ ] PGMQ extension is enabled.
- [ ] Realtime publication contains only low-volume operational tables.
- [ ] RLS/Data API exposure reviewed before any public deployment.

## 4. Deployment

```powershell
npm run netra:start:production
npm run netra:validate:production
```

Expected:

- Frontend is reachable at `NETRA_PUBLIC_BASE_URL`.
- Backend is internal to Docker and not published directly.
- Production compose does not include local PostgreSQL, Kafka, or Elasticsearch.
- Deployment readiness endpoint is reachable.

## 5. End-To-End Officer Smoke Test

```powershell
npm run netra:validate:supabase
```

For full coverage, set:

```env
SUPABASE_TEST_EMAIL=
SUPABASE_TEST_PASSWORD=
```

Expected:

- Supabase login works.
- PCAP upload creates case/evidence/manifest rows.
- tshark/Zeek analysis completes.
- Alerts, anomalies, sessions, and packet metadata persist.
- Report, JSON export, alert CSV, custody verification, replay, sensor test path, and CEF export pass.

## 6. Legal Evidence Review

- [ ] Evidence manifest contains plaintext hash, encrypted hash, key ID, and manifest hash.
- [ ] Custody ledger verifies.
- [ ] Legal review checklist is visible in Evidence Report.
- [ ] Audit export excludes secrets and raw PCAP payload bytes.
- [ ] Report contains custody summary and legal review status.
- [ ] Legal hold is enabled for cases that must not be purged.

## 7. Incident Readiness

- [ ] Technical Status shows incident readiness.
- [ ] Dead-letter queue is empty or reviewed.
- [ ] Failed jobs are reviewed.
- [ ] Denied actions are visible in audit logs.
- [ ] Operator knows how to stop, restart, and collect logs:

```powershell
npm run netra:logs
npm run netra:stop
```

## 8. Final Handoff Notes

- Stored PCAP upload is the primary reliable workflow.
- Sensor capture and replay are advanced workflows.
- Public internet deployment is not approved until a security review is complete.
- Detection output is evidence-assisting, not a standalone legal conclusion.
