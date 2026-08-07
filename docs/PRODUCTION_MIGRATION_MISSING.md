# Netra production migration: missing requirements

Audit date: 7 August 2026 (Asia/Kolkata)

Current decision: **NO-GO for migration, merge to `main`, or production deployment.**

This file records names and status only. Never add credential values here.

## Blocking findings

| Area | Verified state | Required before production |
|---|---|---|
| Source Supabase quota | The legacy project dashboard says services are restricted because the organization has used its quota. | Wait for the quota reset and confirm at least 0.75 GB of available egress before any source export or Storage download. |
| Target database | Target `frjzewpyjgirorbguegm` is healthy, but has 0 public application tables and 0 project migration records. | Create the 49 repository-backed tables, apply infrastructure migrations, then rerun advisors. |
| Target durable data | Target has 0 Auth users, 0 Auth identities, and 0 Storage objects. | Migrate and verify database data, the allowed Auth rows, and the frozen Storage manifest. |
| Target foundation | Seven expected private buckets and fourteen expected empty PGMQ queues exist. Security and performance advisors are clean for the currently empty target. | Preserve these names; do not treat this partial foundation as a completed migration. |
| Migration credentials | The Supabase connection can verify the target and an active publishable key exists. A target Session Pooler password/URL and target service-role/secret key are not available to the local migration scripts. | Supply both through an approved secret manager or ignored local environment file. Do not commit them. |
| Railway target | Both `netra-api` and `netra-worker` currently expose the legacy project ref `kirctxhxcmnncpuxjknw`. | Switch both services atomically to `frjzewpyjgirorbguegm` only after target acceptance checks pass. |
| Railway database aliases | `DATABASE_URL`, `SUPABASE_POOLER_DATABASE_URL`, and `SUPABASE_DIRECT_DATABASE_URL` all exist. Django selects them in that order. | Make `DATABASE_URL` the only production database URL and remove the two aliases after cutover, preventing a stale value from winning. |
| Railway region | Both services report that `us-west2` is invalid and is blocking deployments. | Select a supported Railway region, preferably the closest available region to Sydney, before pushing. |
| Railway persistent cache | No persistent volume is visible in the project architecture/settings. | Attach a volume with at least 1 GB and mount it at `/app/storage` on every service that reads immutable evidence. |
| Railway public API | `netra-api-production.up.railway.app` currently has no DNS result. | Create/restore a Railway public domain, verify `/api/health`, and then update Vercel `VITE_API_BASE_URL`. |
| Railway CI gate | `Wait for CI` is disabled on both services. | Add GitHub CI, make it required, then enable Railway `Wait for CI`. |
| Vercel production bundle | The active production bundle contains the legacy Supabase URL and the non-resolving Railway API URL; it does not contain the target project ref. | Replace the four canonical public variables below and produce a validated preview build before promotion. |
| GitHub CI | There are no GitHub Actions workflows or test check runs. `main` is not protected. The green Vercel/Railway commit statuses belong to deployed commit `370a5c0`, not the unpushed migration branch. | Add backend tests, frontend tests/build, migration-tool tests, and secret scanning; protect `main` and require the checks. |
| Migration tools | PostgreSQL 17 `psql`, `pg_dump`, and `pg_restore` are not installed locally. Supabase, Railway, and Vercel CLIs are also absent. | PostgreSQL 17 tools are mandatory for the migration scripts. Inspect current Supabase CLI help before CLI migration operations. |
| Worker topology | The only Railway worker runs `run_postgres_worker`, while the locked target configuration says `NETRA_QUEUE_PROVIDER=supabase-pgmq`. | Decide and rehearse the target worker topology. Do not set PGMQ merely to satisfy readiness while leaving all required PGMQ consumers undeployed. |
| Cutover coordination | No verified egress screenshot/value or 60-minute maintenance window is recorded. | Record both before starting the frozen export. |

## Collision-free environment-variable contract

### Railway shared variables: API and worker

Create these as Railway **shared variables** so the API and worker cannot drift.

| Variable | Required value/role | Rule |
|---|---|---|
| `DATABASE_URL` | Target PostgreSQL Session Pooler URL | Canonical database connection. Percent-encode the password. |
| `DATABASE_CONN_MAX_AGE` | `0` | Appropriate for the Supabase pooler. |
| `SUPABASE_PROJECT_REF` | `frjzewpyjgirorbguegm` | Public identifier. |
| `SUPABASE_URL` | Target project API URL | Server-side Supabase client URL. |
| `SUPABASE_ANON_KEY` | Target active publishable key | Compatibility name used by the current backend. It must not contain the secret/service-role key. |
| `SUPABASE_SERVICE_ROLE_KEY` | Target service-role/secret key | Railway only; sensitive; never add to Vercel or a `VITE_` variable. |
| `DJANGO_SECRET_KEY` | Existing production value | Preserve exactly; do not rotate during the database migration. |
| `NETRA_EVIDENCE_KEY` | Existing production value | Preserve exactly or existing encrypted evidence becomes unreadable. |
| `NETRA_EVIDENCE_KEY_ID` | Existing production value | Preserve exactly. |
| `NETRA_EVIDENCE_PREVIOUS_KEYS` | Existing production value, if any | Preserve exactly. |
| `NETRA_DATABASE_PROVIDER` | `supabase` | Must agree with `DATABASE_URL`. |
| `NETRA_DATABASE_MODE` | `supabase` | Must agree with the provider. |
| `NETRA_STORAGE_PROVIDER` | `supabase` | Durable objects remain in Supabase Storage. |
| `NETRA_AUTH_PROVIDER` | `supabase` | Supabase issues the user tokens. |
| `NETRA_ACCESS_MODE` | `supabase-auth` | Replaces the current Railway value `bearer`. |
| `NETRA_SEARCH_PROVIDER` | `postgres` | Avoid Elasticsearch infrastructure. |
| `NETRA_REALTIME_PROVIDER` | `sse` | Replaces the current Railway value `supabase`. |
| `NETRA_FREE_PLAN_GUARD` | `1` | Explicit even though `hackathon-core` also defaults it on. |
| `NETRA_STORAGE_DEEP_HEALTHCHECK` | `0` | Prevent recurring object downloads. |
| `NETRA_DIRECT_UPLOAD_ENABLED` | `0` | Keep direct browser uploads disabled. |
| `NETRA_STORAGE_ROOT` | `/app/storage` | Must match the Railway persistent-volume mount. |
| `NETRA_DEPLOYMENT_PROFILE` | `hackathon-core` | Free-plan-safe feature profile. |
| `NETRA_DEPLOYMENT_ENV` | `production` | Production behavior and reporting. |
| `NETRA_DEV_ROLE_HEADERS` | `0` | Never trust development role headers in production. |
| `NETRA_AUTH_PROXY_ENABLED` | `0` | Do not use the local-development auth proxy. |
| `NETRA_PUBLIC_API_AUTH_REQUIRED` | `1` | Require API authentication. |
| `NETRA_SUPABASE_START_WORKERS` | `0` during cutover | Enable only the reviewed worker topology after acceptance. |

Keep the existing production values for `NETRA_SENSOR_SHARED_KEY`,
`NETRA_WEBHOOK_SIGNING_SECRET`, job lease/poll values, and upload limits unless a
separate rotation or tuning change is reviewed.

Remove these Railway aliases after setting `DATABASE_URL`:

- `SUPABASE_POOLER_DATABASE_URL`
- `SUPABASE_DIRECT_DATABASE_URL`

Do not leave an old-project URL under either alias.

### Railway service-specific variables

| Service | Variable | Value/role |
|---|---|---|
| `netra-api` | `NETRA_SERVICE_KIND` | `api` |
| `netra-api` | `DJANGO_ALLOWED_HOSTS` | New Railway API domain only, plus any reviewed custom API domain. |
| `netra-api` | `DJANGO_CSRF_TRUSTED_ORIGINS` | Production Vercel/custom frontend HTTPS origins. |
| `netra-api` | `NETRA_FRONTEND_ORIGINS` | Same reviewed frontend origins for CORS. |
| `netra-api` | `NETRA_PUBLIC_BASE_URL` | Production frontend URL. |
| `netra-worker` | `NETRA_SERVICE_KIND` | `worker` for the current row-lock worker only. Change the start command when adopting PGMQ stage workers. |
| `netra-worker` | `RAILWAY_DOCKERFILE_PATH` | Keep only if Railway intentionally uses it; otherwise configure `railway.worker.json` as the service config file. |

### Vercel production variables

Only browser-safe variables belong in Vercel. Scope these to **Production**;
do not give Preview deployments production access unless a separate staging
policy is approved.

| Variable | Required value/role |
|---|---|
| `VITE_API_BASE_URL` | `https://<working-railway-api-domain>/api` |
| `VITE_DEPLOYMENT_PROFILE` | `hackathon-core` |
| `VITE_SUPABASE_URL` | Target project API URL |
| `VITE_SUPABASE_ANON_KEY` | Target active publishable key |
| `VITE_SUPABASE_REALTIME_ENABLED` | `0` |
| `VITE_NETRA_FREE_PLAN_GUARD` | `1` |
| `VITE_DIRECT_UPLOAD_ENABLED` | `0` |
| `VITE_MAX_UPLOAD_MB` | `25` |

Never add any of the following to Vercel:

- `DATABASE_URL` or either database URL alias
- `SUPABASE_SERVICE_ROLE_KEY`
- `DJANGO_SECRET_KEY`
- `NETRA_EVIDENCE_KEY` or previous evidence keys
- sensor or webhook secrets

Every `VITE_` value is public in the compiled JavaScript bundle.

### Supabase Auth dashboard settings

These are dashboard configuration, not Railway/Vercel variables:

- Auth Site URL: production frontend URL
- Allowed redirect URLs: exact production sign-in callback URLs
- Keep the target project's new JWT secret; do not copy the legacy JWT secret

## Required release order

1. Resolve the source quota and record the egress gate.
2. Fix Railway regions and add the `/app/storage` volume without switching projects.
3. Add CI and branch protection; enable Railway `Wait for CI`.
4. Provision and verify the target schema/security.
5. Freeze writes and migrate Storage, public durable data, and allowed Auth rows.
6. Validate row/hash manifests and advisors.
7. Update Railway shared variables atomically, with workers stopped.
8. Verify the new Railway domain and `/api/health`.
9. Update Vercel production variables and build a preview.
10. Smoke-test the preview, promote it, then start reviewed workers gradually.

Production is ready only when every blocking row above is resolved and the
cutover acceptance checklist in `NETRA_SUPABASE_MIGRATION_RUNBOOK.md` passes.
