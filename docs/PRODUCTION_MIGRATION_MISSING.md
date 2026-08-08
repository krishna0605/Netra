# Netra production cutover status and missing requirements

Audit date: 7 August 2026 (Asia/Kolkata)

Phase 2 local update: 8 August 2026. The Phase 2 tenancy migration and code are local only. Production remains on the previously deployed 49-table schema; migration `0014`, its two new tables, and the new environment names have not been applied to Supabase or Railway.

Current decision: **the application stack is switched to the new Supabase
project, but production evidence writes remain NO-GO until the two owner
actions below are complete.**

This file records names and status only. Never add credential values here.

## Required owner actions

| Priority | Missing item | Why it matters | Required action |
|---|---|---|---|
| Blocking | Permanent Netra administrator | The migration smoke-test identity is temporary and will be removed. A public signup must never silently become Admin. | Create or identify the permanent user in target Supabase Auth, then assign its matching `forensics_userprofile.role` to `Admin` through a reviewed server-side operation. |
| Blocking for evidence processing | Railway persistent cache volume | `NETRA_STORAGE_ROOT=/app/storage` is configured, but no Railway volume is visibly attached. Without it, an instance restart loses the immutable-object cache and can repeat Storage downloads. | Attach at least 1 GB to `/app/storage` on every service that reads evidence, then restart and verify persistence. Confirm any Railway cost before creating it. |
| Operational | Source retirement decision | This execution used the new project as a fresh start and did not read legacy Storage or export legacy rows. | Keep the legacy project untouched until you explicitly approve archival/deletion. Rotate or revoke legacy deployment credentials after the rollback window. |
| Phase 2 activation | Administrator TOTP/AAL2 enrollment | Phase 2 blocks user and administrator mutations unless the verified Supabase token has `aal2`. | Enroll and verify a TOTP factor for the permanent Admin before any future Phase 2 deployment. Do not place factor secrets in this file. |
| Local test environment | Disposable PostgreSQL 17 test credential | PostgreSQL 17 is installed locally on port 5434, but no approved credential is available for the row-lock concurrency rehearsal. | Supply an approved disposable local database credential or create a disposable local test database before the future push gate. Do not use Supabase free-plan egress for this test. |
| Release governance | Phase 7 CI and branch protection | Phase 2 is locally green, but required CI/security scans and protected-main workflow are not yet installed. | Complete Phases 3–7 before pushing this branch or opening the production PR. |

## Completed cutover work

| Area | Verified state |
|---|---|
| Target Supabase | Healthy project `frjzewpyjgirorbguegm` in Sydney (`ap-southeast-2`). |
| Database | 49 public tables, 31 Django migration rows including all 13 forensics migrations, and RLS enabled on all 49 tables. |
| Data API security | Public/`anon`/`authenticated` privileges revoked; Netra tables are not published to Supabase Realtime. |
| Storage | Seven private buckets exist, zero objects for the fresh start, and routine health checks are metadata-only. |
| Queues | Fourteen canonical PGMQ queues exist empty. Production processing currently uses the reviewed `postgres-row-lock` worker because only one matching Railway worker is deployed. |
| Supabase credentials | Target publishable key, dedicated modern backend secret key, and Session Pooler connection are installed in secret managers; no values are committed. |
| Supabase Auth | Production site/redirect URL points to the Vercel application. Target token login and backend token validation were smoke-tested. |
| Railway API | `https://netra-api-production.up.railway.app/api/health` returns HTTP 200. Target Postgres, Auth, Storage, encryption, and worker checks pass. |
| Railway worker | `netra-worker` is online and its latest deployment is successful. |
| Vercel | Production and Preview use the new Supabase URL/publishable key, the Railway API URL, Realtime disabled, and direct upload disabled. |
| Production bundle | HTTP 200; contains target ref `frjzewpyjgirorbguegm` and does not contain legacy ref `kirctxhxcmnncpuxjknw`. |
| GitHub | Migration PR #1 merged to `main`; CodeRabbit and Vercel checks passed. |
| Egress | No legacy database export or Storage object download was performed. Legacy migration egress consumed by this fresh-start cutover: zero. |

## Collision-free environment-variable contract

### Railway shared variables: API and worker

| Variable | Production contract |
|---|---|
| `DATABASE_URL` | New project Session Pooler URL; the only database URL. |
| `DATABASE_CONN_MAX_AGE` | `0` for the pooler. |
| `SUPABASE_PROJECT_REF` | `frjzewpyjgirorbguegm`. |
| `SUPABASE_URL` | New project API URL. |
| `SUPABASE_ANON_KEY` | New publishable key; compatibility variable used by the backend. |
| `SUPABASE_SECRET_KEY` | Dedicated `sb_secret_...` backend key; Railway only. |
| `NETRA_DATABASE_PROVIDER` / `NETRA_DATABASE_MODE` | `supabase`. |
| `NETRA_STORAGE_PROVIDER` | `supabase`. |
| `NETRA_AUTH_PROVIDER` | `supabase`. |
| `NETRA_ACCESS_MODE` | `bearer`; this is the HTTP transport mode, not the provider name. |
| `NETRA_QUEUE_PROVIDER` | `postgres-row-lock` while `run_postgres_worker` is the deployed worker. |
| `NETRA_REALTIME_PROVIDER` | `sse`. |
| `NETRA_SEARCH_PROVIDER` | `postgres`. |
| `NETRA_FREE_PLAN_GUARD` | `1`. |
| `NETRA_STORAGE_DEEP_HEALTHCHECK` | `0`. |
| `NETRA_DIRECT_UPLOAD_ENABLED` | `0`. |
| `NETRA_STORAGE_ROOT` | `/app/storage`; requires the owner volume action above. |
| `NETRA_DEPLOYMENT_PROFILE` | `hackathon-core`. |
| `NETRA_DEPLOYMENT_ENV` | `production`. |
| `NETRA_DEV_ROLE_HEADERS` | `0`. |
| `NETRA_AUTH_PROXY_ENABLED` | `0`. |
| `NETRA_PUBLIC_API_AUTH_REQUIRED` | `1`. |
| `NETRA_SUPABASE_START_WORKERS` | `0`; the existing Railway worker service owns processing. |
| `NETRA_RATE_LIMITS_ENABLED` | Future Phase 2 value `1`; Railway backend only. Not deployed yet. |
| `NETRA_RATE_LIMIT_READ_PER_MINUTE` / `NETRA_RATE_LIMIT_MUTATION_PER_MINUTE` | Future defaults `300` / `60`; Railway backend only. |
| `NETRA_RATE_LIMIT_UPLOAD_USER_PER_HOUR` / `NETRA_RATE_LIMIT_UPLOAD_ORG_PER_HOUR` | Future defaults `10` / `25`; Railway backend only. |
| `NETRA_RATE_LIMIT_REPORT_USER_PER_HOUR` / `NETRA_RATE_LIMIT_EXPORT_USER_PER_HOUR` | Future defaults `10` / `10`; Railway backend only. |
| `NETRA_RATE_LIMIT_WEBHOOK_TEST_ADMIN_PER_HOUR` | Future default `5`; Railway backend only. |

The following remain secret-manager-only and were rotated for the fresh target:

- `DJANGO_SECRET_KEY`
- `NETRA_EVIDENCE_KEY`
- `NETRA_EVIDENCE_KEY_ID`
- `NETRA_EVIDENCE_PREVIOUS_KEYS`, when used
- `NETRA_SENSOR_SHARED_KEY`
- `NETRA_WEBHOOK_SIGNING_SECRET`

The stale aliases `SUPABASE_POOLER_DATABASE_URL`,
`SUPABASE_DIRECT_DATABASE_URL`, and `SUPABASE_SERVICE_ROLE_KEY` have been
removed from Railway so they cannot override the target.

### Railway service-specific variables

| Service | Variable | Value/role |
|---|---|---|
| `netra-api` | `NETRA_SERVICE_KIND` | `api` |
| `netra-api` | `DJANGO_ALLOWED_HOSTS` | Railway API host only. |
| `netra-api` | `DJANGO_CSRF_TRUSTED_ORIGINS` | Exact production Vercel HTTPS origin. |
| `netra-api` | `NETRA_FRONTEND_ORIGINS` | Exact production Vercel HTTPS origin. |
| `netra-api` | `NETRA_PUBLIC_BASE_URL` | Production Vercel URL. |
| `netra-worker` | `NETRA_SERVICE_KIND` | `worker`. |

### Vercel public variables

| Variable | Production value/role |
|---|---|
| `VITE_API_BASE_URL` | `https://netra-api-production.up.railway.app/api` |
| `VITE_DEPLOYMENT_PROFILE` | `hackathon-core` |
| `VITE_SUPABASE_URL` | New target project API URL. |
| `VITE_SUPABASE_ANON_KEY` | New target publishable key. |
| `VITE_SUPABASE_REALTIME_ENABLED` | `0` |
| `VITE_NETRA_FREE_PLAN_GUARD` | `1` |
| `VITE_DIRECT_UPLOAD_ENABLED` | `0` |
| `VITE_MAX_UPLOAD_MB` | `25` |

Never add `DATABASE_URL`, `SUPABASE_SECRET_KEY`, Django/evidence keys, sensor
keys, or webhook secrets to Vercel. Every `VITE_` value is public in the
compiled browser bundle.

## Release acceptance snapshot

- Target project health, schema, RLS, buckets, queue names, and Realtime posture
  match the fresh-start contract.
- Authenticated production `/api/auth/me` returned HTTP 200 with a temporary,
  explicitly server-provisioned Admin profile.
- Production deep health passed Postgres, target Storage metadata access,
  encryption, Auth/RBAC, and the deployed worker. Zeek is not installed in the
  hackathon image and is reported as an optional degraded packet tool.
- Frontend tests: 10/10 passed; production build passed.
- Targeted backend migration/security tests: 28/28 passed.
- Full backend suite: 35/37 passed locally; only the two `tshark`-dependent
  PCAP tests failed because this workstation lacks the executable.

Phase 2 local verification supersedes the old workstation result above: Wireshark 4.6.6 is now available and the complete backend suite passes 90/90. PostgreSQL concurrency rehearsal remains outstanding for the separate credential reason listed above.

Production evidence writes may open only after the permanent Admin and
persistent Railway volume are verified. No source-data migration is implied by
this fresh-start cutover.
