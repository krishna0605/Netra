# Netra production cutover status and missing requirements

Audit date: 7 August 2026 (Asia/Kolkata)

Phase 5 local update: 9 August 2026. The tenancy, custody-ordering, and durable feature migrations are local only. Production remains on the previously deployed schema; migrations `0014` through `0016`, their schema changes, and the new environment names have not been applied to Supabase or Railway. The expected repository schema after those migrations is 53 public application tables and 16 forensics migrations.

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
| Local test environment | Disposable PostgreSQL 17 concurrency evidence | Completed locally against a disposable PostgreSQL 17.6 container; no Supabase connection was used. | Repeat in Phase 7 CI using an isolated service container. Never substitute a Supabase free-plan project. |
| Phase 4 activation | Separate Railway API and worker services | Local images are split and pinned, but the Phase 4 topology has not been deployed or sized on Railway Hobby. | Confirm service separation, CPU/memory limits, worker persistent volume, and expected Hobby usage before preview deployment. |
| Phase 4 activation | Migration `0015` rehearsal | Hash-link backfill and failure cases pass locally, but production data has not been rehearsed. | Rehearse migrations `0014` and `0015` on an encrypted disposable copy, review every chain, and approve the migration window. |
| Phase 5 activation | Migration `0016` rehearsal | Durable references, imports, and tenant-owned integration changes pass locally but are not present in the hosted database. | Rehearse migrations `0014` through `0016` on an encrypted disposable copy and approve the migration window. |
| Phase 5 activation | Integration allowlist and consumer approval | Integration delivery is implemented but intentionally disabled without exact approved hosts and worker capacity. | Supply exact HTTPS hostnames, approve the worker consumer, and keep generic external sync disabled until a reviewed adapter exists. |
| Phase 6 activation | Auth redirects, SMTP, and TOTP | Invitation, password-recovery, and Administrator MFA flows require exact redirects, production email delivery, and an enrolled factor. | Configure the exact invite/recovery redirects and custom SMTP, then complete a controlled TOTP/recovery drill without recording secrets. |
| Release governance | Phase 7 CI and branch protection | Phases 1–5 are locally implemented, but required CI/security scans and protected-main workflow are not yet installed. | Complete Phases 6–7 before pushing this branch or opening the production PR. |
| Phase 3 activation | Evidence encryption key material | v2.1 writers require high-entropy active key material and a stable non-secret key ID; legacy artifacts require decrypt-only prior keys during rollback. | Provision `NETRA_EVIDENCE_KEY`, `NETRA_EVIDENCE_KEY_ID`, and reviewed previous keys through Railway secrets. Never place values in this file or Vercel. |
| Phase 3 activation | Custody signing material | External anchors cannot be signed without a 32-byte raw Ed25519 private key and stable key ID. | Provision the base64 private key and key ID through Railway secrets, enable anchors only afterward, and preserve public keys with exported anchors. |
| Phase 3 activation | Crypto migration rehearsal | The resumable command is locally implemented but has not been exercised against the target sequence or any Supabase object. | Rehearse with fake/local Storage, approve the 0.75 GB window after quota reset, then run plan-only inventory before any execution. |
| Phase 3 activation | Railway volume persistence drill | Cache logic is bounded and tested locally, but the external `/app/storage` mount contract is not proven across restarts. | Attach/verify the volume, create the sentinel, restart API and workers, and confirm cache persistence without performing a deep object probe. |

## Completed cutover work

| Area | Verified state |
|---|---|
| Target Supabase | Healthy project `frjzewpyjgirorbguegm` in Sydney (`ap-southeast-2`). |
| Hosted database snapshot | 49 public tables and the previously deployed migration set. Local migrations `0014`–`0016` are not included in this hosted snapshot. Do not describe the hosted target as 53 tables until the reviewed migration sequence is applied and verified. |
| Data API security | Public/`anon`/`authenticated` privileges revoked; Netra tables are not published to Supabase Realtime. |
| Storage | Seven private buckets exist, zero objects for the fresh start, and routine health checks are metadata-only. |
| Queues | Fourteen canonical PGMQ queues exist empty. Production processing currently uses the reviewed `postgres-row-lock` worker because only one matching Railway worker is deployed. |
| Supabase credentials | Target publishable key, dedicated modern backend secret key, and Session Pooler connection are installed in secret managers; no values are committed. |
| Supabase Auth | Production site/redirect URL points to the Vercel application. Target token login and backend token validation were smoke-tested. |
| Railway API | `https://netra-api-production.up.railway.app/api/health` returns HTTP 200. Target Postgres, Auth, Storage, encryption, and worker checks pass. |
| Railway worker | `netra-worker` is online and its latest deployment is successful. |
| Vercel | Production and Preview use the new Supabase URL/publishable key, the Railway API URL, Realtime disabled, and direct upload disabled. |
| Production bundle | HTTP 200; contains the approved target reference and does not contain `LEGACY_PROJECT_REF`. |
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
| `SUPABASE_PUBLISHABLE_KEY` | New publishable key used by backend Auth integration. |
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
| `NETRA_STORAGE_CACHE_ENABLED` | Phase 3 contract value `1`; production activation still requires the persistent-volume proof. |
| `NETRA_STORAGE_CACHE_MAX_BYTES` / `NETRA_STORAGE_CACHE_MIN_FREE_BYTES` | Phase 3 defaults `629145600` / `209715200`; Railway backend only. |
| `NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS` / `NETRA_STORAGE_CACHE_TOUCH_INTERVAL_SECONDS` / `NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS` | Phase 3 cache-maintenance values `3600` / `60` / `30`; Railway backend only. |
| `NETRA_EVIDENCE_WRITE_FORMAT` / `NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES` | Phase 3 values `v2` / `8388608`; Railway backend only. |
| `NETRA_CUSTODY_ANCHORS_ENABLED` | Value `1` only after signing material is provisioned and verified. |
| `NETRA_CUSTODY_SIGNING_PRIVATE_KEY` / `NETRA_CUSTODY_SIGNING_KEY_ID` | Phase 3 signing material; Railway secret/backend scope only. |
| `NETRA_MFA_POLICY` | Phase 6 value `admin_required`; backend-owned and never a `VITE_` variable. |
| `NETRA_AUTH_INVITATIONS_ENABLED` | Keep `0` until exact redirect URLs and custom SMTP are verified. |
| `NETRA_AUTH_INVITE_REDIRECT_URL` | Exact approved frontend `/auth/invite` URL; backend only. |
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
- per-integration webhook HMAC credentials, provisioned through the AAL2 API after integrations are approved

Stale database/key aliases from the pre-Phase-7 contract have been removed
from Railway so they cannot override the target. The canonical backend secret
name is `SUPABASE_SECRET_KEY`.

### Railway service-specific variables

| Service | Variable | Value/role |
|---|---|---|
| `netra-api` | `NETRA_RUNTIME_ROLE` | `api` |
| `netra-api` | `DJANGO_ALLOWED_HOSTS` | Railway API host only. |
| `netra-api` | `DJANGO_CSRF_TRUSTED_ORIGINS` | Exact production Vercel HTTPS origin. |
| `netra-api` | `NETRA_FRONTEND_ORIGINS` | Exact production Vercel HTTPS origin. |
| `netra-api` | `NETRA_PUBLIC_BASE_URL` | Production Vercel URL. |
| `netra-worker` | `NETRA_RUNTIME_ROLE` | `worker`. |

### Vercel public variables

| Variable | Production value/role |
|---|---|
| `VITE_API_BASE_URL` | `https://netra-api-production.up.railway.app/api` |
| `VITE_DEPLOYMENT_PROFILE` | `hackathon-core` |
| `VITE_SUPABASE_URL` | New target project API URL. |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | New target publishable key. |
| Supabase database Realtime variable | Not present; Phase 5 removed all browser database-channel code. |
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
- The Phase 4 worker image contract pins TShark 4.6.7 and Zeek 8.2.1. Neither
  tool is optional for a worker advertising full PCAP capability.
- Phase 6 local verification recorded 174 successful backend tests with four
  environment-specific skips, 42 selected PostgreSQL tests, and 24 frontend unit tests.
- Frontend lint has no warning. The initial shell is 60.85 KiB gzip and the
  direct authentication closure is 186.63 KiB gzip; the build-time budget passes.
- Production dependency advisories discovered locally remain a Phase 7
  remediation and scanning gate. Do not push until they are reviewed and cleared.
- These are local repository results, not evidence that migrations `0014`–`0016`
  or the split worker topology have been activated in production.

Production evidence writes may open only after the permanent Admin and
persistent Railway volume are verified. No source-data migration is implied by
this fresh-start cutover.
