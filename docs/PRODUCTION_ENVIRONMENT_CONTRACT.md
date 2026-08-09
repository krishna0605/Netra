# Netra production environment contract

This file records variable ownership and validation only. It must never contain deployed values.

## Railway API and worker

Both backend services receive the target database connection, Supabase Auth configuration, server-only Storage key, evidence-encryption keys, custody-signing keys, and `NETRA_RELEASE_ID`. Secret values remain in Railway's secret manager.

The API uses `NETRA_RUNTIME_ROLE=api`; the worker uses `NETRA_RUNTIME_ROLE=worker`. Hosted services use `NETRA_PROCESSING_MODE=postgres-worker`, `NETRA_QUEUE_PROVIDER=postgres-row-lock`, and `NETRA_SYNC_FALLBACK_ENABLED=0`.

Only the worker receives parser limits and required TShark/Zeek versions. `/app/storage` is the persistent cache contract. Routine startup and readiness checks inspect metadata only and never download an object.

### Shared backend variables

| Variable | Scope | Contract |
|---|---|---|
| `NETRA_RELEASE_ID` | API + worker | Same immutable release identifier during normal operation |
| `NETRA_PROCESSING_MODE` | API + worker | `postgres-worker` in hosted environments |
| `NETRA_QUEUE_PROVIDER` | API + worker | `postgres-row-lock` for analysis-job acquisition |
| `NETRA_SYNC_FALLBACK_ENABLED` | API + worker | `0`; hosted synchronous PCAP analysis is forbidden |
| `NETRA_STORAGE_ROOT` | Storage consumers | `/app/storage` on a verified persistent volume |
| `NETRA_STORAGE_CACHE_ENABLED` | Storage consumers | `1` in production |
| `NETRA_STORAGE_CACHE_MAX_BYTES` | Storage consumers | Reviewed default `629145600` |
| `NETRA_STORAGE_CACHE_MIN_FREE_BYTES` | Storage consumers | Reviewed default `209715200` |
| `NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS` | Storage consumers | Reviewed default `3600` |
| `NETRA_STORAGE_CACHE_TOUCH_INTERVAL_SECONDS` | Storage consumers | Reviewed default `60` |
| `NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS` | Storage consumers | Reviewed default `30` |
| `NETRA_REALTIME_PROVIDER` | API + worker | `sse`; browser database Realtime is not compiled into the frontend |
| `NETRA_SEARCH_PROVIDER` | API + worker | `postgres` for the Free/Hobby profile |
| `NETRA_ENABLE_STRUCTURED_IMPORTS` | API + worker | `0` until the 25 MiB import workflow is explicitly approved |
| `NETRA_ENABLE_INTEGRATIONS` | API + worker | `0` until outbound delivery is explicitly approved |
| `NETRA_WEBHOOK_ALLOWED_HOSTS` | API + worker | Empty while disabled; otherwise exact comma-separated HTTPS hostnames |

### Railway API-only variables

| Variable | Contract |
|---|---|
| `NETRA_RUNTIME_ROLE` | `api` |
| `NETRA_WORKER_STALE_AFTER_SECONDS` | Reviewed default `45` |
| `NETRA_WORKER_CAPACITY_CACHE_SECONDS` | Reviewed default `10` |

The API must not receive parser executable paths or parser resource-limit settings. It must start and pass imports when TShark, Zeek, tcpdump, and Scapy are absent.

### API stream and webhook limits

| Variable | Reviewed default | Scope |
|---|---:|---|
| `NETRA_RATE_LIMIT_SSE_USER_PER_MINUTE` | `12` | API only |
| `NETRA_RATE_LIMIT_SSE_ORG_PER_MINUTE` | `60` | API only |
| `NETRA_SSE_MAX_SECONDS` | `300` | API only |
| `NETRA_SSE_HEARTBEAT_SECONDS` | `15` | API only |
| `NETRA_SSE_POLL_SECONDS` | `5` | API only |
| `NETRA_SSE_BATCH_SIZE` | `100` | API only |
| `NETRA_WEBHOOK_CONNECT_TIMEOUT_SECONDS` | `3` | Worker only when integrations are enabled |
| `NETRA_WEBHOOK_READ_TIMEOUT_SECONDS` | `5` | Worker only when integrations are enabled |
| `NETRA_WEBHOOK_REQUEST_MAX_BYTES` | `262144` | Worker only when integrations are enabled |
| `NETRA_WEBHOOK_RESPONSE_MAX_BYTES` | `32768` | Worker only when integrations are enabled |
| `NETRA_WEBHOOK_MAX_ATTEMPTS` | `2` | Worker only when integrations are enabled |

Webhook signing uses a versioned, encrypted credential belonging to one organization-scoped integration. There is no shared `NETRA_WEBHOOK_SIGNING_SECRET` variable. Credential creation or replacement requires an organization Admin with AAL2.

### Railway worker-only variables

| Variable | Reviewed default |
|---|---:|
| `NETRA_RUNTIME_ROLE` | `worker` |
| `NETRA_WORKER_HEARTBEAT_SECONDS` | `15` |
| `NETRA_REQUIRED_TSHARK_VERSION` | `4.6.7` |
| `NETRA_REQUIRED_ZEEK_VERSION` | `8.2.1` |
| `NETRA_PARSER_TIMEOUT_SECONDS` | `180` |
| `NETRA_PARSER_STDOUT_MAX_BYTES` | `67108864` |
| `NETRA_PARSER_STDERR_MAX_BYTES` | `1048576` |
| `NETRA_PARSER_CPU_SECONDS` | `180` |
| `NETRA_PARSER_MEMORY_MAX_BYTES` | `536870912` |
| `NETRA_PARSER_MAX_OPEN_FILES` | `64` |
| `NETRA_PARSER_MAX_PROCESSES` | `16` |
| `NETRA_PARSER_TEMP_MAX_BYTES` | `1073741824` |

All parser variables are backend-only. None may use a `VITE_` prefix or enter Vercel.

### Railway API Auth variables

| Variable | Reviewed contract |
|---|---|
| `NETRA_MFA_POLICY` | `admin_required` |
| `NETRA_AUTH_INVITATIONS_ENABLED` | `0` until redirect, SMTP and controlled invitation gates pass |
| `NETRA_AUTH_INVITE_REDIRECT_URL` | Exact approved `https://<frontend>/auth/invite` URL |
| `NETRA_AUTH_ADMIN_TIMEOUT_SECONDS` | `5` |
| `NETRA_AUTH_ADMIN_RESPONSE_MAX_BYTES` | `65536` |
| `NETRA_AUTH_ADMIN_LIST_PAGE_SIZE` | Maximum `100` |

### Railway JWT verification variables

| Variable | Reviewed contract |
|---|---|
| `SUPABASE_URL` | Exact project API origin; also derives the issuer/JWKS origin |
| `SUPABASE_PUBLISHABLE_KEY` | Publishable Auth key; never treated as a secret |
| `SUPABASE_SECRET_KEY` | Backend-only modern secret key; never enters Vercel |
| `NETRA_SUPABASE_JWT_MODE` | `remote` until Phase 8 key verification; then `asymmetric-jwks` |
| `NETRA_SUPABASE_JWKS_CACHE_SECONDS` | `600` |
| `NETRA_SUPABASE_JWKS_TIMEOUT_SECONDS` | `3` |
| `NETRA_SUPABASE_JWKS_RESPONSE_MAX_BYTES` | `131072` |
| `NETRA_SUPABASE_JWT_AUDIENCE` | `authenticated` |
| `NETRA_SUPABASE_PRIVILEGED_VERIFY_TIMEOUT_SECONDS` | `3` |

Do not configure a legacy JWT secret or any obsolete anonymous/service-role
alias. The application never performs local HS256 verification.

The Auth Admin adapter uses the existing backend-only Supabase service-role/secret key. No second alias is created. Invitation redirect values come from backend configuration, never request JSON.

## Vercel frontend

Vercel receives only the public API URL, `VITE_SUPABASE_URL`, `VITE_SUPABASE_PUBLISHABLE_KEY`, and safe feature flags. Database URLs, Supabase secret keys, evidence keys, custody private keys, sensor secrets, and webhook secrets must never use a `VITE_` prefix or enter Vercel. No `VITE_SUPABASE_REALTIME_ENABLED` variable exists after Phase 5.

## Local concurrency tests

`backend/.env.test.example` contains disposable localhost-only values. `NETRA_TEST_POSTGRES=1` prevents the Django test runner from selecting SQLite. These credentials must never be reused outside the disposable PostgreSQL container.

## Validation

- Hosted startup fails on default application secrets, disabled encryption, non-v2 writes, or conflicting runtime roles.
- API cache-maintenance failure is degraded but Storage-dependent operations fail closed.
- Worker cache or parser-capability failure blocks worker readiness.
- Production variables are changed only during an approved deployment phase.
