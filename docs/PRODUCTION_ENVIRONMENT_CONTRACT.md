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

### Railway API-only variables

| Variable | Contract |
|---|---|
| `NETRA_RUNTIME_ROLE` | `api` |
| `NETRA_WORKER_STALE_AFTER_SECONDS` | Reviewed default `45` |
| `NETRA_WORKER_CAPACITY_CACHE_SECONDS` | Reviewed default `10` |

The API must not receive parser executable paths or parser resource-limit settings. It must start and pass imports when TShark, Zeek, tcpdump, and Scapy are absent.

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

## Vercel frontend

Vercel receives only the public API URL, Supabase URL, publishable key, and safe feature flags. Database URLs, service-role/secret keys, evidence keys, custody private keys, sensor secrets, and webhook secrets must never use a `VITE_` prefix or enter Vercel.

## Local concurrency tests

`backend/.env.test.example` contains disposable localhost-only values. `NETRA_TEST_POSTGRES=1` prevents the Django test runner from selecting SQLite. These credentials must never be reused outside the disposable PostgreSQL container.

## Validation

- Hosted startup fails on default application secrets, disabled encryption, non-v2 writes, or conflicting runtime roles.
- API cache-maintenance failure is degraded but Storage-dependent operations fail closed.
- Worker cache or parser-capability failure blocks worker readiness.
- Production variables are changed only during an approved deployment phase.
