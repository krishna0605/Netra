# Netra production environment contract

This file records variable ownership and validation only. It must never contain deployed values.

## Railway API and worker

Both backend services receive the target database connection, Supabase Auth configuration, server-only Storage key, evidence-encryption keys, custody-signing keys, and `NETRA_RELEASE_ID`. Secret values remain in Railway's secret manager.

The API uses `NETRA_RUNTIME_ROLE=api`; the worker uses `NETRA_RUNTIME_ROLE=worker`. Hosted services use `NETRA_PROCESSING_MODE=postgres-worker`, `NETRA_QUEUE_PROVIDER=postgres-row-lock`, and `NETRA_SYNC_FALLBACK_ENABLED=0`.

Only the worker receives parser limits and required TShark/Zeek versions. `/app/storage` is the persistent cache contract. Routine startup and readiness checks inspect metadata only and never download an object.

## Vercel frontend

Vercel receives only the public API URL, Supabase URL, publishable key, and safe feature flags. Database URLs, service-role/secret keys, evidence keys, custody private keys, sensor secrets, and webhook secrets must never use a `VITE_` prefix or enter Vercel.

## Local concurrency tests

`backend/.env.test.example` contains disposable localhost-only values. `NETRA_TEST_POSTGRES=1` prevents the Django test runner from selecting SQLite. These credentials must never be reused outside the disposable PostgreSQL container.

## Validation

- Hosted startup fails on default application secrets, disabled encryption, non-v2 writes, or conflicting runtime roles.
- API cache-maintenance failure is degraded but Storage-dependent operations fail closed.
- Worker cache or parser-capability failure blocks worker readiness.
- Production variables are changed only during an approved deployment phase.
