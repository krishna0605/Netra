# Netra Phase 5 Verification

## Outcome

Phase 5 is implemented and verified locally on `codex/netra-security-remediation`. It adds truthful feature capability reporting, durable scoped references and structured imports, organization-safe integrations, bounded authenticated SSE, scoped search, and URL-scoped capture control.

The hosted environment was not contacted. Migration `0016_analysis_references_and_integration_links` has not been applied to Supabase, and no Railway, Vercel, GitHub, Storage, Auth, Realtime, or database configuration was changed.

## Expected schema state

| Contract | Phase 5 value |
|---|---:|
| Public application tables | 53 |
| Forensics migrations | 16 |
| Latest migration | `0016_analysis_references_and_integration_links` |
| Materialized views | 0 |

The two new public tables are `forensics_analysisreference` and `forensics_integrationcaselink`. Migration `0016` also tenant-scopes integrations, adds durable delivery leases and idempotency, records processing operation kinds, and introduces encrypted integration-credential envelope metadata.

## Finding closure

| Finding | Local status | Evidence |
|---|---|---|
| NTR-008 | Verified | Exact-host HTTPS allowlist, unsafe-address rejection, DNS revalidation, pinned TLS connection, no redirects, bounded request/response, encrypted per-integration HMAC credential, and durable leased delivery |
| NTR-009 | Verified | Authenticated case-scoped SSE, connection rate limits, resume cursor, heartbeat, capped batches, minimal payloads, and five-minute termination |
| NTR-011 | Verified | Mandatory workspace/job scope, bounded Postgres search, and fixed-field Elasticsearch query construction without raw `query_string` |
| NTR-012 | Verified | Frontend Supabase database Realtime channels and related Vite configuration removed; authenticated Django SSE is authoritative |
| NTR-018 | Verified | Capture-stop identity comes from the workspace/job URL; body-supplied job IDs are rejected |
| NTR-024 | Verified | Success and 202 responses require committed durable state and a local consumer; absent external sync returns 501 and disabled features return 503 |

## Local commit sequence

1. `fix(operations): close phase one-to-four carryover gaps`
2. `feat(capabilities): publish authoritative feature availability`
3. `feat(schema): add durable references and tenant integration links`
4. `feat(imports): persist scoped references and structured log jobs`
5. `fix(integrations): enforce tenant-safe ssrf-resistant delivery`
6. `feat(realtime): add bounded authenticated sse refresh`
7. `fix(search): require scoped queries and capture job urls`
8. `fix(frontend): honor capabilities and remove realtime channels`
9. `docs(security): record phase five verification and handoff`

## Verification boundary

Tests use local SQLite, a disposable local PostgreSQL 17 container, mocked DNS/socket/TLS, local encrypted files, and synthetic in-memory PCAP/PCAPNG fixtures. Network-facing test providers fail closed unless explicitly replaced by a fake.

The final verification record includes:

- 166 successful backend tests with four expected environment-specific skips;
- Django model and migration checks;
- 20 successful PostgreSQL concurrency, capability, integration-delivery, and migration-0016 tests;
- 18 successful frontend unit tests, lint with no errors and one unchanged hook warning, and a successful production build;
- a local rendered-page smoke check with no browser errors;
- static scans for deleted Realtime code, raw Elasticsearch syntax, body-scoped capture IDs, stale topology claims, and secret-bearing configuration;
- repository diff, status, and local commit history.

## Free-plan and deployment status

Phase 5 implementation consumed zero Supabase project egress because it made no Supabase project call. Hosted defaults keep structured imports and integrations disabled, use Postgres search, disable browser database Realtime, and require an exact webhook hostname allowlist before integration delivery can start.

This branch is not eligible for push or merge. Remaining gates are:

1. Phase 6 frontend architecture, MFA enrollment/recovery, and accessibility.
2. Phase 7 JWT/header hardening, CI, dependency/security scans, and branch protection.
3. Railway API/worker sizing and `/app/storage` persistence proof.
4. Supabase hardening for all 53 tables.
5. Disposable rehearsal and approved application of migrations `0014` through `0016`.
6. Controlled data migration and cutover under the separately approved 0.75 GB ceiling.
