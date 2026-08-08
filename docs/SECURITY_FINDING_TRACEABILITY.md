# Netra security finding traceability

## Phase 1 verification record

Phase 1 is a repository-only containment release. It does not change Django models, database tables, Supabase schemas, Storage objects, Railway, Vercel, or production configuration.

| Finding | Status | Control | Regression evidence |
|---|---|---|---|
| NTR-001 | Verified | Analysis reads resolve an authenticated actor, visible workspace, and job belonging to that case. Missing or mismatched scope returns the same non-disclosing 404. | `test_analysis_case_boundaries.py` route inventory, cross-case matrix, duplicate-ID, and case+job SQL assertions |
| NTR-002 | Verified | Finding changes use exact IDs inside one locked job and update JSON, normalized rows, workspace snapshot, audit, and custody state in one transaction. Events publish after commit. | Cross-case/no-side-effect, exact-ID, rule-ID rejection, invalid-status, and selected-alert tests |
| NTR-003 | Verified | Legal/custody additions use a Django autoescaped template. Generated HTML has a restrictive CSP and no active script/form/object/event-handler content. PDF values are escaped as text. | Hostile HTML and PDF cases in `test_artifact_security.py` |
| NTR-004 | Verified | Case IDs use one strict validator. Artifact names are server-generated, extension allowlisted, resolved under one approved folder, and written through removable temporary plaintext files. | Windows, POSIX, UNC, encoded, control-character, trailing-dot/space, length, and containment tests |
| NTR-025 (authorization) | Verified for Phase 1 | Scoped analysis authorization and API behavior live in dedicated API/service modules. | Route inventory requires all canonical granular routes to use `apps.forensics.api.analysis` |

## Local commit evidence

| Commit | Purpose |
|---|---|
| `4368060` | Scope analysis reads by workspace and job |
| `c69da48` | Make finding mutations exact, atomic, case-scoped, and job-scoped |
| `8667ac0` | Validate case identifiers and contain artifact paths |
| `9918609` | Autoescape generated report supplements and apply report CSP |
| Phase 1 verification commit | Enforce final route contracts, remove optional persistence scope, and record verification |

## Acceptance evidence

- Focused backend security suite: 37 tests passed.
- Complete forensics backend suite: 60 tests passed.
- Django model check: `makemigrations --check --dry-run` reported no changes detected.
- Frontend: 11 tests passed; lint completed with one unchanged `captureJob` dependency warning; production build passed.
- Static searches found no unscoped `_analysis()`, `analysis_for_case()`, or `latest_job_for_case()` calls.
- No Supabase Storage download, database migration, cloud configuration change, deployment, or push occurred.

The local Django migration check also emitted a warning because the optional local PostgreSQL service at `localhost:5432` was unavailable. It still completed successfully and reported no model changes.

## Deferred work

- Remove compatibility routes only after a later observation phase records zero calls.
- Split the remaining monolithic operational/report/integration views in later phases.
- Address the existing frontend hook-dependency and bundle-size warnings in their planned frontend/performance phase.
- Perform deployment and Supabase migration work only through their separately approved phases.

## Phase 2 verification record

Phase 2 is repository-only. Migration `0014_security_tenancy_and_rate_limits` is committed but has not been applied to Supabase, Railway, Vercel, or any production database.

| Finding/control | Status | Phase 2 control | Regression evidence |
|---|---|---|---|
| NTR-010 | Verified locally | Deterministic `Organization` ownership replaces department-string tenancy; queue capacity is stored on and locked by organization. | `test_tenancy_migration.py`, `test_organization_boundaries.py`, `test_rate_limits.py` |
| NTR-022 | Verified locally | Cases, users, memberships, upload sessions, access logs, audit exports, operational events, readiness metrics, and cache identities are organization-scoped. | Cross-organization Admin, investigator, same-department, audit, event, and membership tests |
| NTR-028 (Phase 2 portion) | Verified locally | Privileged mutations require a verified AAL2 token; the database permits at most one Admin; application readiness requires exactly one active Admin; transfer and break-glass operations are atomic and audited. | `test_admin_invariants.py` |
| Abuse resistance | Verified locally | Fixed-window user/organization limits use transactional database buckets; queue admission locks the organization before counting active jobs. | Exact-limit, rollback, window-reset, header, organization/user, and queue-idempotency tests |
| Phase 1 stabilization | Verified | Queued report format/ID, safe request IDs, and frontend structured errors were corrected without amending Phase 1 history. | `test_phase_one_stabilization.py` and frontend tests |

### Phase 2 local commits

| Commit | Purpose |
|---|---|
| `b43801a` | Close Phase 1 release blockers |
| `5fa9fde` | Add organization/rate-bucket schema and deterministic backfill |
| `9ff832d` | Enforce tenant authorization and audit privacy |
| `5948930` | Add atomic request and organization queue limits |
| `2708940` | Enforce AAL2 and administrator invariants |
| Phase 2 verification commit | Record final checks, environment contract, and rollout gates |

### Phase 2 acceptance evidence

- Complete backend suite: 90 tests passed using local SQLite plus Wireshark 4.6.6 for PCAP tests.
- Focused migration, tenancy, rate-limit, administrator, and Phase 1 suites passed.
- Frontend: 12 tests passed; lint completed with zero errors and one unchanged hook-dependency warning; production build passed.
- Django system/model checks reported no issues and no pending migrations beyond committed migration `0014`.
- Local PostgreSQL 17 is installed on port 5434, but no approved local test credential is available. PostgreSQL row-lock concurrency rehearsal therefore remains a pre-push gate; cloud Supabase was deliberately not used as a substitute.
- No Supabase database/Storage/Auth call, Storage download, Railway/Vercel mutation, deployment, branch push, or production egress occurred.

### Phase 2 deployment status

Do not push or merge this branch. Phase 3 through Phase 7, PostgreSQL 17 concurrency rehearsal, CI/security scanning, branch protection, preview validation, MFA enrollment UX, and the reviewed migration window remain mandatory gates.
