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

## Phase 3 verification record

Phase 3 is repository-only. No crypto migration was executed against Supabase, no Storage object was downloaded, no cloud configuration changed, and no deployment or push occurred. Public tables remain 51 and Django forensics migrations remain 14.

| Finding | Status | Phase 3 control | Regression evidence |
|---|---|---|---|
| NTR-005 | Verified locally | Legacy Fernet derivation is isolated behind a decrypt-only reader. All durable producers use authenticated `netra-artifact-v2.1` manifests, artifact-specific HKDF domains, random data keys, AES-256-GCM chunks, and immutable object paths. | `test_crypto_v2.py`, `test_crypto_migration.py`, artifact security and worker tests |
| NTR-017 | Superseded by Phase 4 correction | Phase 3's timestamp/random-ID ordering failed under tied timestamps. Phase 4 replaces it with a migrated monotonic per-case `chain_index`. | See the Phase 4 verification record below. |
| NTR-027 | Verified locally | v2.1 encryption and legacy migration use bounded chunk processing; temporary plaintext is permission-restricted and removed in `finally`. | Empty, boundary, multi-chunk, no-`read_bytes`, authentication-failure, and resume safety tests |
| NTR-029 | Verified locally | The persistent encrypted cache verifies local size/hash, collapses parallel misses, holds entry leases, performs LRU eviction, preserves a hard free-space reserve, and prohibits uncached fallback. | `test_storage_provider.py` zero-second-GET, concurrency, corruption, capacity, lease, and stale-partial tests |
| Public documentation | Verified locally | Root README uses Netra-only branding, synthetic content, five locally decoded direct QR assets, explicit controlled-demo limitations, and no committed source reports/decks. | `docs/assets/readme/ASSET_PROVENANCE.md` and staged-asset audit |

### Phase 3 local commits

| Commit | Purpose |
|---|---|
| `fa1bd2d` | Make authenticated v2.1 the only durable artifact write format |
| `a0569ee` | Add explicit, resumable, egress-capped legacy crypto migration |
| `307c457` | Serialize custody appends and add signed external anchors |
| `f870fc1` | Add bounded persistent encrypted object cache |
| `6cdc87c` | Publish the sanitized README and direct QR assets |
| Phase 3 verification commit | Record recovery, key, egress, verification, and handoff gates |

### Phase 3 acceptance evidence

- Focused crypto, migration, anchor, and cache unit tests pass locally.
- Historical note: Phase 3 initially reported a blocked monolithic Windows analysis/Scapy import. Phase 4 removes parser-heavy API imports and reruns the complete suite; current evidence is recorded below.
- New v2.1 writes never call Fernet; legacy fixtures remain decryptable through the explicit legacy reader.
- Plan-only crypto migration makes zero Storage calls and creates no state file.
- Five parallel cache misses produce one mocked GET; a verified repeat read produces zero GETs.
- QR codes decode locally to the five approved direct destinations; image EXIF is empty and all README local links resolve.
- The PostgreSQL 17 fifty-writer custody test is committed but remains an external pre-push gate because no approved disposable PostgreSQL credential is available.
- No Supabase, Railway, Vercel, or GitHub mutation occurred.

### Phase 3 deployment status

Do not push or merge this branch. The real crypto migration, Railway volume persistence drill, production key provisioning, PostgreSQL locking rehearsal, Phases 4-7, CI/security scanning, and protected-main workflow remain mandatory gates.

## Phase 4 verification record

Phase 4 is repository-only. Migration `0015_custody_chain_index` is committed locally but has not been applied to Supabase or any hosted database. No cloud credential was loaded, no Supabase object was listed or downloaded, and no Railway, Vercel, GitHub, or Supabase configuration changed.

| Finding/control | Status | Phase 4 control | Regression evidence |
|---|---|---|---|
| V-01 / NTR-017 | Verified locally | Custody order uses a unique monotonic `chain_index` per case. Migration backfill reconstructs only complete, unbranched hash-linked histories and aborts on ambiguity. | `test_custody_migration.py`, SQLite tied-time test, PostgreSQL 50-writer test |
| V-02 | Verified locally | Rate-limit, queue-quota, Admin-transfer, and custody invariants run against disposable PostgreSQL 17.6. | `test_postgres_concurrency.py`, `test_custody_concurrency.py` |
| V-03 through V-07 | Verified locally | Test documentation is current, operational contracts exist, legacy crypto labels fail closed, and recoverable cache maintenance degrades API readiness without terminating safe metadata service. | `test_phase_four_operations.py`, environment/cutover documents |
| NTR-006 / NTR-013 | Verified locally | Production processing is worker-only; API imports no parser-heavy analysis module and cannot synchronously process a capture. | `test_processing_topology.py`, API image binary/import checks |
| NTR-007 | Verified locally | The central parser runner uses argument arrays, an allowlisted environment, no shell, bounded output/time/resources, process-group termination, and fail-closed parsing. | `test_analysis_tooling.py` |
| NTR-014 | Verified locally | Worker heartbeat publishes exact release/parser capabilities; readiness and admission reject missing, stale, or mismatched workers. | `test_worker_capabilities.py`, in-container version checks |
| NTR-015 | Verified locally | Executable pickle/joblib model loading and the tracked model artifact are removed. ML readiness reports insufficient training data. | Static scans and `test_detector_registry.py` |
| NTR-016 | Verified locally | One canonical detector registry drives evaluation, normalized findings, API metadata, and reporting labels with per-entity confidence. | `test_detector_registry.py` |

### Phase 4 local commits

| Commit | Purpose |
|---|---|
| `f4885cb` | Add deterministic per-case custody ordering and migration 0015 |
| `926b35c` | Add PostgreSQL concurrency evidence |
| `49cbd00` | Close Phase 0–3 operational gaps |
| `3ea5241` | Enforce worker-only production processing |
| `d9ddc5f` | Isolate and bound parser subprocesses |
| `37b4f89` | Publish verified worker capacity |
| `962f4c3` | Remove executable models and unify detector truth |
| `27239a4` | Build separate pinned API and worker images |
| Phase 4 verification commit | Record complete verification and handoff evidence |

### Phase 4 deployment status

Do not push or merge this branch. Phases 5–7, MFA enrollment/recovery UX, CI and security scanning, protected `main`, migration rehearsal, Railway service/volume verification, and a controlled deployment approval remain mandatory gates.

## Phase 5 verification record

Phase 5 is repository-only. Migration `0016_analysis_references_and_integration_links` is committed locally but has not been applied to Supabase or another hosted database. Expected application state is 53 public tables and 16 forensics migrations. No materialized view was added.

| Finding/control | Status | Phase 5 control | Regression evidence |
|---|---|---|---|
| NTR-008 | Verified locally | Webhooks require an exact HTTPS hostname allowlist, reject IP literals and unsafe/mixed DNS answers, reject changed DNS answers, pin the validated address with hostname TLS verification, refuse redirects, bound bodies/responses/timeouts/retries, and require an encrypted per-integration HMAC credential. | `test_integration_delivery.py` destination, rebinding, idempotency, credential, lease, and PostgreSQL claim tests |
| NTR-009 | Verified locally | Django SSE requires authenticated case scope, applies connection-start user/organization limits, emits minimal invalidations, supports `Last-Event-ID`, heartbeats and retry hints, caps batches, and terminates after five minutes. | `test_sse_contract.py` and `frontend/src/lib/eventStream.test.ts` |
| NTR-011 | Verified locally | Search requires workspace and processing-job scope. Elasticsearch, when separately enabled, uses fixed fields with mandatory case/job filters and `simple_query_string`; Postgres is the production fallback. | Phase 5 feature/search tests and static query scan |
| NTR-012 | Verified locally | All browser `.channel()` and `postgres_changes` code and its Vite variable were deleted. Authenticated fetch-stream SSE is authoritative, with five-minute polling retained as a low-frequency fallback. | Frontend static scan, 18 unit tests, lint and build |
| NTR-018 | Verified locally | Capture stop resolves case and job only from the canonical scoped URL. Legacy body-provided job IDs return `400 scope_required` without state change. | `test_phase_five_features.py` |
| NTR-024 | Verified locally | Capability state is server-authored; accepted imports, references, links and deliveries have committed rows/consumers; absent external sync returns honest 501; disabled features return 503. | `test_feature_contracts.py`, schema/import/integration suites |
| Phase 1–4 closure | Verified locally | Stale Kafka, PGMQ, synchronous fallback, Scikit-learn, optional-Zeek and frontend Realtime claims were removed or corrected. Offline fixtures no longer initialize Windows live-capture drivers. | Full 166-test suite, topology tests and static scans |

### Phase 5 local commits

| Commit | Purpose |
|---|---|
| `ea4f014` | Close Phase 1–4 operational carryovers |
| `41a533d` | Publish authoritative capability state |
| `0415c36` | Add migration 0016 and durable tenant-owned schema |
| `3ee84b0` | Persist scoped references and structured import jobs |
| `8255e27` | Add encrypted tenant-safe webhook delivery |
| `cd51519` | Add bounded authenticated SSE |
| `1407e89` | Scope search and capture-stop URLs |
| `3168efb` | Remove browser database Realtime and consume capability/SSE contracts |
| Phase 5 verification commit | Close PostgreSQL/SSRF/test-isolation findings and record handoff evidence |

### Phase 5 acceptance evidence

- Complete backend suite: 166 tests passed with four expected environment-specific skips.
- Disposable PostgreSQL 17 suite: 20 tests passed, including database concurrency invariants plus feature, expanded SSRF/integration-delivery, and migration-0016 checks.
- Frontend: 18 tests passed; lint completed with zero errors and one unchanged hook-dependency warning; production build passed.
- Django system/model checks reported no issues and no pending model migration.
- Static scans found no browser Supabase database Realtime code, no raw Elasticsearch `query_string`, and no capture-stop body authorization ID.
- Tests used local SQLite, a disposable local PostgreSQL container, fake DNS/socket/TLS, local encrypted Storage, and synthetic in-memory PCAP/PCAPNG fixtures.
- No Supabase project/API/Storage/Auth/Realtime call, Railway/Vercel mutation, deployment, GitHub Actions run, branch push, or production egress occurred.

### Phase 5 deployment status

Do not push or merge this branch. Phase 6 MFA/frontend/accessibility work, Phase 7 JWT/headers/CI/scanning, protected-main workflow, Railway API/worker sizing and volume proof, Supabase hardening for 53 tables, migrations 0014–0016 rehearsal, and the separately budgeted data cutover remain mandatory gates.

## Phase 6 verification record

Phase 6 is repository-only and adds no schema object. Expected state remains 53 public tables and 16 forensics migrations.

| Finding/control | Status | Phase 6 control | Evidence |
|---|---|---|---|
| NTR-019 | Verified locally | Root application composition is small and direct Auth/console entries are lazy. | Vite manifest and bundle-budget gate |
| NTR-020 | Verified locally | Initial shell is 60.85 KiB gzip and Auth closure 186.63 KiB gzip; individual JS assets remain below 350 KiB gzip. | `npm run check:bundle` |
| NTR-025, Phase 6 scope | Verified locally | Auth/Admin frontend and backend routes use dedicated modules and shared security services. | Route inventory, module tests and complete regressions |
| NTR-028 | Verified locally | Server-side invitations, enumeration-resistant recovery, global sign-out, TOTP enrollment/challenge and AAL2 Admin workspace are implemented. | Provisioning tests, Auth unit tests and browser journeys |
| Phase 1–5 closure | Verified locally | Capability state remains authoritative; no synchronous processing or database Realtime frontend path returned. | Static scans and complete regression suites |

Complete evidence and remaining gates are recorded in `PHASE_6_VERIFICATION.md`. Do not push or merge: Phase 7 scanning currently includes unresolved production dependency advisories, and all hosted Auth/migration/platform gates remain outstanding.

## Phase 7 verification record

Phase 7 adds no schema object. Expected state remains 53 public tables and 16
forensics migrations.

| Finding/control | Status | Phase 7 control | Evidence |
|---|---|---|---|
| NTR-021 | Verified locally | Exact frontend origins replace wildcard CSP sources; API headers and CORS have explicit cross-origin contracts. | Header unit/browser tests and `frontend/vercel.json` policy test |
| NTR-023 | Verified locally | ES256 tokens are locally signature/claim verified through bounded cached JWKS; privileged mutations additionally validate the live remote session. | `test_jwt_verification.py`, Auth/admin regressions |
| NTR-026 | Verified locally | Canonical publishable/secret variable names are used and generic migration examples require operator-supplied references. | Environment/static checks and built-asset secret scan |
| NTR-025, Phase 7 scope | Open | Public entry facades are small, but `api/legacy_views.py` and `ConsoleApplication.tsx` still contain concentrated compatibility implementations. | Module-size inventory in `PHASE_7_VERIFICATION.md` |
| Supply-chain control | Verified locally | npm advisories are cleared; Python runtime graphs are hashed; runtime images are pinned, non-root, SBOM-capable, and scan-gated. | npm/pip audits, image runtime checks, Trivy/SBOM tooling |
| Delivery governance | Implemented locally; external activation pending | Deterministic workflows, CODEOWNERS, Dependabot, and no-bypass ruleset contract are committed. | Local workflow/governance validators |
| Phase 1–6 closure | Verified locally | Complete backend, PostgreSQL, frontend, bundle, browser and desktop/mobile accessibility gates remain green. | `PHASE_7_VERIFICATION.md` |

The branch remains unpushed. Repository-level NTR-021/NTR-023/NTR-026 controls
are complete, but NTR-025 prevents the controlled branch-push approval. Hosted
JWT activation, GitHub ruleset activation, SMTP/MFA drills, migrations,
platform sizing/volume proof, and data migration remain separate external
gates.
