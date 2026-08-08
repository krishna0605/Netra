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
