# Netra Phase 1 security remediation runbook

## Scope

This runbook verifies critical containment without touching production or Supabase. Run it from the `codex/netra-security-remediation` branch. Keep the confidential audit PDF untracked.

```mermaid
flowchart LR
    REQUEST["Authenticated request"] --> SCOPE["Workspace + job resolver"]
    SCOPE -->|"case/job mismatch"| HIDDEN["404 non-disclosing error"]
    SCOPE -->|"not complete"| NOTREADY["409 analysis_not_ready"]
    SCOPE -->|"authorized"| RESOURCE["Job-local resource lookup"]
    RESOURCE --> READ["Scoped read"]
    RESOURCE --> LOCK["Transactional exact-ID mutation"]
    INPUT["Case ID / artifact request"] --> VALIDATE["Central identifier + safe path validation"]
    VALIDATE --> ENCRYPT["Contained temporary write, encrypt, delete plaintext"]
    REPORT["Structured legal/custody context"] --> ESCAPE["Autoescaped template + CSP"]
```

## Verification procedure

Set the local packet-analysis prerequisites in PowerShell:

```powershell
$env:Path = 'C:\Program Files\Wireshark;' + $env:Path
$env:PYTHONPATH = 'C:\Users\ADMIN\Desktop\hackthon\ml-services\anomaly-engine'
```

Run focused security tests from `backend`:

```powershell
python manage.py test apps.forensics.tests.test_analysis_case_boundaries apps.forensics.tests.test_artifact_security apps.forensics.tests.test_access_control
```

Run the complete backend and model checks:

```powershell
python manage.py test apps.forensics.tests
python manage.py makemigrations --check --dry-run
```

Run frontend checks from `frontend`:

```powershell
npm test -- --run
npm run lint
npm run build
```

Run repository/static checks from the repository root:

```powershell
rg -n --pcre2 "(?<!empty)_analysis\(\)|analysis_for_case\(\)|latest_job_for_case\(\)" backend
git diff --check
git status --short
git log --oneline --decorate -6
```

The static search should return no results. Repository status should show only the intentionally untracked confidential audit PDF after the final commit.

## Failure handling

- Do not commit a failing state.
- A cross-case response other than the expected 404 is a no-go.
- Any failed mutation side effect is a no-go.
- Any plaintext artifact left behind or file outside the temporary Storage root is a no-go.
- Any executable report markup is a no-go.
- If model changes are detected, stop; Phase 1 authorizes no migration.
- If a cloud credential, URL, or object operation appears in logs, stop and investigate; Phase 1 is local-only.

Rollback uses ordinary `git revert` in reverse commit order. Do not use destructive reset commands and do not alter the baseline commit.

## Phase 2 local verification

Phase 2 adds one Django migration and changes the expected application schema to 51 public tables and 14 forensics migrations. Do not run this migration against Supabase during local remediation.

```mermaid
flowchart LR
    TOKEN["Verified token + AAL"] --> ACTOR["Provisioned organization Actor"]
    ACTOR --> TENANT["Organization-scoped authorization"]
    TENANT --> LIMIT["Atomic request buckets"]
    TENANT --> QUEUE["Locked organization queue quota"]
    TENANT --> AUDIT["Tenant-safe logs and events"]
    ACTOR --> ADMIN["AAL2 sole-admin transfer"]
```

Run from `backend` with no cloud database URL loaded:

```powershell
$env:NETRA_TEST_SQLITE = '1'
$env:Path = 'C:\Program Files\Wireshark;' + $env:Path
$env:PYTHONPATH = 'C:\Users\ADMIN\Desktop\hackthon\ml-services\anomaly-engine'
python manage.py test apps.forensics.tests
python manage.py makemigrations --check --dry-run
python manage.py check
```

Run focused Phase 2 suites:

```powershell
python manage.py test apps.forensics.tests.test_tenancy_migration apps.forensics.tests.test_organization_boundaries apps.forensics.tests.test_rate_limits apps.forensics.tests.test_admin_invariants apps.forensics.tests.test_access_control
```

The backend-only environment names are:

```text
NETRA_RATE_LIMITS_ENABLED
NETRA_RATE_LIMIT_READ_PER_MINUTE
NETRA_RATE_LIMIT_MUTATION_PER_MINUTE
NETRA_RATE_LIMIT_UPLOAD_USER_PER_HOUR
NETRA_RATE_LIMIT_UPLOAD_ORG_PER_HOUR
NETRA_RATE_LIMIT_REPORT_USER_PER_HOUR
NETRA_RATE_LIMIT_EXPORT_USER_PER_HOUR
NETRA_RATE_LIMIT_WEBHOOK_TEST_ADMIN_PER_HOUR
```

These variables belong on Railway only. They must not use `VITE_`, must not be added to Vercel, and must not contain credentials. Queue capacity is database configuration on `Organization.max_queued_analyses`, not an environment variable.

Before a future push, run the rate/queue concurrency suite against an approved disposable PostgreSQL 17 database. Do not use either Supabase project for that rehearsal. A missing local PostgreSQL credential is a no-go for the push gate, not authorization to consume free-plan cloud egress.

Phase 2 rollback remains commit-by-commit locally. Migration reversal is for a disposable rehearsal database only; it is not the production rollback strategy after new tenant-owned writes exist.

## Phase 3 local verification

Phase 3 changes artifact cryptography, custody serialization, encrypted Storage caching, and public documentation without changing models or applying cloud migrations.

```mermaid
flowchart LR
    SOURCE["Authorized plaintext"] --> V2["Chunked v2.1 encryption"]
    V2 --> OBJECTS["Immutable encrypted generation"]
    OBJECTS --> CACHE["Verified bounded cache"]
    CACHE --> READER["Authorized parser/download"]
    V2 --> POINTER["Transactional database pointer"]
    POINTER --> CUSTODY["Case-locked custody append"]
    CUSTODY --> ANCHOR["Signed external anchor"]
```

Run focused tests from `backend` with no cloud credentials loaded:

```powershell
$env:NETRA_TEST_SQLITE = '1'
$env:PYTHONPATH = 'C:\Users\ADMIN\Desktop\hackthon\ml-services\anomaly-engine'
python manage.py test apps.forensics.tests.test_crypto_v2 apps.forensics.tests.test_crypto_migration apps.forensics.tests.test_custody_concurrency apps.forensics.tests.test_storage_provider apps.forensics.tests.test_artifact_security
```

The custody concurrency module skips its fifty-writer test on SQLite. Run that test against an approved disposable PostgreSQL 17 database before any push; do not use a Supabase free-plan project as the rehearsal database.

On this Windows workstation, the canonical complete Django runner currently stalls before assertions while importing the pre-existing monolithic analysis/Scapy URL stack. Do not reinterpret that as a passing full suite. The focused Phase 3 suite can run against a disposable database through Django's migration executor, but completing the canonical full run remains a no-push gate and a Phase 4 isolation concern.

Safe operational commands:

```powershell
python manage.py migrate_evidence_crypto --plan --state C:\approved-encrypted-workspace\crypto-state.json
python manage.py maintain_storage_cache --startup
python manage.py maintain_storage_cache --status --json
python manage.py maintain_storage_cache --prune
python manage.py export_custody_anchors --case-id CASE_REFERENCE --output-directory C:\approved-anchor-output
python manage.py verify_custody_anchor C:\approved-anchor-output\ANCHOR_FILE.json
```

Do not run `migrate_evidence_crypto --execute` or `export_custody_anchors --upload` during local remediation. The first requires the separately approved quota-reset window; the second mutates private Storage.

Backend-only configuration names:

```text
NETRA_EVIDENCE_KEY
NETRA_EVIDENCE_KEY_ID
NETRA_EVIDENCE_PREVIOUS_KEYS
NETRA_EVIDENCE_WRITE_FORMAT
NETRA_EVIDENCE_ENCRYPTION_CHUNK_BYTES
NETRA_CUSTODY_ANCHORS_ENABLED
NETRA_CUSTODY_SIGNING_PRIVATE_KEY
NETRA_CUSTODY_SIGNING_KEY_ID
NETRA_STORAGE_CACHE_ENABLED
NETRA_STORAGE_CACHE_MAX_BYTES
NETRA_STORAGE_CACHE_MIN_FREE_BYTES
NETRA_STORAGE_CACHE_STALE_TEMP_SECONDS
NETRA_STORAGE_CACHE_TOUCH_INTERVAL_SECONDS
NETRA_STORAGE_CACHE_LOCK_TIMEOUT_SECONDS
```

These variables belong on Railway/backend services only. None may use a `VITE_` prefix. Startup performs bounded stale-partial cleanup and never downloads an object. Routine health checks remain metadata-only.

See `KEY_ROTATION_AND_RECOVERY.md` for the future key rollout, retention, restore drill, and explicit retirement approval process.
