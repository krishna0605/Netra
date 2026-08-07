# Netra Supabase migration runbook

This runbook migrates durable Netra data from `kirctxhxcmnncpuxjknw` to
`frjzewpyjgirorbguegm` while keeping metered transfer below the free-plan
budget. It intentionally excludes Supabase sessions, refresh tokens, Django
sessions, PGMQ messages, PGMQ archives, and Realtime publications.

## Hard stop conditions

Do not start any source export or Storage transfer until all of these are true:

- The old project's egress quota has reset.
- The Supabase Usage page shows at least 768 MiB available.
- The frontend is in maintenance mode and all producers/workers are stopped.
- PostgreSQL 17 client tools are installed.
- The working directory is encrypted, outside Git, and has at least 1 GiB free.
- Source and target URLs are visibly different before secrets are loaded.

Never put database URLs or service-role keys on a command line, in Git, or in
the migration manifest. Load them into the current shell from an approved
secret manager using these names:

```text
NETRA_MIGRATION_SOURCE_DATABASE_URL
NETRA_MIGRATION_TARGET_DATABASE_URL
NETRA_MIGRATION_SOURCE_URL
NETRA_MIGRATION_SOURCE_SERVICE_ROLE_KEY
NETRA_MIGRATION_TARGET_URL
NETRA_MIGRATION_TARGET_SERVICE_ROLE_KEY
```

## 1. Prepare and test the repository

From the repository root:

```powershell
$env:PYTHONPATH = (Resolve-Path '.\ml-services\anomaly-engine').Path
Push-Location backend
python manage.py test
python manage.py makemigrations --check --dry-run
Pop-Location

Push-Location frontend
npm ci
npm test -- --run
npm run build
Pop-Location
```

The production configuration must retain:

```text
NETRA_REALTIME_PROVIDER=sse
NETRA_STORAGE_DEEP_HEALTHCHECK=0
NETRA_FREE_PLAN_GUARD=1
VITE_SUPABASE_REALTIME_ENABLED=0
VITE_NETRA_FREE_PLAN_GUARD=1
```

Railway's ordinary pre-deploy hook runs Django migrations only. Run
`bootstrap_supabase` as the explicit, supervised target-provisioning step below;
do not add it to every production deployment because it changes buckets, queues,
and Realtime publication membership.

## 2. Provision the empty target

Set only the target `DATABASE_URL`, then create the repository-backed schema:

```powershell
$env:DATABASE_URL = $env:NETRA_MIGRATION_TARGET_DATABASE_URL
$env:NETRA_DATABASE_PROVIDER = 'supabase'
Push-Location backend
python manage.py migrate --noinput
python manage.py export_supabase_schema_manifest --output '<encrypted-work-dir>\target-schema.json'
Pop-Location
```

Apply the Supabase infrastructure migrations only after all 49 public tables
exist. Inspect the current CLI flags before use:

```powershell
npx --yes supabase@latest db push --help
npx --yes supabase@latest login
npx --yes supabase@latest link --workdir infra --project-ref frjzewpyjgirorbguegm
npx --yes supabase@latest db push --workdir infra --linked --dry-run
npx --yes supabase@latest db push --workdir infra --linked
```

Load the target Supabase URL and service-role key into the backend environment,
then perform shallow bootstrap only:

```powershell
Push-Location backend
python manage.py bootstrap_supabase
Pop-Location
```

Do not pass `--deep-storage-check` during normal provisioning or startup.

## 3. Capture the frozen source and migrate database/Auth data

Enable maintenance mode, stop all workers and producers, and record the freeze
timestamp. Then create source manifests before export:

```powershell
$env:DATABASE_URL = $env:NETRA_MIGRATION_SOURCE_DATABASE_URL
Push-Location backend
python manage.py export_supabase_schema_manifest --output '<encrypted-work-dir>\source-schema.json'
python manage.py export_supabase_data_manifest --output '<encrypted-work-dir>\source-data.json'
Pop-Location
```

Export only public durable data and separate `auth.users`/`auth.identities`
archives so users are restored before identities:

```powershell
.\infra\scripts\migrate-netra-database.ps1 `
  -Action Export `
  -WorkDirectory '<encrypted-work-dir>' `
  -ConfirmSourceEgressReset `
  -AvailableEgressBytes 805306368
```

Import into the empty target:

```powershell
.\infra\scripts\migrate-netra-database.ps1 `
  -Action Import `
  -WorkDirectory '<encrypted-work-dir>'
```

Reapply migrations and generate the target manifest:

```powershell
$env:DATABASE_URL = $env:NETRA_MIGRATION_TARGET_DATABASE_URL
Push-Location backend
python manage.py migrate --noinput
python manage.py export_supabase_data_manifest --output '<encrypted-work-dir>\target-data.json'
Pop-Location

.\infra\scripts\migrate-netra-database.ps1 `
  -Action Validate `
  -WorkDirectory '<encrypted-work-dir>' `
  -ConfirmSourceEgressReset `
  -AvailableEgressBytes 805306368
```

Compare `source-data.json` and `target-data.json`. Every public table row count
and primary-key digest must match. Target Auth sessions, refresh tokens, and
`django_session` must remain empty.

## 4. Migrate Storage with a resumable hard budget

The transfer tool downloads every source object once and every target object
once for SHA-256 verification. It stores progress after each object and refuses
to exceed 600 MiB of metered downloads.

```powershell
python .\infra\scripts\migrate_supabase_storage.py `
  --confirm-source-egress-reset `
  --available-egress-bytes 805306368 `
  --budget-bytes 629145600 `
  --expected-source-objects 608 `
  --manifest '<encrypted-work-dir>\storage-manifest.json' `
  --work-dir '<encrypted-work-dir>\storage-temp'
```

If interrupted, run the same command with the same manifest. Verified objects
are skipped. Check the Supabase Usage page after every bucket; stop manually if
the dashboard delta reaches 0.75 GiB even if the local meter is lower.

## 5. Acceptance and cutover

Before reopening writes, verify:

- 49 public tables and 13 Netra Django migrations.
- Source and target data manifests match.
- One Auth user and one identity exist; sessions and refresh tokens are empty.
- Seven private buckets and 608 hash-verified objects exist.
- Fourteen canonical PGMQ queues exist and are empty.
- No Netra table is in `supabase_realtime`.
- RLS is enabled on every Netra/Django table, including
  `forensics_evidenceuploadsession`.
- `anon` and `authenticated` cannot resolve or query Netra public tables.
- Security/performance advisor results have been reviewed.
- The frontend bundle contains no service-role/secret key and opens no Realtime
  WebSocket.
- Routine health checks perform no Storage object GET.

Switch Railway and Vercel to the values in
`.env.supabase.production.example`, deploy the backend with workers stopped,
perform read-only smoke tests, and then start workers one group at a time.
Do not update either platform's project variables until the target schema,
infrastructure migrations, shallow bootstrap, and acceptance checks are complete.

## 6. Rollback window

Keep the source frozen and read-only for seven days. Before target writes are
reopened, rollback is an environment-variable reversal. After target writes are
reopened, do not point back to the source without a new write freeze and an
explicit reverse-delta migration. Do not pause or delete the source without
separate approval after the seven-day window.
