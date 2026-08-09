# Netra cutover and rollback checklist

This checklist is documentation only. It does not authorize a deployment.

## Before cutover

- Protect `main` and obtain green CI, security, and container checks.
- Rehearse Django migrations `0014` through the then-current migration on a disposable PostgreSQL 17 copy.
- Confirm the current repository target is migration `0017_phase8_security_closure`, 53 application tables, and zero materialized views.
- Export an encrypted logical backup outside Git before any hosted schema change; Supabase Free automatic backups are not treated as a recoverable operator backup.
- Confirm one active organization Admin with AAL2 enrollment.
- Confirm the exact Auth Site URL plus `/auth/invite` and `/auth/recovery` redirects.
- Confirm custom SMTP delivery with a controlled non-Admin invitation and recovery drill.
- Confirm separate Railway API and worker services and the persistent `/app/storage` volume.
- Confirm target environment names without exposing values in logs or frontend builds.
- Record Supabase egress before the window; do not start legacy-object transfer before quota approval.
- Keep Realtime and recurring deep Storage checks disabled.
- Verify the target signing key is EC P-256/ES256, inspect the bounded public JWKS, and retain `NETRA_SUPABASE_JWT_MODE=remote` until that check is approved.
- Confirm the GitHub main ruleset matches `infra/github/main-ruleset.json` and every required policy-gate context has reported successfully.

## Cutover

- Freeze writes, uploads, workers, schedules and retention jobs.
- Apply reviewed migrations once and stop on the first error.
- Apply the append-only 53-table RLS/privilege hardening and Realtime-removal migrations only after confirming the historical 49-table migration is already recorded.
- Deploy API with workers stopped and confirm liveness/readiness.
- Deploy one worker and verify its pinned capability heartbeat.
- Run read-only authentication, database and case-boundary checks.
- Activate `asymmetric-jwks` only after ordinary-token, key-rotation, cached-outage, and privileged remote-validation smoke tests pass.
- Verify password login, Administrator TOTP challenge, invitation acceptance, recovery global sign-out, and rejection of an AAL1 Admin mutation.
- Run one tiny explicit Storage probe only when the migration runbook authorizes it.
- Reopen workers gradually, then reopen writes after every acceptance gate passes.

## Rollback before writes reopen

- Restore prior Railway/Vercel environment references and the last known-good build.
- Keep the target isolated for diagnosis.
- Resume source workers only after confirming the source remains frozen and consistent.

## Rollback after target writes reopen

- Start another write freeze.
- Inventory target-only rows and Storage objects.
- Obtain a new egress budget before reverse transfer.
- Reconcile forward writes; never perform a simple environment reversal that would discard evidence.

No source project, target project, Railway service, Vercel deployment, or GitHub setting is modified by this checklist.
