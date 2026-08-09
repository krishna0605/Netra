# Phase 8A local verification

Verification date: 9 August 2026 (Asia/Kolkata)

## Verdict

Phase 8A is locally verified. It closes the repository structural gaps carried from Phases 1–7. No Supabase project, Storage object, Auth identity, Railway service, Vercel deployment, GitHub setting, or remote branch was queried or changed.

Phase 8 as a whole is **not complete**. Phase 8B hosted activation is owner-executed and remains blocked on explicit push/platform approval and real sanitized evidence.

## Repository state

```text
Public application tables: 53
Forensics migrations: 17
Latest migration: 0017_phase8_security_closure
Materialized views: 0
Supabase project egress: 0 bytes
Branch push: not performed
```

Corrective commits discovered by full-suite verification were added rather than amending history. Consequently, local commit totals are higher than the original Phase 8 forecast; the real platform-evidence commit must be a later new commit and must never be fabricated from local results.

## Closed carryovers

- API/worker import and image isolation.
- Streaming, bounded legacy artifact reads and cleanup-aware report/export downloads.
- Feature-owned frontend console and backend endpoint modules.
- Complete 183-route security-policy inventory and drift check.
- Authenticated MFA, AAL2 Admin, case, and analysis browser/accessibility journeys.
- Truthful deterministic detector provenance through migration `0017`.
- Encrypted-only application credential writes, plan-only migration inventory, and delivery blocking while legacy plaintext remains.

## Verification evidence

| Gate | Result |
|---|---|
| Complete backend | 216 passed; four expected environment-specific skips |
| PostgreSQL 17 security subset | 27 passed |
| Django migration drift | No changes detected |
| Django checks | No issues |
| Route-policy inventory | 183 policies verified |
| Frontend unit tests | 28 passed |
| Frontend lint/build | Passed |
| Bundle budget | Application shell 61.27 KiB gzip; Auth closure 187.71 KiB gzip |
| Browser matrix | 60 desktop/mobile tests passed |
| Authenticated accessibility | MFA enrollment/challenge, case list, analysis, and Admin users: no serious/critical axe findings at desktop or Pixel 7 sizes |

The local worker-path tests used the installed workstation TShark 4.6.6. This validates the synthetic parsing path but is not evidence of the exact production tool version. The worker image and readiness contract remain pinned to TShark 4.6.7 and Zeek 8.2.1; their image verification remains part of the repository/container and later Railway gates.

## Remaining owner-executed Phase 8B gates

1. Rehearse append-only 53-table hardening SQL locally, then inspect hosted migration history before any dry run/push.
2. Confirm Railway and Vercel branch isolation before pushing only the remediation branch.
3. Run remote quality/security/container workflows and activate the audited `main` ruleset.
4. Back up and harden an empty target, apply migrations `0014`–`0017`, and verify RLS/grants/Realtime membership.
5. Supervise one-time bootstrap; validate API/worker separation, persistent volume, cache, exact parsers, and resource limits.
6. Provision evidence/custody keys and perform synthetic crypto/custody drills.
7. Rotate Auth signing keys with the documented grace period; configure SMTP/redirects and perform real TOTP/recovery drills.
8. Validate the Vercel preview CSP and built-asset secret boundary.
9. Keep measured Supabase egress below the 60 MB Phase 8 ceiling.

Do not push `main`, merge the draft PR, migrate legacy data, reopen writes, or claim Phase 8 completion until those gates have real sanitized evidence.
