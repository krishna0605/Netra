# Netra Phase 6 verification

Phase 6 is implemented and verified locally on `codex/netra-security-remediation`. It adds a route-oriented root shell, server-authorized invitation provisioning, password recovery, TOTP/AAL2 journeys, an organization-scoped Administrator workspace, accessibility contracts, and enforced frontend bundle budgets.

## Repository contract

| Contract | Phase 6 value |
|---|---:|
| Public application tables | 53 |
| Forensics migrations | 16 |
| New Phase 6 migrations | 0 |
| Materialized views | 0 |
| Phase 6 commits | 10 |
| Supabase project egress | 0 bytes |

## Local evidence

| Gate | Result |
|---|---|
| Complete Django suite | 174 tests passed; four reviewed environment-specific skips |
| Disposable PostgreSQL 17 suite | 42 tests passed, including concurrency, custody, feature, integration, schema, Admin and provisioning controls |
| Django model/system checks | No pending model migration; no system-check issue |
| Frontend unit tests | 24 tests passed |
| Browser journeys | 33 passed; five duplicate mobile axe scans skipped while mobile functional journeys remained green |
| Authoritative axe gate | Nine desktop public/authentication journeys passed with no serious or critical findings |
| Frontend lint | Passed with no warning |
| Bundle gate | Initial shell 60.85 KiB gzip; authentication closure 186.63 KiB gzip; all generated JS assets below 350 KiB gzip |
| Realtime/static checks | No application `.channel()`, `postgres_changes`, or WebSocket path; no token-shaped localStorage write |

Automated accessibility checks are evidence, not WCAG certification. Keyboard, skip-link, focus, reduced-motion, form-status, table and mobile functional behavior have local coverage; an assisted-technology and production-browser review remains part of preview acceptance.

## Findings

| Finding | Local status | Evidence |
|---|---|---|
| NTR-019 | Verified | Root `App.tsx` is composition-only; direct Auth and console entries are lazy. |
| NTR-020 | Verified | Manifest-based gzip budgets fail the build on regression. |
| NTR-025, Phase 6 scope | Verified | Authentication and Admin APIs/UI are dedicated modules and use shared security services. The large console feature module remains a maintainability follow-up; it is no longer the application root or Auth owner. |
| NTR-028 | Verified locally | Invitations never accept passwords; Admin sessions require verified TOTP/AAL2; factor recovery is operator-controlled and documented. |
| NTR-012/NTR-013/NTR-024 carryover | Verified | No database Realtime path, no frontend synchronous processing fallback, and Phase 5 capability state remains authoritative. |

## Known pre-push blockers

- `npm audit --omit=dev` currently reports four production dependency advisories: three high and one moderate, with zero critical. Phase 7 must review and upgrade the affected dependency graph, then rerun all browser and bundle gates.
- Phase 7 JWT/header hardening, CI, secret/dependency scanning and branch protection are not implemented.
- Custom SMTP, Auth redirect allowlists and a real Administrator TOTP/recovery drill are not configured.
- Migrations `0014`–`0016`, target RLS hardening, Railway worker sizing/volume proof and the data migration remain external gates.

No Supabase, Railway, Vercel or GitHub project was queried or mutated. Tests used local mocks, local files and a disposable localhost PostgreSQL container.
