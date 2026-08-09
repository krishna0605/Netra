# Phase 7 local verification

Verification date: 9 August 2026 (Asia/Kolkata)

Phase 7 is repository-only. It adds no Django model, migration, Supabase SQL
migration, public table, materialized view, deployment, or cloud setting. The
expected application schema remains 53 public tables and 16 forensics
migrations.

## Outcome

The repository now contains the Phase 7 authentication, header, dependency,
container, CI, and GitHub-governance controls. NTR-021, NTR-023, and NTR-026
are verified at repository level. Hosted activation remains deliberately
deferred.

One structural acceptance gate remains open: the public backend/frontend entry
files are small composition facades, but their compatibility implementations
remain concentrated in `api/legacy_views.py` and `ConsoleApplication.tsx`.
Those files must be split into true feature-owned implementations before this
branch is approved for its first remote push. This record does not describe a
facade rename as completion of NTR-025.

## Implemented controls

### Authentication

- Ordinary Supabase access tokens can be verified locally with ES256 only.
- The verifier checks token length/shape, `alg`, `kid`, type, issuer, audience,
  role, subject UUID, AAL, issued time, expiry, and optional not-before time.
- JWKS retrieval uses an internally derived exact HTTPS origin, no redirects,
  no proxy inheritance, a three-second timeout, a 128 KiB response limit, and
  at most ten validated P-256 signing keys.
- The in-memory JWKS cache lasts 600 seconds, serializes refreshes, and
  negatively caches unknown key IDs for 30 seconds.
- Local organization, role, activation, and profile state are resolved on
  every request. JWT metadata never grants a Netra role.
- Privileged user, administrator, and integration-credential mutations require
  a second bounded remote validation of the same bearer session before any
  transaction starts.
- `remote` remains the safe default until Phase 8 activates the target ES256
  signing key and verifies the public JWKS.

### Browser and API policy

- The Vercel CSP allows only the exact current API and Supabase HTTPS origins.
- No wildcard Railway/Supabase source, WebSocket source, arbitrary HTTPS image
  source, inline script, or `unsafe-eval` remains.
- Frontend policy includes `no-referrer`, `nosniff`, frame denial, COOP,
  same-origin CORP, and a restricted Permissions Policy.
- API responses use a non-rendering CSP, frame denial, no-referrer,
  `nosniff`, restricted permissions, and cross-origin resource policy required
  for the separately hosted approved frontend.
- CORS remains exact-origin and bearer-token based.

### Reproducibility and supply chain

- Frontend audits report zero known vulnerabilities in both production and
  complete dependency graphs.
- React Router is 7.18.2, PostCSS is 8.5.26, and Nano ID is 3.3.18.
- API, worker, development, and sensor Python graphs have source manifests and
  fully pinned hash-locked outputs.
- Linux/Python 3.13 `pip-audit` reports no known vulnerability in the API,
  worker, or sensor lock.
- Runtime images install only reviewed binary wheels using
  `--require-hashes --only-binary=:all:` and do not upgrade pip in-image.
- API, worker, and frontend bases are digest-pinned and run as non-root users.
- Local CycloneDX SBOM generation and Trivy high/critical policy checks pass.
  Unfixed operating-system findings remain reportable; the policy does not
  conceal them with a blanket ignore.
- VEX is empty. Any future exception must have an owner, reachability analysis,
  remediation ticket, and expiry within 30 days.

### CI and repository governance

- Three pull-request workflows cover application quality, security analysis,
  and container/SBOM policy.
- Every third-party Action is pinned to a full commit SHA.
- Workflows use read-only defaults, explicit timeouts, cancellation, no
  deployment command, no production credential, and no `pull_request_target`.
- Stable policy-gate jobs are provided for protected-main status checks.
- CODEOWNERS, grouped Dependabot configuration, a no-bypass main ruleset, and
  a read-only ruleset verifier are committed.
- The ruleset is repository state only; it has not been applied to GitHub.

## Verification evidence

| Gate | Result |
|---|---|
| Complete backend in pinned worker image | 183 tests passed; four expected environment-specific skips |
| Django model/system checks | No pending migration; no system issue |
| Production-like Django deploy check | No issue with local synthetic production settings |
| Disposable PostgreSQL 17 suite | 25 selected concurrency, custody, Admin, and provisioning tests passed |
| Frontend unit suite | 27 tests passed |
| Frontend lint/build | Passed |
| Bundle budget | Shell 61.19 KiB gzip; Auth closure 187.48 KiB gzip; passed |
| Browser journeys | 38 desktop/mobile tests passed |
| Accessibility | 18 desktop/mobile accessibility journeys passed with no serious/critical axe result |
| npm audits | Zero vulnerabilities in production and complete graphs |
| Python audits | API, worker, and sensor: no known vulnerability |
| Workflow/governance/VEX/SQL validators | Passed without cloud linking |
| Container contracts | API UID 10001/no parsers; worker UID 10001/TShark 4.6.7/Zeek 8.2.1; frontend UID 101 |
| Cloud usage | No Supabase, Railway, Vercel, or GitHub API/deployment call |

The Windows host does not provide TShark on PATH, so the authoritative complete
backend run was executed inside the already built pinned worker image. The
PostgreSQL suite used only the disposable localhost container and removed it
afterward. The Python lock audit was run under Linux/Python 3.13 because the
locks intentionally target the production platform; a Windows audit attempts
to resolve the platform-only `tzdata` dependency and is not the release gate.

## Local Phase 7 commits

| Commit | Purpose |
|---|---|
| `3d556e8` | Close Phase 1–6 operational carryovers |
| `c0d0fdf` | Add backend API ownership facades and route inventory |
| `4972960` | Add console composition boundary |
| `2b618d7` | Add bounded cached ES256/JWKS verification |
| `bfc5b05` | Enforce exact-origin browser/API policy |
| `858c423` | Remediate and hash-lock dependencies |
| `b672028` | Pin, scan, and attest runtime images |
| `aca0fd7` | Add deterministic quality/security/container workflows |
| `5686ad2` | Codify ownership, updates, and protected-main contract |
| Phase 7 verification commit | Close mobile accessibility regressions and record the push gate |

## Remaining external and structural gates

- Split the concentrated backend/frontend compatibility implementations into
  their actual feature families and rerun route/module parity.
- Obtain owner approval before any branch push.
- Confirm Railway deploys production from `main` only and Vercel previews are
  isolated and receive no backend secrets.
- Push only `codex/netra-security-remediation`, run the new workflows, then
  apply and verify the committed main ruleset before opening a draft PR.
- Keep the draft PR unmerged through platform hardening, migrations 0014–0016,
  signing-key activation, SMTP/MFA drills, volume proof, and the capped data
  migration.

## Egress record and verdict

No production credentials were loaded. No target JWKS, Auth identity, database
row, Storage object, Realtime channel, Railway service, Vercel deployment, or
GitHub setting was read or changed. Supabase project egress attributable to
Phase 7 local implementation is zero bytes.

Because the compatibility implementations remain concentrated, the branch is
**not yet approved for its controlled remediation-branch push**. It remains
strictly ineligible for direct push or merge to `main`.
