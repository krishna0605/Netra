# Netra Admin Console

The administration surface for Netra — user provisioning, role and permission
assignment, credential recovery, and the record of what everyone did.

This is a **separate source workspace from `frontend/`** so its dependencies and
tests remain independently reviewable. Production builds both workspaces into
one Vercel project: the investigator console at `/` and administration at the
neutral `/workspace` path. The administration token is memory-only and is never
written to browser storage.

> **Status: production-wired Phase 5 implementation.** Authentication, the
> directory, administrative writes, audit verification, live sessions, roles,
> grants and ownership use `/api/admin/v1/*`. Browser tests stub that namespace
> deliberately; the combined Vercel artifact is validated against the same API
> and Supabase project used by the investigator console.

## Running it

```bash
cd admin && npm install && npm run dev
```

Then open <http://localhost:5180>.

`frontend/` uses 5173, so both consoles can run side by side during development.

| Script | Does |
|---|---|
| `npm run dev` | Dev server on port 5180 |
| `npm run build` | Typecheck then production build |
| `npm run preview` | Serve the production build |

## Isolation

Nothing here is shared with `frontend/` at build time:

- its own `package.json` and `node_modules`
- its own Vite, TypeScript and Tailwind configuration
- its own `public/` — brand assets and fonts are **copied**, not linked
- no imports that cross the folder boundary

The only thing the two consoles share is the design language, and that is
deliberate duplication rather than a dependency.

## Theme

Brand tokens are ported verbatim from `frontend/src/index.css`. Do not let them
drift — the two consoles are one product.

| Token | Value |
|---|---|
| `--color-charcoal-deep` | `#1d1d1d` |
| `--color-charcoal-panel` | `#242424` |
| `--color-cream-primary` | `#e9e0d1` |
| `--color-cream-bright` | `#f0e8da` |
| `--color-sand-muted` | `#ccbd9f` |
| `--color-signal` | `#fa6c34` |

Geist and IBM Plex Mono are self-hosted from `public/fonts/`, copied out of the
investigator console so both surfaces render identically offline.

Two things this console adds that the investigator console has no need for:

1. **A semantic state palette** — `state-ok`, `state-warn`, `state-crit`,
   `state-info`. Desaturated so they read as state and never compete with the
   accent. Nothing in the investigator console has to render "allowed vs denied".
2. **A permanent ADMIN marker** — the orange rule across the top of the viewport
   and the tag in the rail. Being a beat unsure which console you are typing into
   is a real failure mode when one of them can reset credentials.

## Screens

| Route | Purpose |
|---|---|
| `/` | Overview — is anything wrong right now |
| `/users` | User list, filterable by role, status and MFA gap |
| `/users/:id` | Identity, permissions, sessions, activity, danger zone |
| `/roles` | Permission matrix across every role |
| `/activity` | Unified activity explorer, denied-first |
| `/sessions` | Active sessions, revocable |
| `/organization` | Org settings, quotas, ownership transfer |
| `/capabilities` | Read-only render of the backend capability registry |
| `/audit` | Hash-chained record of administrator writes |

## Layout

```
src/
├── components/
│   ├── ui/primitives.tsx   Button, Badge, Panel, Table, inputs
│   ├── AppShell.tsx        Left rail, ADMIN marker, operator status
│   ├── common.tsx          PageHeader, StatTile, shared state badges
│   └── RecoveryDialog.tsx  The three credential recovery paths
├── data/
│   ├── types.ts            Mirrors the /api/admin/v1/* contract
│   └── mock.ts             Seed data tracking the real backend
├── lib/utils.ts            cn() and date formatting
└── pages/                  One file per route
```

## Wiring it to the backend

`src/data/types.ts` mirrors the API contract from §9 of the plan rather than
inventing shapes that happened to be convenient. When the backend namespace
lands, add a `src/data/client.ts` that fetches and returns those same types, and
swap the imports in `pages/`. No component should need to change.

Seed data deliberately tracks reality: the ten permission strings come from
`backend/common/audit.py`, and the capability flags reproduce what
`capability_registry()` actually reports today — including `user_invitations`
and `password_recovery` sitting disabled behind an approved SMTP domain.
