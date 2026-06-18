# Netra Security Hardening Notes

This document covers the production safety steps for Netra Supabase mode.

## Supabase Key Rotation

Rotate the Supabase service-role key before any shared demo or deployment if it was ever pasted into chat, logs, screenshots, commits, or another untrusted place.

1. Open the Supabase Dashboard.
2. Go to Project Settings -> API.
3. Rotate or regenerate the service-role/secret key.
4. Update only the backend environment file:

```powershell
.env.supabase.local
```

5. Restart Netra:

```powershell
npm run netra:start:supabase
```

6. Validate:

```powershell
npm run netra:validate:security
```

Never put the service-role key in frontend files, Vite variables, screenshots, reports, or committed documentation. The frontend must use only the Supabase publishable/anon key.

## Role Model

Supabase Auth is the identity provider. Netra stores server-side application roles in `forensics_userprofile`.

Supported roles:

| Role | Purpose |
|---|---|
| Admin | Manage users, integrations, evidence actions, exports, and reports. |
| Investigator | Upload evidence, confirm findings, generate reports, and export evidence. |
| Analyst | Upload evidence and review suspicious activity without final legal export authority. |
| Viewer | Read-only access to permitted investigation data. |

The first authenticated Supabase user becomes a Netra Admin only when no Admin profile exists. After that, Admin users should assign roles through Netra's user management API or an operator-controlled database update.

## Enforcement Rules

Backend permission checks are mandatory for protected actions. Hiding buttons in the UI is not sufficient.

Protected actions include:

- PCAP upload
- replay and live capture start
- report generation and download
- evidence export and download
- evidence download
- alert confirmation/dismissal
- integration configuration and delivery
- user/role management
- custody/compliance actions

Denied actions must return `403` for authenticated users and create an `AccessLog` row with `result = denied`.

## Supabase RLS Readiness

Netra currently uses the Django backend as the trusted data boundary and the Supabase service role only on the server.

Before public or broad shared deployment:

1. Enable RLS only with explicit policies.
2. Do not rely on user-editable `user_metadata` for authorization.
3. Keep privileged functions out of exposed schemas.
4. Limit Realtime publication to low-volume operational tables.
5. Keep Storage buckets private.
6. Re-run Supabase advisors and Netra validation after policy changes.

## Validation

Run:

```powershell
npm run build
npm run netra:validate:security
npm run netra:validate:supabase
```

The security validator checks:

- Supabase Auth is active.
- Development role headers are disabled.
- Service-role credentials are backend-only.
- Admin can manage roles.
- Viewer cannot upload or generate reports.
- Denied actions are audit logged.
- Investigator can upload, report, and export.
- Technical Status reports RBAC safely without leaking secrets.
