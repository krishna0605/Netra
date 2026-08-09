# Netra MFA and account recovery runbook

This runbook defines the reviewed recovery boundary. It does not authorize a hosted Auth change by itself.

## Hackathon release policy

Netra has no owned, verified SMTP domain for this release. `NETRA_PASSWORD_RECOVERY_ENABLED=0` and `NETRA_AUTH_INVITATIONS_ENABLED=0` are mandatory. The frontend obtains this state from `/api/capabilities`, hides email controls, and renders an accessible unavailable notice on direct routes. Resend and Supabase custom SMTP remain unconfigured. Existing-user password login and TOTP are unaffected.

No temporary password, public default sender, or alternate recovery bypass is permitted.

## Future normal recovery after approved SMTP activation

1. The user requests password recovery from `/auth/forgot-password`.
2. The browser sends the request directly to Supabase Auth using the publishable key and the exact `/auth/recovery` redirect.
3. Netra shows the same response whether or not the address exists.
4. A valid recovery session may set a password that satisfies the local 12–128 character policy.
5. Netra performs global sign-out, clears local session consumers, and requires a fresh password and MFA sign-in.

Password recovery never creates a profile, changes an organization, changes a role, activates a user, or bypasses AAL2.

## Lost Administrator authenticator

Supabase TOTP does not provide recovery codes. Netra must not imply that recovery codes exist.

1. Open an approved incident/ticket and record the operator, reason, affected organization, and Administrator identity.
2. Confirm the operator is authorized through an independent channel.
3. Use authorized Supabase administration to remove only the lost factor. Never request or record the former TOTP secret.
4. Record the recovery action through the audited Netra operator process.
5. Globally sign out the affected user.
6. Require password sign-in and immediate fresh TOTP enrollment.
7. Verify the new factor produces an AAL2 session and `/api/auth/me` reports `privilegedAdminReady=true`.
8. Review the organization audit trail and close the ticket.

If the Administrator identity itself cannot be recovered, use the existing ticketed break-glass transfer command. The command must leave exactly one active organization Administrator and write both audit records.

## Future email-activation prerequisites

- Exact Site URL and invitation/recovery redirect allowlist.
- Production custom SMTP and sender identity.
- One enrolled current Administrator factor.
- One non-Administrator invitation test identity.
- Backend invitation capability enabled only after the above checks.

Never place the service-role key, factor secret, invitation link, recovery token, password, access token, or refresh token in logs, screenshots, tickets, Vercel variables, or this repository.
