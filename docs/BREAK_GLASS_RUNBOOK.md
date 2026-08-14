# Administration break-glass runbook

Break-glass access is for a verified loss of normal administration only. It is
not a shortcut around AAL2, role ceilings, ownership transfer, or change review.

## Activation conditions

Use this procedure only when no active organization owner with a working AAL2
factor can restore access through the administration console. Open an incident
or approved change ticket first and record the incident commander, operator,
reason, target identity, intended role, and expiry/review time. Two people must
verify the target email through a channel independent of the affected account.

Do not place passwords, TOTP seeds, recovery codes, bearer tokens, database
URLs, or service keys in the ticket or terminal transcript.

## Procedure

1. Freeze unrelated administrative changes and record the current Git release,
   Railway deployment, organization owner, and active Admin profiles.
2. Confirm the target identity already exists in the configured Supabase Auth
   project. This command provisions Netra authorization; it does not create or
   verify an identity-provider account.
3. Open a one-off shell in the Railway API service for the active production
   deployment. Do not run the command in the worker or against a local database.
4. Run the narrow provisioning command, supplying the real approved ticket,
   operator identity, and reason:

   ```text
   python manage.py provision_netra_user person@example.org --role Viewer --organization netra --ticket NETRA-0000 --operator "First Last" --reason "Approved emergency restoration reason"
   ```

   Start with the lowest role that restores the recovery path. Granting Admin
   is a separate approval. Ownership transfer must use the console's protected
   ownership flow once an AAL2 Admin can sign in; do not silently equate an Admin
   role with organization ownership.
5. Require the restored user to sign in, enroll or recover a second factor, and
   prove an AAL2 administrative read before any destructive action.
6. Verify both audit records exist: AccessLog action
   `break_glass.profile_provisioned` and OperationalEvent type with the same
   value. Confirm the ticket, operator, target, and requested role without
   exporting personal or secret data.

## Closure

- Restore normal ownership through the AAL2-protected console if it changed.
- Remove temporary grants or accounts, revoke emergency sessions, and rotate any
  credential that may have been exposed during the incident.
- Verify the AccessLog append-only control and hash-chained AdminAuditLog, then
  attach sanitized timestamps and record identifiers to the incident.
- End the write freeze, record the closure approver, and complete a post-incident
  review. A failed audit write, uncertain target identity, or missing second
  approver leaves the incident open and access frozen.
