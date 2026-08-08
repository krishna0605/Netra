# Phase 2 tenancy and administrator API contract

## Additive identity fields

`GET /api/auth/me` adds `organization`, `aal`, and `privilegedAdminReady`. Organization comes from the locally provisioned `UserProfile`; client metadata never selects it.

## Administrator transfer

```text
POST /api/admin/organizations/{organizationId}/admin-transfer
```

The caller must be the active organization Admin and present a verified `aal2` token. The target must be a different active user in the same organization. The transaction demotes the previous Admin, promotes the target, and writes both `AccessLog` and `OperationalEvent`; any failure rolls back all four writes.

```json
{
  "targetUserId": 123,
  "reason": "Approved administrator rotation under ticket NETRA-1234."
}
```

Generic user creation/update cannot assign, demote, deactivate, or replace an Admin.

## Rate-limit contract

Rate rejections use HTTP 429 and include `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `X-RateLimit-Scope`. A rate-limit database failure fails closed with HTTP 503 and `rate_limit_unavailable`.

The server generates stable route categories; raw URLs, resource IDs, email addresses, tokens, and IP values are not bucket keys.

## Tenant disclosure contract

Cross-organization case, user, membership, log, event, and audit resources return the same 404 as a nonexistent resource. Department remains descriptive metadata and grants no access.
