/**
 * These shapes mirror the `/api/admin/v1/*` contract described in §9 of the
 * implementation plan. Nothing here talks to a server yet — the backend
 * namespace is phase 1 work. Keeping the types honest now means the swap from
 * mock to fetch is confined to `client.ts`.
 */

export type PermissionKey =
  | "view"
  | "review"
  | "upload"
  | "confirm"
  | "report"
  | "export"
  | "compliance"
  | "integrations"
  | "operations"
  | "manage_users";

export type RiskLevel = "standard" | "elevated" | "high";

export type Permission = {
  key: PermissionKey;
  label: string;
  description: string;
  category: "Evidence" | "Analysis" | "Reporting" | "Administration";
  risk: RiskLevel;
};

export type RoleSlug =
  | "admin"
  | "investigator"
  | "analyst"
  | "viewer"
  | "lan_operator"
  | (string & {});

export type Role = {
  slug: RoleSlug;
  name: string;
  description: string;
  isSystem: boolean;
  permissions: PermissionKey[];
  memberCount: number;
};

export type UserStatus = "active" | "invited" | "locked_out" | "deactivated";
export type MfaState = "verified" | "unenrolled" | "factor_lost";

export type PermissionSource = "role" | "granted" | "revoked";

export type EffectivePermission = {
  key: PermissionKey;
  source: PermissionSource;
  expiresAt: string | null;
  reason: string;
  grantedBy: string;
};

export type CaseMembership = {
  caseId: string;
  caseTitle: string;
  role: string;
  addedAt: string;
};

export type AdminUser = {
  id: number;
  email: string;
  name: string;
  roleSlug: RoleSlug;
  isOwner: boolean;
  status: UserStatus;
  mfa: MfaState;
  department: string;
  supabaseId: string;
  joinedAt: string;
  lastSignInAt: string | null;
  lastActivityAt: string | null;
  invitationState: "accepted" | "pending" | "expiring" | "none";
  deniedLast24h: number;
  permissions: EffectivePermission[];
  caseMemberships: CaseMembership[];
};

export type ActivitySource =
  | "AccessLog"
  | "AdminAudit"
  | "Custody"
  | "OperationalEvent"
  | "CaseHistory";

export type ActivityResult = "allowed" | "denied" | "recorded";

export type ActivityEvent = {
  id: string;
  at: string;
  actor: string;
  actorEmail: string;
  role: string;
  action: string;
  target: string;
  result: ActivityResult;
  source: ActivitySource;
  chainIndex: number | null;
};

export type SessionRow = {
  id: string;
  userId: number;
  userName: string;
  userEmail: string;
  origin: string;
  aal: "aal1" | "aal2";
  startedAt: string;
  lastSeenAt: string;
  ipHint: string;
};

export type CapabilityState = "available" | "disabled" | "not_implemented" | "degraded";

export type CapabilityFlag = {
  key: string;
  state: CapabilityState;
  reason: string;
  requiresAal2: boolean;
  durableConsumer: string | null;
};

export type AuditEvent = {
  id: string;
  chainIndex: number;
  at: string;
  actor: string;
  action: string;
  targetType: string;
  targetId: string;
  reason: string;
  before: string;
  after: string;
  previousHash: string;
  eventHash: string;
};

export type OrganizationSettings = {
  id: string;
  name: string;
  slug: string;
  ownerUserId: number;
  maxQueuedAnalyses: number;
  accessLogRetentionDays: number;
  mfaPolicy: "admin_required" | "optional";
  createdAt: string;
};

export type OverviewSummary = {
  activeUsers: number;
  newUsersThisWeek: number;
  deniedLast24h: number;
  deniedTopActor: string;
  mfaEnrolled: number;
  mfaTotal: number;
  pendingInvites: number;
  invitesExpiringToday: number;
  temporaryGrants: number;
  staleAccounts: number;
};
