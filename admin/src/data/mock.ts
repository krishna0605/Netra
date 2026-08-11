import type {
  ActivityEvent,
  AdminUser,
  AuditEvent,
  CapabilityFlag,
  OrganizationSettings,
  OverviewSummary,
  Permission,
  PermissionKey,
  Role,
  SessionRow,
} from "./types";

/** Minutes/hours/days before "now", so the console always looks live. */
const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
const daysAgo = (days: number) => ago(days * 24 * 60);
const ahead = (days: number) => new Date(Date.now() + days * 24 * 60 * 60_000).toISOString();

/* ---------------------------------------------------------------------------
   Permissions — the ten strings currently hardcoded in
   backend/common/audit.py:16, promoted to rows as described in plan §5.
   --------------------------------------------------------------------------- */
export const PERMISSIONS: Permission[] = [
  { key: "view", label: "View", description: "Read cases, evidence and analysis output.", category: "Analysis", risk: "standard" },
  { key: "review", label: "Review", description: "Triage detections and annotate findings.", category: "Analysis", risk: "standard" },
  { key: "upload", label: "Upload", description: "Admit new captures against a case.", category: "Evidence", risk: "standard" },
  { key: "confirm", label: "Confirm", description: "Sign off a finding as investigator-reviewed.", category: "Analysis", risk: "elevated" },
  { key: "report", label: "Report", description: "Generate investigator-facing reports.", category: "Reporting", risk: "elevated" },
  { key: "export", label: "Export", description: "Take evidence and reports out of the platform.", category: "Reporting", risk: "high" },
  { key: "compliance", label: "Compliance", description: "Read custody ledgers and access logs.", category: "Reporting", risk: "elevated" },
  { key: "integrations", label: "Integrations", description: "Configure outbound webhooks and case links.", category: "Administration", risk: "high" },
  { key: "operations", label: "Operations", description: "Control workers, queues and sensor capture.", category: "Administration", risk: "high" },
  { key: "manage_users", label: "Manage users", description: "Provision accounts, assign roles, recover credentials.", category: "Administration", risk: "high" },
];

/* ---------------------------------------------------------------------------
   Roles — five system roles seeded from ROLE_PERMISSIONS, plus one custom role
   to show what cloning produces.
   --------------------------------------------------------------------------- */
export const ROLES: Role[] = [
  {
    slug: "admin",
    name: "Admin",
    description: "Full administrative authority within the organization.",
    isSystem: true,
    memberCount: 2,
    permissions: ["view", "review", "upload", "confirm", "report", "export", "compliance", "integrations", "operations", "manage_users"],
  },
  {
    slug: "investigator",
    name: "Investigator",
    description: "Owns cases end to end, including sign-off and export.",
    isSystem: true,
    memberCount: 7,
    permissions: ["view", "review", "upload", "confirm", "report", "export", "compliance"],
  },
  {
    slug: "analyst",
    name: "Analyst",
    description: "Works the evidence but cannot confirm findings or export.",
    isSystem: true,
    memberCount: 9,
    permissions: ["view", "review", "upload"],
  },
  {
    slug: "viewer",
    name: "Viewer",
    description: "Read-only access to cases they are a member of.",
    isSystem: true,
    memberCount: 5,
    permissions: ["view"],
  },
  {
    slug: "lan_operator",
    name: "LAN Operator",
    description: "Trusted-LAN operator profile for on-premises deployments.",
    isSystem: true,
    memberCount: 0,
    permissions: ["view", "review", "upload", "confirm", "report", "export", "compliance", "integrations", "operations"],
  },
  {
    slug: "evidence_clerk",
    name: "Evidence Clerk",
    description: "Cloned from Analyst. Adds export for the records desk.",
    isSystem: false,
    memberCount: 1,
    permissions: ["view", "review", "upload", "export"],
  },
];

/* ---------------------------------------------------------------------------
   Users
   --------------------------------------------------------------------------- */
export const USERS: AdminUser[] = [
  {
    id: 1,
    email: "a.patel@gcc.gov.in",
    name: "Inspector A. Patel",
    roleSlug: "admin",
    isOwner: true,
    status: "active",
    mfa: "verified",
    department: "Gujarat Cyber Crime Cell",
    supabaseId: "8f2c41d0-11ab-4e6f-9d3a-0c7b5e2fa91c",
    joinedAt: daysAgo(410),
    lastSignInAt: ago(6),
    lastActivityAt: ago(2),
    invitationState: "accepted",
    deniedLast24h: 0,
    permissions: ROLES[0].permissions.map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" })),
    caseMemberships: [
      { caseId: "CASE-2026-0142", caseTitle: "Exfiltration — Sector 7 relay", role: "Admin", addedAt: daysAgo(9) },
      { caseId: "CASE-2026-0139", caseTitle: "Credential stuffing — payroll portal", role: "Admin", addedAt: daysAgo(14) },
    ],
  },
  {
    id: 12,
    email: "k.desai@gcc.gov.in",
    name: "K. Desai",
    roleSlug: "investigator",
    isOwner: false,
    status: "active",
    mfa: "verified",
    department: "Gujarat Cyber Crime Cell",
    supabaseId: "3b91ce77-4a52-4b18-8f01-6d2ac8e41730",
    joinedAt: daysAgo(295),
    lastSignInAt: ago(64),
    lastActivityAt: ago(18),
    invitationState: "accepted",
    deniedLast24h: 0,
    permissions: ROLES[1].permissions.map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" })),
    caseMemberships: [
      { caseId: "CASE-2026-0142", caseTitle: "Exfiltration — Sector 7 relay", role: "Investigator", addedAt: daysAgo(9) },
      { caseId: "CASE-2026-0138", caseTitle: "Beaconing — municipal VPN", role: "Investigator", addedAt: daysAgo(21) },
    ],
  },
  {
    id: 41,
    email: "a.mehta@gcc.gov.in",
    name: "A. Mehta",
    roleSlug: "analyst",
    isOwner: false,
    status: "active",
    mfa: "unenrolled",
    department: "Gujarat Cyber Crime Cell",
    supabaseId: "c4d70a19-9e35-4a72-bb64-2f8e11c30d5a",
    joinedAt: daysAgo(151),
    lastSignInAt: ago(330),
    lastActivityAt: ago(40),
    invitationState: "accepted",
    deniedLast24h: 11,
    permissions: [
      { key: "view", source: "role", expiresAt: null, reason: "", grantedBy: "" },
      { key: "review", source: "role", expiresAt: null, reason: "", grantedBy: "" },
      { key: "upload", source: "revoked", expiresAt: null, reason: "Suspended pending review of repeated export attempts.", grantedBy: "Inspector A. Patel" },
      { key: "export", source: "granted", expiresAt: ahead(21), reason: "Temporary access for the Sector 7 handover pack.", grantedBy: "Inspector A. Patel" },
    ],
    caseMemberships: [
      { caseId: "CASE-2026-0142", caseTitle: "Exfiltration — Sector 7 relay", role: "Analyst", addedAt: daysAgo(9) },
      { caseId: "CASE-2026-0139", caseTitle: "Credential stuffing — payroll portal", role: "Analyst", addedAt: daysAgo(14) },
      { caseId: "CASE-2026-0131", caseTitle: "Lateral movement — records annexe", role: "Viewer", addedAt: daysAgo(28) },
    ],
  },
  {
    id: 44,
    email: "p.iyer@gcc.gov.in",
    name: "P. Iyer",
    roleSlug: "analyst",
    isOwner: false,
    status: "locked_out",
    mfa: "factor_lost",
    department: "Gujarat Cyber Crime Cell",
    supabaseId: "77aa2f5b-6c14-4d90-a2e7-91b0c4d85e63",
    joinedAt: daysAgo(88),
    lastSignInAt: daysAgo(3),
    lastActivityAt: daysAgo(3),
    invitationState: "accepted",
    deniedLast24h: 0,
    permissions: ROLES[2].permissions.map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" })),
    caseMemberships: [{ caseId: "CASE-2026-0138", caseTitle: "Beaconing — municipal VPN", role: "Analyst", addedAt: daysAgo(21) }],
  },
  {
    id: 52,
    email: "r.shah@gcc.gov.in",
    name: "R. Shah",
    roleSlug: "viewer",
    isOwner: false,
    status: "invited",
    mfa: "unenrolled",
    department: "Gujarat Cyber Crime Cell",
    supabaseId: "",
    joinedAt: ago(310),
    lastSignInAt: null,
    lastActivityAt: null,
    invitationState: "expiring",
    deniedLast24h: 0,
    permissions: ROLES[3].permissions.map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" })),
    caseMemberships: [],
  },
  {
    id: 57,
    email: "m.joshi@gcc.gov.in",
    name: "M. Joshi",
    roleSlug: "evidence_clerk",
    isOwner: false,
    status: "active",
    mfa: "verified",
    department: "Records Desk",
    supabaseId: "d1e88b03-5f27-49ca-8b16-3ce7a0f2149d",
    joinedAt: daysAgo(64),
    lastSignInAt: ago(190),
    lastActivityAt: ago(95),
    invitationState: "accepted",
    deniedLast24h: 2,
    permissions: ROLES[5].permissions.map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" })),
    caseMemberships: [{ caseId: "CASE-2026-0131", caseTitle: "Lateral movement — records annexe", role: "Viewer", addedAt: daysAgo(28) }],
  },
  {
    id: 63,
    email: "s.nair@gcc.gov.in",
    name: "S. Nair",
    roleSlug: "viewer",
    isOwner: false,
    status: "deactivated",
    mfa: "unenrolled",
    department: "Gujarat Cyber Crime Cell",
    supabaseId: "9c05e7a4-8d31-4f56-b0a9-45e2c1f78802",
    joinedAt: daysAgo(300),
    lastSignInAt: daysAgo(96),
    lastActivityAt: daysAgo(96),
    invitationState: "accepted",
    deniedLast24h: 0,
    permissions: [],
    caseMemberships: [],
  },
  {
    id: 70,
    email: "v.rathod@gcc.gov.in",
    name: "V. Rathod",
    roleSlug: "investigator",
    isOwner: false,
    status: "active",
    mfa: "verified",
    department: "Gujarat Cyber Crime Cell",
    supabaseId: "b6f3d920-2a48-4c7e-9351-e08fa7c46b1d",
    joinedAt: daysAgo(198),
    lastSignInAt: ago(420),
    lastActivityAt: ago(230),
    invitationState: "accepted",
    deniedLast24h: 0,
    permissions: ROLES[1].permissions.map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" })),
    caseMemberships: [{ caseId: "CASE-2026-0139", caseTitle: "Credential stuffing — payroll portal", role: "Investigator", addedAt: daysAgo(14) }],
  },
];

/* ---------------------------------------------------------------------------
   Activity — the union of the five streams described in plan §6.
   --------------------------------------------------------------------------- */
export const ACTIVITY: ActivityEvent[] = [
  { id: "a1", at: ago(3), actor: "A. Mehta", actorEmail: "a.mehta@gcc.gov.in", role: "Analyst", action: "permission:export", target: "Case CASE-2026-0142", result: "denied", source: "AccessLog", chainIndex: null },
  { id: "a2", at: ago(5), actor: "A. Mehta", actorEmail: "a.mehta@gcc.gov.in", role: "Analyst", action: "permission:export", target: "Case CASE-2026-0142", result: "denied", source: "AccessLog", chainIndex: null },
  { id: "a3", at: ago(9), actor: "A. Mehta", actorEmail: "a.mehta@gcc.gov.in", role: "Analyst", action: "permission:operations", target: "—", result: "denied", source: "AccessLog", chainIndex: null },
  { id: "a4", at: ago(14), actor: "Inspector A. Patel", actorEmail: "a.patel@gcc.gov.in", role: "Owner", action: "user.role_changed", target: "User 57 → Evidence Clerk", result: "allowed", source: "AdminAudit", chainIndex: 214 },
  { id: "a5", at: ago(18), actor: "K. Desai", actorEmail: "k.desai@gcc.gov.in", role: "Investigator", action: "permission:review", target: "Case CASE-2026-0142", result: "allowed", source: "AccessLog", chainIndex: null },
  { id: "a6", at: ago(26), actor: "system", actorEmail: "", role: "—", action: "evidence.custody_append", target: "CASE-2026-0142 · chain 812", result: "recorded", source: "Custody", chainIndex: 812 },
  { id: "a7", at: ago(34), actor: "A. Mehta", actorEmail: "a.mehta@gcc.gov.in", role: "Analyst", action: "permission:export", target: "Case CASE-2026-0139", result: "denied", source: "AccessLog", chainIndex: null },
  { id: "a8", at: ago(41), actor: "Inspector A. Patel", actorEmail: "a.patel@gcc.gov.in", role: "Owner", action: "credential.recovery_link", target: "User 44 · P. Iyer", result: "allowed", source: "AdminAudit", chainIndex: 213 },
  { id: "a9", at: ago(52), actor: "M. Joshi", actorEmail: "m.joshi@gcc.gov.in", role: "Evidence Clerk", action: "permission:compliance", target: "—", result: "denied", source: "AccessLog", chainIndex: null },
  { id: "a10", at: ago(68), actor: "system", actorEmail: "", role: "—", action: "job.completed", target: "Analysis job 8814", result: "recorded", source: "OperationalEvent", chainIndex: null },
  { id: "a11", at: ago(84), actor: "Inspector A. Patel", actorEmail: "a.patel@gcc.gov.in", role: "Owner", action: "permission.granted", target: "User 41 · +export until 01 Sep", result: "allowed", source: "AdminAudit", chainIndex: 212 },
  { id: "a12", at: ago(96), actor: "M. Joshi", actorEmail: "m.joshi@gcc.gov.in", role: "Evidence Clerk", action: "permission:export", target: "Case CASE-2026-0131", result: "allowed", source: "AccessLog", chainIndex: null },
  { id: "a13", at: ago(120), actor: "K. Desai", actorEmail: "k.desai@gcc.gov.in", role: "Investigator", action: "case.status_changed", target: "CASE-2026-0138 → open", result: "recorded", source: "CaseHistory", chainIndex: null },
  { id: "a14", at: ago(155), actor: "V. Rathod", actorEmail: "v.rathod@gcc.gov.in", role: "Investigator", action: "permission:upload", target: "Case CASE-2026-0139", result: "allowed", source: "AccessLog", chainIndex: null },
  { id: "a15", at: ago(190), actor: "M. Joshi", actorEmail: "m.joshi@gcc.gov.in", role: "Evidence Clerk", action: "auth.sign_in", target: "console.netra.app · aal1", result: "allowed", source: "AccessLog", chainIndex: null },
  { id: "a16", at: ago(240), actor: "Inspector A. Patel", actorEmail: "a.patel@gcc.gov.in", role: "Owner", action: "user.invited", target: "r.shah@gcc.gov.in · Viewer", result: "allowed", source: "AdminAudit", chainIndex: 211 },
  { id: "a17", at: ago(310), actor: "system", actorEmail: "", role: "—", action: "evidence.custody_append", target: "CASE-2026-0139 · chain 604", result: "recorded", source: "Custody", chainIndex: 604 },
  { id: "a18", at: ago(330), actor: "A. Mehta", actorEmail: "a.mehta@gcc.gov.in", role: "Analyst", action: "auth.sign_in", target: "console.netra.app · aal1", result: "allowed", source: "AccessLog", chainIndex: null },
];

/* ---------------------------------------------------------------------------
   Sessions
   --------------------------------------------------------------------------- */
export const SESSIONS: SessionRow[] = [
  { id: "s1", userId: 1, userName: "Inspector A. Patel", userEmail: "a.patel@gcc.gov.in", origin: "admin.netra.app", aal: "aal2", startedAt: ago(6), lastSeenAt: ago(1), ipHint: "10.24.x.x" },
  { id: "s2", userId: 1, userName: "Inspector A. Patel", userEmail: "a.patel@gcc.gov.in", origin: "console.netra.app", aal: "aal2", startedAt: ago(180), lastSeenAt: ago(22), ipHint: "10.24.x.x" },
  { id: "s3", userId: 41, userName: "A. Mehta", userEmail: "a.mehta@gcc.gov.in", origin: "console.netra.app", aal: "aal1", startedAt: ago(330), lastSeenAt: ago(3), ipHint: "10.24.x.x" },
  { id: "s4", userId: 41, userName: "A. Mehta", userEmail: "a.mehta@gcc.gov.in", origin: "console.netra.app", aal: "aal1", startedAt: daysAgo(2), lastSeenAt: daysAgo(2), ipHint: "203.0.x.x" },
  { id: "s5", userId: 12, userName: "K. Desai", userEmail: "k.desai@gcc.gov.in", origin: "console.netra.app", aal: "aal2", startedAt: ago(64), lastSeenAt: ago(18), ipHint: "10.24.x.x" },
  { id: "s6", userId: 70, userName: "V. Rathod", userEmail: "v.rathod@gcc.gov.in", origin: "console.netra.app", aal: "aal2", startedAt: ago(420), lastSeenAt: ago(230), ipHint: "10.24.x.x" },
  { id: "s7", userId: 57, userName: "M. Joshi", userEmail: "m.joshi@gcc.gov.in", origin: "console.netra.app", aal: "aal2", startedAt: ago(190), lastSeenAt: ago(95), ipHint: "10.31.x.x" },
];

/* ---------------------------------------------------------------------------
   Capabilities — mirrors capability_registry() in backend/common/capabilities.py
   --------------------------------------------------------------------------- */
export const CAPABILITIES: CapabilityFlag[] = [
  { key: "user_invitations", state: "disabled", reason: "User invitations require an approved custom SMTP domain.", requiresAal2: true, durableConsumer: null },
  { key: "password_recovery", state: "disabled", reason: "Password recovery requires an approved custom SMTP domain.", requiresAal2: false, durableConsumer: null },
  { key: "analysis_references", state: "available", reason: "Durable workspace and analysis-job scoped references are available.", requiresAal2: false, durableConsumer: null },
  { key: "structured_log_import", state: "disabled", reason: "Structured-log import is disabled for this deployment profile.", requiresAal2: false, durableConsumer: "postgres-worker:capture_log_import" },
  { key: "zeek_log_import", state: "disabled", reason: "Zeek-log import is disabled for this deployment profile.", requiresAal2: false, durableConsumer: "postgres-worker:zeek_log_import" },
  { key: "integration_configuration", state: "disabled", reason: "Integration configuration is disabled for this deployment profile.", requiresAal2: true, durableConsumer: null },
  { key: "integration_delivery", state: "disabled", reason: "Outbound delivery requires integrations and an exact webhook hostname allowlist.", requiresAal2: true, durableConsumer: "postgres-worker:integration_delivery" },
  { key: "integration_case_linking", state: "disabled", reason: "Integration case linking is disabled for this deployment profile.", requiresAal2: false, durableConsumer: null },
  { key: "integration_external_sync", state: "not_implemented", reason: "No reviewed external synchronization adapter is installed.", requiresAal2: false, durableConsumer: null },
  { key: "sse", state: "available", reason: "Bounded authenticated Django SSE is available.", requiresAal2: false, durableConsumer: null },
  { key: "postgres_search", state: "available", reason: "Scoped Postgres search is available.", requiresAal2: false, durableConsumer: null },
  { key: "elasticsearch_search", state: "disabled", reason: "Elasticsearch search is experimental and disabled in production.", requiresAal2: false, durableConsumer: null },
  { key: "capture_stop", state: "disabled", reason: "Capture controls are disabled for this deployment profile.", requiresAal2: false, durableConsumer: null },
];

/* ---------------------------------------------------------------------------
   Admin audit — the hash-chained record of this console's own writes.
   --------------------------------------------------------------------------- */
export const AUDIT: AuditEvent[] = [
  {
    id: "e214", chainIndex: 214, at: ago(14), actor: "Inspector A. Patel",
    action: "user.role_changed", targetType: "UserProfile", targetId: "57",
    reason: "Records desk needs export for the quarterly handover pack.",
    before: "role=analyst", after: "role=evidence_clerk",
    previousHash: "9d41c8…7b2e", eventHash: "4fa07b…13c9",
  },
  {
    id: "e213", chainIndex: 213, at: ago(41), actor: "Inspector A. Patel",
    action: "credential.recovery_link_generated", targetType: "AuthUser", targetId: "44",
    reason: "Authenticator device lost. Identity verified in person against service record.",
    before: "—", after: "link issued, expires in 60 min",
    previousHash: "1c77ea…9f40", eventHash: "9d41c8…7b2e",
  },
  {
    id: "e212", chainIndex: 212, at: ago(84), actor: "Inspector A. Patel",
    action: "permission.granted", targetType: "UserProfile", targetId: "41",
    reason: "Temporary export access for the Sector 7 handover pack.",
    before: "—", after: "+export expires 01 Sep 2026",
    previousHash: "6b02af…c815", eventHash: "1c77ea…9f40",
  },
  {
    id: "e211", chainIndex: 211, at: ago(240), actor: "Inspector A. Patel",
    action: "user.invited", targetType: "AuthUser", targetId: "r.shah@gcc.gov.in",
    reason: "New records liaison joining the unit this week.",
    before: "—", after: "role=viewer, invitation sent",
    previousHash: "aa39d1…0e77", eventHash: "6b02af…c815",
  },
  {
    id: "e210", chainIndex: 210, at: daysAgo(2), actor: "Inspector A. Patel",
    action: "permission.revoked", targetType: "UserProfile", targetId: "41",
    reason: "Suspended pending review of repeated export attempts on CASE-2026-0142.",
    before: "upload=role", after: "upload=revoked",
    previousHash: "33fe80…b6a1", eventHash: "aa39d1…0e77",
  },
];

export const ORGANIZATION: OrganizationSettings = {
  id: "0f8a1b52-6d34-4c19-9e02-7a3d8f5c1b40",
  name: "Gujarat Cyber Crime Cell",
  slug: "netra",
  ownerUserId: 1,
  maxQueuedAnalyses: 5,
  accessLogRetentionDays: 90,
  mfaPolicy: "admin_required",
  createdAt: daysAgo(410),
};

export const OVERVIEW: OverviewSummary = {
  activeUsers: USERS.filter((user) => user.status === "active").length,
  activeUsersTrend: [3, 3, 4, 4, 4, 5, 5],
  newUsersThisWeek: 2,
  deniedLast24h: ACTIVITY.filter((event) => event.result === "denied").length,
  deniedTrend: [0, 1, 0, 0, 2, 1, 5],
  deniedTopActor: "A. Mehta",
  mfaEnrolled: USERS.filter((user) => user.mfa === "verified").length,
  mfaTotal: USERS.filter((user) => user.status !== "deactivated").length,
  pendingInvites: USERS.filter((user) => user.status === "invited").length,
  invitesExpiringToday: 1,
  temporaryGrants: USERS.flatMap((user) => user.permissions).filter((permission) => permission.expiresAt).length,
  staleAccounts: 2,
};

/** The signed-in operator. Step-up freshness drives the header badge — see
 *  plan §3; it derives from the `amr` claim once that is plumbed through. */
export const CURRENT_OPERATOR = {
  name: "Inspector A. Patel",
  email: "a.patel@gcc.gov.in",
  role: "Owner",
  aal: "aal2" as const,
  stepUpVerifiedAt: ago(4),
};

export const PERMISSION_BY_KEY = new Map<PermissionKey, Permission>(PERMISSIONS.map((permission) => [permission.key, permission]));
export const ROLE_BY_SLUG = new Map<string, Role>(ROLES.map((role) => [role.slug, role]));
