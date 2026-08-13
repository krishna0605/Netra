import { API_BASE_URL } from "../lib/env";
import { supabase } from "../lib/supabase";
import { ACTIVITY, AUDIT, CAPABILITIES, CURRENT_OPERATOR, ORGANIZATION, PERMISSIONS, ROLES, SESSIONS, USERS } from "./mock";
import type {
  ActivityEvent,
  AdminUser,
  AuditEvent,
  EffectivePermission,
  CapabilityFlag,
  OrganizationSettings,
  Permission,
  PermissionKey,
  Role,
  RoleSlug,
  SessionRow,
  UserStatus,
} from "./types";

/**
 * The transport boundary.
 *
 * Everything above this file treats these as network calls: they are async,
 * they can fail, and they return the state the server now holds rather than
 * assuming the caller can predict it. Today the "server" is in this module.
 * When the Django namespace exists, only the bodies here change — no screen,
 * dialog or state machine moves.
 *
 * Passwords are deliberately absent from every request and response shape.
 * They are shown once at the moment they are set and never stored.
 */

export type DirectorySnapshot = {
  users: AdminUser[];
  sessions: SessionRow[];
  activity: ActivityEvent[];
  audit: AuditEvent[];
  roles: Role[];
  organization: OrganizationSettings;
  /** The permission catalogue and feature flags are server-owned too, so they
   *  travel in the snapshot rather than being imported from a seed file.
   *  Otherwise a screen keeps reading fixtures after the backend lands. */
  permissions: Permission[];
  capabilities: CapabilityFlag[];
};

export class ApiFailure extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status = 500) {
    super(message);
    this.name = "ApiFailure";
    this.code = code;
    this.status = status;
  }
}

/* ---------------------------------------------------------------------------
   Development controls
   --------------------------------------------------------------------------- */

/**
 * States that only appear on a slow or failing network are the ones that never
 * get looked at. These make them reachable on demand:
 *
 *   netraSimulate("slow")   — three second responses
 *   netraSimulate("error")  — every call fails
 *   netraSimulate("")       — back to normal
 */
type Simulation = "" | "slow" | "error";

function simulation(): Simulation {
  if (typeof window === "undefined") return "";
  return (window.localStorage.getItem("netra.simulate") as Simulation) ?? "";
}

if (typeof window !== "undefined") {
  (window as unknown as Record<string, unknown>).netraSimulate = (mode: Simulation) => {
    if (mode) window.localStorage.setItem("netra.simulate", mode);
    else window.localStorage.removeItem("netra.simulate");
    return `simulation: ${mode || "off"} — reload or refetch to see it`;
  };
}

async function settle<T>(value: T): Promise<T> {
  const mode = simulation();
  const delay = mode === "slow" ? 3000 : 220 + Math.random() * 260;
  await new Promise((resolve) => setTimeout(resolve, delay));
  if (mode === "error") {
    throw new ApiFailure("upstream_unavailable", "The directory service did not respond.", 503);
  }
  return value;
}

/* ---------------------------------------------------------------------------
   Persistence — stands in for the database
   --------------------------------------------------------------------------- */

const now = () => new Date().toISOString();

function marker(input: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  const hex = hash.toString(16).padStart(8, "0");
  return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

function seed(): DirectorySnapshot {
  return {
    users: USERS,
    sessions: SESSIONS,
    activity: ACTIVITY,
    audit: AUDIT,
    roles: ROLES,
    organization: ORGANIZATION,
    permissions: PERMISSIONS,
    capabilities: CAPABILITIES,
  };
}

/**
 * State lives in memory for the lifetime of the tab, and nowhere else.
 *
 * It used to persist to localStorage, which was reasonable while this module
 * stood in for a database. It is not reasonable now that a real one exists.
 * The admin console already goes out of its way to keep its Supabase session
 * out of localStorage — memory-only storage under a separate key — precisely
 * because the two consoles share an origin and therefore share that store.
 * Writing the full directory there anyway would have put every officer's
 * address, role and denial count into the same place, on what may be a shared
 * machine, surviving sign-out.
 */
let state: DirectorySnapshot = seed();

function commit(next: DirectorySnapshot): DirectorySnapshot {
  state = next;
  return state;
}

/** Every administrator write lands in both records, as the server will do. */
function record(
  base: DirectorySnapshot,
  entry: { action: string; targetType: string; targetId: string; reason: string; before: string; after: string },
): DirectorySnapshot {
  const at = now();
  const previous = base.audit[0];
  const chainIndex = (previous?.chainIndex ?? 200) + 1;

  const auditEvent: AuditEvent = {
    id: `e${chainIndex}`,
    chainIndex,
    at,
    actor: CURRENT_OPERATOR.name,
    action: entry.action,
    targetType: entry.targetType,
    targetId: entry.targetId,
    reason: entry.reason,
    before: entry.before,
    after: entry.after,
    previousHash: previous?.eventHash ?? marker("genesis"),
    eventHash: marker(`${chainIndex}${entry.action}${entry.targetId}${at}`),
  };

  const activityEvent: ActivityEvent = {
    id: `a-${chainIndex}`,
    at,
    actor: CURRENT_OPERATOR.name,
    actorEmail: CURRENT_OPERATOR.email,
    role: CURRENT_OPERATOR.role,
    action: entry.action,
    target: `${entry.targetType} · ${entry.targetId}`,
    result: "allowed",
    source: "AdminAudit",
    chainIndex,
  };

  return { ...base, audit: [auditEvent, ...base.audit], activity: [activityEvent, ...base.activity] };
}

function requireUser(snapshot: DirectorySnapshot, userId: number): AdminUser {
  const user = snapshot.users.find((entry) => entry.id === userId);
  if (!user) throw new ApiFailure("resource_not_found", "That account no longer exists.", 404);
  return user;
}

/* ---------------------------------------------------------------------------
   The surface
   --------------------------------------------------------------------------- */

export type CreateUserInput = {
  name: string;
  email: string;
  department: string;
  roleSlug: RoleSlug;
  mustChangePassword: boolean;
};

export type SetPasswordInput = {
  userId: number;
  reason: string;
  requireChange: boolean;
  revokeSessions: boolean;
};

/**
 * Test seam. The module holds one state, as a server would, so tests that
 * mutate it would otherwise leak into each other and pass or fail by
 * ordering. Clearing storage alone is not enough — the in-memory copy is
 * already loaded.
 */
export function resetDirectory() {
  state = seed();
}

/** Test seam. The write operations still run against the in-memory snapshot
 *  until their endpoints exist, and a test needs to see that snapshot without
 *  going through the network. Not used by the console itself. */
export function currentDirectory(): DirectorySnapshot {
  return state;
}

/* ---------------------------------------------------------------------------
   The network
   --------------------------------------------------------------------------- */

/** Maps a failed response onto a sentence an operator can act on.
 *
 *  The distinction that matters is "you are not allowed" versus "we could not
 *  ask". Collapsing them is what made a suspended Supabase project look like a
 *  rejected password during the frontend build, and cost an evening.
 */
function describe(status: number, code: string): string {
  if (status === 401) return "This session is no longer valid. Sign in again.";
  if (status === 403 && code === "aal2_required") {
    return "Administration requires a verified authenticator on this session.";
  }
  if (status === 403) return "This account is not permitted to administer the organization.";
  if (status === 404) return "The administration service is not available on this address.";
  if (status === 429) return "Too many requests. Wait a moment and try again.";
  if (status >= 500) return "The administration service is temporarily unavailable.";
  return "The administration service refused the request.";
}

async function authorizedRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  // The dev controls have to apply here too, not only to the local writes.
  // Reads are the calls most likely to be slow or to fail in production, so
  // they are exactly the ones whose loading and failure states need to be
  // reachable on demand.
  const mode = simulation();
  if (mode === "slow") {
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  if (mode === "error") {
    throw new ApiFailure("upstream_unavailable", "The directory service did not respond.", 503);
  }

  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) {
    throw new ApiFailure("session_missing", "This session is no longer valid. Sign in again.", 401);
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        ...(init.headers ?? {}),
        Authorization: `Bearer ${token}`,
        Accept: "application/json",
      },
    });
  } catch {
    // fetch only rejects for transport failures — offline, DNS, CORS, a server
    // that is not running. None of those are the operator's fault and none
    // should read as a rejection.
    throw new ApiFailure(
      "service_unreachable",
      "Could not reach the administration service. Check that it is running.",
      0,
    );
  }

  if (!response.ok) {
    let code = "request_failed";
    try {
      const body = await response.json();
      // Two error shapes are in play: the auth middleware answers flat, the
      // view helper nests under "error".
      code = (typeof body?.error === "object" ? body.error?.code : body?.code) || code;
    } catch {
      // A non-JSON error body is still a failure; the status carries the meaning.
    }
    throw new ApiFailure(code, describe(response.status, code), response.status);
  }

  return (await response.json()) as T;
}

/** What the server says about the caller's own administrative standing. */
export type AdminSession = {
  userId: number;
  name: string;
  email: string;
  role: string;
  roleSlug: string;
  isOwner: boolean;
  aal: "aal1" | "aal2";
  permissions: string[];
  organization: { id: string; name: string; slug: string };
};

/**
 * Ask the server whether this account may administer the organization.
 *
 * The console used to answer this itself, from a seed file, falling back to
 * "yes" for any account that could authenticate against the project. That was
 * fenced behind a development flag and still the wrong shape of answer: whether
 * someone is an administrator is a fact about a row in Postgres, and the only
 * honest way to learn it is to ask.
 */
export function fetchAdminSession(): Promise<AdminSession> {
  return authorizedRequest<AdminSession>("/admin/v1/session");
}

export const directoryApi = {
  /** The only read the console performs. Every screen renders from this. */
  async read(): Promise<DirectorySnapshot> {
    const snapshot = await authorizedRequest<DirectorySnapshot>("/admin/v1/directory");
    // Writes below still operate on the in-memory snapshot until their
    // endpoints exist, so the fetched state has to become the state they see.
    // Without this a create would be applied to seed data and vanish on the
    // next read, which looks exactly like the server silently rejecting it.
    state = snapshot;
    return snapshot;
  },

  async createUser(input: CreateUserInput) {
    const email = input.email.trim().toLowerCase();
    if (state.users.some((user) => user.email.toLowerCase() === email)) {
      await settle(null);
      throw new ApiFailure("email_in_use", "An account with that address already exists.", 409);
    }

    const role = state.roles.find((entry) => entry.slug === input.roleSlug);
    const created: AdminUser = {
      id: Math.max(0, ...state.users.map((user) => user.id)) + 1,
      email,
      name: input.name.trim(),
      roleSlug: input.roleSlug,
      isOwner: false,
      status: "active",
      mfa: "unenrolled",
      department: input.department.trim(),
      supabaseId: crypto.randomUUID(),
      joinedAt: now(),
      lastSignInAt: null,
      lastActivityAt: null,
      invitationState: "none",
      deniedLast24h: 0,
      permissions: (role?.permissions ?? []).map((key) => ({
        key,
        source: "role" as const,
        expiresAt: null,
        reason: "",
        grantedBy: "",
      })),
      caseMemberships: [],
    };

    const next = record({ ...state, users: [created, ...state.users] }, {
      action: "user.created",
      targetType: "Account",
      targetId: created.email,
      reason: `Account provisioned as ${role?.name ?? input.roleSlug}.`,
      before: "—",
      after: `${role?.name ?? input.roleSlug}${input.mustChangePassword ? ", password change required" : ""}`,
    });

    await settle(null);
    commit(next);
    return { snapshot: state, created };
  },

  async changeRole(userId: number, roleSlug: RoleSlug, reason: string) {
    const target = requireUser(state, userId);
    if (target.roleSlug === roleSlug) return settle(state);

    const previousRole = state.roles.find((entry) => entry.slug === target.roleSlug);
    const nextRole = state.roles.find((entry) => entry.slug === roleSlug);

    // Explicit grants and revocations survive a role change; only the
    // role-derived set is swapped. A temporary grant silently vanishing on a
    // promotion would be a nasty way to lose access.
    const kept = target.permissions.filter((permission) => permission.source !== "role");
    const fromRole: EffectivePermission[] = (nextRole?.permissions ?? [])
      .filter((key) => !kept.some((permission) => permission.key === key))
      .map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" }));

    const users = state.users.map((user) =>
      user.id === userId ? { ...user, roleSlug, permissions: [...fromRole, ...kept] } : user,
    );

    const next = record({ ...state, users }, {
      action: "user.role_changed",
      targetType: "Account",
      targetId: target.email,
      reason,
      before: previousRole?.name ?? target.roleSlug,
      after: nextRole?.name ?? roleSlug,
    });

    await settle(null);
    return commit(next);
  },

  async setPassword({ userId, reason, requireChange, revokeSessions }: SetPasswordInput) {
    const target = requireUser(state, userId);
    const users = state.users.map((user) =>
      user.id === userId ? { ...user, status: user.status === "locked_out" ? ("active" as const) : user.status } : user,
    );
    const sessions = revokeSessions ? state.sessions.filter((session) => session.userId !== userId) : state.sessions;

    const next = record({ ...state, users, sessions }, {
      action: "credential.password_set",
      targetType: "Account",
      targetId: target.email,
      reason,
      before: "—",
      after: [
        "password replaced",
        requireChange ? "change required at next sign-in" : null,
        revokeSessions ? "all sessions revoked" : null,
      ]
        .filter(Boolean)
        .join(", "),
    });

    await settle(null);
    return commit(next);
  },

  async setStatus(userId: number, status: UserStatus, reason: string) {
    const target = requireUser(state, userId);
    if (target.isOwner && status === "deactivated") {
      await settle(null);
      throw new ApiFailure("owner_protected", "The owner cannot be deactivated. Transfer ownership first.", 409);
    }

    const users = state.users.map((user) => (user.id === userId ? { ...user, status } : user));
    const sessions = status === "deactivated" ? state.sessions.filter((session) => session.userId !== userId) : state.sessions;

    const next = record({ ...state, users, sessions }, {
      action: status === "deactivated" ? "user.deactivated" : "user.reactivated",
      targetType: "Account",
      targetId: target.email,
      reason,
      before: target.status,
      after: status,
    });

    await settle(null);
    return commit(next);
  },

  async resetAuthenticator(userId: number, reason: string) {
    const target = requireUser(state, userId);
    const users = state.users.map((user) => (user.id === userId ? { ...user, mfa: "unenrolled" as const } : user));

    const next = record({ ...state, users }, {
      action: "credential.authenticator_reset",
      targetType: "Account",
      targetId: target.email,
      reason,
      before: target.mfa,
      after: "unenrolled, must re-enrol at next sign-in",
    });

    await settle(null);
    return commit(next);
  },

  async revokeSession(sessionId: string) {
    const next = { ...state, sessions: state.sessions.filter((session) => session.id !== sessionId) };
    await settle(null);
    return commit(next);
  },

  async revokeUserSessions(userId: number) {
    const target = requireUser(state, userId);
    const sessions = state.sessions.filter((session) => session.userId !== userId);
    const removed = state.sessions.length - sessions.length;

    const next = record({ ...state, sessions }, {
      action: "session.revoked_all",
      targetType: "Account",
      targetId: target.email,
      reason: "Signed out of every device.",
      before: `${removed} active`,
      after: "0 active",
    });

    await settle(null);
    return commit(next);
  },

  async revokeAllSessions() {
    const next = record({ ...state, sessions: [] }, {
      action: "session.revoked_organization",
      targetType: "Organization",
      targetId: "netra",
      reason: "Every session across the organization was ended.",
      before: `${state.sessions.length} active`,
      after: "0 active",
    });

    await settle(null);
    return commit(next);
  },

  async grantPermission(userId: number, key: PermissionKey, expiresAt: string | null, reason: string) {
    const target = requireUser(state, userId);
    const permissions: EffectivePermission[] = [
      ...target.permissions.filter((permission) => permission.key !== key),
      { key, source: "granted", expiresAt, reason, grantedBy: CURRENT_OPERATOR.name },
    ];
    const users = state.users.map((user) => (user.id === userId ? { ...user, permissions } : user));

    const next = record({ ...state, users }, {
      action: "permission.granted",
      targetType: "Account",
      targetId: target.email,
      reason,
      before: "—",
      after: `+${key}${expiresAt ? ` until ${new Date(expiresAt).toLocaleDateString("en-IN")}` : ", no expiry"}`,
    });

    await settle(null);
    return commit(next);
  },

  async createRole(input: { name: string; description: string; baseSlug: string }) {
    const slug = input.name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
    if (!slug) throw new ApiFailure("invalid_role_name", "Give the role a name.", 400);
    if (state.roles.some((role) => role.slug === slug)) {
      await settle(null);
      throw new ApiFailure("role_exists", "A role with that name already exists.", 409);
    }

    const base = state.roles.find((role) => role.slug === input.baseSlug);
    const created: Role = {
      slug,
      name: input.name.trim(),
      description: input.description.trim() || `Cloned from ${base?.name ?? "an existing role"}.`,
      isSystem: false,
      permissions: [...(base?.permissions ?? [])],
      memberCount: 0,
    };

    const next = record({ ...state, roles: [...state.roles, created] }, {
      action: "role.created",
      targetType: "Role",
      targetId: slug,
      reason: `Cloned from ${base?.name ?? "an existing role"}.`,
      before: "—",
      after: `${created.permissions.length} permissions`,
    });

    await settle(null);
    commit(next);
    return { snapshot: state, created };
  },

  async setRolePermission(slug: string, key: PermissionKey, held: boolean) {
    const role = state.roles.find((entry) => entry.slug === slug);
    if (!role) throw new ApiFailure("resource_not_found", "That role no longer exists.", 404);
    if (role.isSystem) {
      await settle(null);
      throw new ApiFailure("system_role_locked", "Standard roles cannot be edited. Clone one to customise it.", 409);
    }

    const permissions = held
      ? [...new Set([...role.permissions, key])]
      : role.permissions.filter((entry) => entry !== key);
    const roles = state.roles.map((entry) => (entry.slug === slug ? { ...entry, permissions } : entry));

    const next = record({ ...state, roles }, {
      action: held ? "role.permission_added" : "role.permission_removed",
      targetType: "Role",
      targetId: slug,
      reason: `${held ? "Added" : "Removed"} ${key} on ${role.name}.`,
      before: held ? "—" : key,
      after: held ? key : "—",
    });

    await settle(null);
    return commit(next);
  },

  async updateOrganization(
    changes: Partial<Pick<OrganizationSettings, "name" | "maxQueuedAnalyses" | "accessLogRetentionDays">>,
  ) {
    const before = state.organization;
    const organization = { ...before, ...changes };

    const described = Object.entries(changes)
      .filter(([key, value]) => before[key as keyof OrganizationSettings] !== value)
      .map(([key, value]) => `${key}=${String(value)}`)
      .join(", ");

    if (!described) return settle(state);

    const next = record({ ...state, organization }, {
      action: "organization.updated",
      targetType: "Organization",
      targetId: before.slug,
      reason: "Organization settings changed by an administrator.",
      before: Object.keys(changes)
        .map((key) => `${key}=${String(before[key as keyof OrganizationSettings])}`)
        .join(", "),
      after: described,
    });

    await settle(null);
    return commit(next);
  },

  async transferOwnership(targetUserId: number, reason: string) {
    const target = requireUser(state, targetUserId);
    const current = state.users.find((user) => user.isOwner);

    if (target.isOwner) {
      await settle(null);
      throw new ApiFailure("already_owner", "That account already owns this organization.", 409);
    }
    if (target.status !== "active") {
      await settle(null);
      throw new ApiFailure("inactive_target", "Ownership can only pass to an active account.", 409);
    }

    // Demote and promote together. A moment with no owner, or with two, is a
    // state nothing downstream should ever have to interpret.
    const users = state.users.map((user) => ({
      ...user,
      isOwner: user.id === targetUserId,
      roleSlug:
        user.id === targetUserId ? "admin" : user.id === current?.id ? "investigator" : user.roleSlug,
    }));

    const next = record(
      { ...state, users, organization: { ...state.organization, ownerUserId: targetUserId } },
      {
        action: "organization.owner_transferred",
        targetType: "Organization",
        targetId: state.organization.slug,
        reason,
        before: current?.email ?? "—",
        after: target.email,
      },
    );

    await settle(null);
    return commit(next);
  },

  async removeGrant(userId: number, key: PermissionKey) {
    const target = requireUser(state, userId);
    const role = state.roles.find((entry) => entry.slug === target.roleSlug);
    const permissions = target.permissions.filter((permission) => permission.key !== key);
    if (role?.permissions.includes(key)) {
      permissions.push({ key, source: "role", expiresAt: null, reason: "", grantedBy: "" });
    }
    const users = state.users.map((user) => (user.id === userId ? { ...user, permissions } : user));

    const next = record({ ...state, users }, {
      action: "permission.grant_removed",
      targetType: "Account",
      targetId: target.email,
      reason: "Temporary permission withdrawn.",
      before: `+${key}`,
      after: role?.permissions.includes(key) ? `${key} from role` : "—",
    });

    await settle(null);
    return commit(next);
  },
};
