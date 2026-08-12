import { ACTIVITY, AUDIT, CURRENT_OPERATOR, ROLE_BY_SLUG, SESSIONS, USERS } from "./mock";
import type {
  ActivityEvent,
  AdminUser,
  AuditEvent,
  EffectivePermission,
  PermissionKey,
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

const STORAGE_KEY = "netra.directory.v1";

export type DirectorySnapshot = {
  users: AdminUser[];
  sessions: SessionRow[];
  activity: ActivityEvent[];
  audit: AuditEvent[];
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
  return { users: USERS, sessions: SESSIONS, activity: ACTIVITY, audit: AUDIT };
}

function load(): DirectorySnapshot {
  if (typeof window === "undefined") return seed();
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return seed();
    const parsed = JSON.parse(raw) as Partial<DirectorySnapshot>;
    if (!Array.isArray(parsed.users) || parsed.users.length === 0) return seed();
    return {
      users: parsed.users,
      sessions: parsed.sessions ?? SESSIONS,
      activity: parsed.activity ?? ACTIVITY,
      audit: parsed.audit ?? AUDIT,
    };
  } catch {
    return seed();
  }
}

let state: DirectorySnapshot = load();

function commit(next: DirectorySnapshot): DirectorySnapshot {
  state = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Storage being unavailable must never break the console.
  }
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

export const directoryApi = {
  read: () => settle(state),

  async createUser(input: CreateUserInput) {
    const email = input.email.trim().toLowerCase();
    if (state.users.some((user) => user.email.toLowerCase() === email)) {
      await settle(null);
      throw new ApiFailure("email_in_use", "An account with that address already exists.", 409);
    }

    const role = ROLE_BY_SLUG.get(input.roleSlug);
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

    const previousRole = ROLE_BY_SLUG.get(target.roleSlug);
    const nextRole = ROLE_BY_SLUG.get(roleSlug);

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

  async removeGrant(userId: number, key: PermissionKey) {
    const target = requireUser(state, userId);
    const role = ROLE_BY_SLUG.get(target.roleSlug);
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
