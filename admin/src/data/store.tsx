import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

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
 * The directory store.
 *
 * Every screen reads and writes through this one module. It holds the
 * organization's people, their sessions, and the two records that trail them.
 * Today it keeps state in the browser; when the server endpoints exist, only
 * the bodies of these functions change — no screen touches storage directly.
 *
 * Passwords are deliberately never held here. A password is shown once at the
 * moment it is set and then forgotten, which is how the real system behaves.
 */

const STORAGE_KEY = "netra.directory.v1";

type DirectorySnapshot = {
  users: AdminUser[];
  sessions: SessionRow[];
  activity: ActivityEvent[];
  audit: AuditEvent[];
};

type CreateUserInput = {
  name: string;
  email: string;
  department: string;
  roleSlug: RoleSlug;
  mustChangePassword: boolean;
};

type SetPasswordInput = {
  userId: number;
  reason: string;
  requireChange: boolean;
  revokeSessions: boolean;
};

type DirectoryValue = DirectorySnapshot & {
  createUser: (input: CreateUserInput) => AdminUser;
  changeRole: (userId: number, roleSlug: RoleSlug, reason: string) => void;
  setPassword: (input: SetPasswordInput) => void;
  setStatus: (userId: number, status: UserStatus, reason: string) => void;
  resetAuthenticator: (userId: number, reason: string) => void;
  revokeSession: (sessionId: string) => void;
  revokeUserSessions: (userId: number) => void;
  revokeAllSessions: () => void;
  grantPermission: (userId: number, key: PermissionKey, expiresAt: string | null, reason: string) => void;
  removeGrant: (userId: number, key: PermissionKey) => void;
};

const DirectoryContext = createContext<DirectoryValue | null>(null);

/* ---------------------------------------------------------------------------
   Helpers
   --------------------------------------------------------------------------- */

const now = () => new Date().toISOString();

/** Short content-derived marker, standing in for the server's real chain hash. */
function marker(input: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  const hex = hash.toString(16).padStart(8, "0");
  return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

/** Readable but strong: five groups of four from an unambiguous alphabet. */
export function generatePassword() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint32Array(20);
  crypto.getRandomValues(bytes);
  const characters = [...bytes].map((value) => alphabet[value % alphabet.length]);
  return [0, 4, 8, 12, 16].map((start) => characters.slice(start, start + 4).join("")).join("-");
}

export function passwordStrength(value: string) {
  if (value.length === 0) return { score: 0, label: "" };
  let score = 0;
  if (value.length >= 12) score += 1;
  if (value.length >= 20) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  const label = score <= 2 ? "Weak" : score === 3 ? "Fair" : score === 4 ? "Strong" : "Very strong";
  return { score, label };
}

function loadSnapshot(): DirectorySnapshot {
  const fallback: DirectorySnapshot = { users: USERS, sessions: SESSIONS, activity: ACTIVITY, audit: AUDIT };
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as Partial<DirectorySnapshot>;
    if (!Array.isArray(parsed.users) || parsed.users.length === 0) return fallback;
    return {
      users: parsed.users,
      sessions: parsed.sessions ?? SESSIONS,
      activity: parsed.activity ?? ACTIVITY,
      audit: parsed.audit ?? AUDIT,
    };
  } catch {
    return fallback;
  }
}

/* ---------------------------------------------------------------------------
   Provider
   --------------------------------------------------------------------------- */

export function DirectoryProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<DirectorySnapshot>(loadSnapshot);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot));
    } catch {
      // Storage being unavailable must never break the console.
    }
  }, [snapshot]);

  /** Every administrator write lands in both records, exactly as the server does. */
  const record = useCallback(
    (
      state: DirectorySnapshot,
      entry: { action: string; targetType: string; targetId: string; reason: string; before: string; after: string },
    ): DirectorySnapshot => {
      const at = now();
      const previous = state.audit[0];
      const chainIndex = (previous?.chainIndex ?? 200) + 1;
      const previousHash = previous?.eventHash ?? marker("genesis");
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
        previousHash,
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
      return { ...state, audit: [auditEvent, ...state.audit], activity: [activityEvent, ...state.activity] };
    },
    [],
  );

  const createUser = useCallback(
    (input: CreateUserInput) => {
      const role = ROLE_BY_SLUG.get(input.roleSlug);
      const created: AdminUser = {
        id: Math.max(0, ...snapshot.users.map((user) => user.id)) + 1,
        email: input.email.trim().toLowerCase(),
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

      setSnapshot((state) =>
        record({ ...state, users: [created, ...state.users] }, {
          action: "user.created",
          targetType: "Account",
          targetId: created.email,
          reason: `Account provisioned as ${role?.name ?? input.roleSlug}.`,
          before: "—",
          after: `${role?.name ?? input.roleSlug}${input.mustChangePassword ? ", password change required" : ""}`,
        }),
      );

      return created;
    },
    [record, snapshot.users],
  );

  const changeRole = useCallback(
    (userId: number, roleSlug: RoleSlug, reason: string) => {
      setSnapshot((state) => {
        const target = state.users.find((user) => user.id === userId);
        if (!target || target.roleSlug === roleSlug) return state;
        const previousRole = ROLE_BY_SLUG.get(target.roleSlug);
        const nextRole = ROLE_BY_SLUG.get(roleSlug);
        const kept = target.permissions.filter((permission) => permission.source !== "role");
        const fromRole: EffectivePermission[] = (nextRole?.permissions ?? [])
          .filter((key) => !kept.some((permission) => permission.key === key))
          .map((key) => ({ key, source: "role" as const, expiresAt: null, reason: "", grantedBy: "" }));

        const users = state.users.map((user) =>
          user.id === userId ? { ...user, roleSlug, permissions: [...fromRole, ...kept] } : user,
        );

        return record({ ...state, users }, {
          action: "user.role_changed",
          targetType: "Account",
          targetId: target.email,
          reason,
          before: previousRole?.name ?? target.roleSlug,
          after: nextRole?.name ?? roleSlug,
        });
      });
    },
    [record],
  );

  const setPassword = useCallback(
    ({ userId, reason, requireChange, revokeSessions }: SetPasswordInput) => {
      setSnapshot((state) => {
        const target = state.users.find((user) => user.id === userId);
        if (!target) return state;
        const users = state.users.map((user) =>
          user.id === userId ? { ...user, status: user.status === "locked_out" ? ("active" as const) : user.status } : user,
        );
        const sessions = revokeSessions ? state.sessions.filter((session) => session.userId !== userId) : state.sessions;
        return record({ ...state, users, sessions }, {
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
      });
    },
    [record],
  );

  const setStatus = useCallback(
    (userId: number, status: UserStatus, reason: string) => {
      setSnapshot((state) => {
        const target = state.users.find((user) => user.id === userId);
        if (!target) return state;
        const users = state.users.map((user) => (user.id === userId ? { ...user, status } : user));
        const sessions = status === "deactivated" ? state.sessions.filter((session) => session.userId !== userId) : state.sessions;
        return record({ ...state, users, sessions }, {
          action: status === "deactivated" ? "user.deactivated" : "user.reactivated",
          targetType: "Account",
          targetId: target.email,
          reason,
          before: target.status,
          after: status,
        });
      });
    },
    [record],
  );

  const resetAuthenticator = useCallback(
    (userId: number, reason: string) => {
      setSnapshot((state) => {
        const target = state.users.find((user) => user.id === userId);
        if (!target) return state;
        const users = state.users.map((user) => (user.id === userId ? { ...user, mfa: "unenrolled" as const } : user));
        return record({ ...state, users }, {
          action: "credential.authenticator_reset",
          targetType: "Account",
          targetId: target.email,
          reason,
          before: target.mfa,
          after: "unenrolled, must re-enrol at next sign-in",
        });
      });
    },
    [record],
  );

  const revokeSession = useCallback((sessionId: string) => {
    setSnapshot((state) => ({ ...state, sessions: state.sessions.filter((session) => session.id !== sessionId) }));
  }, []);

  const revokeUserSessions = useCallback(
    (userId: number) => {
      setSnapshot((state) => {
        const target = state.users.find((user) => user.id === userId);
        const sessions = state.sessions.filter((session) => session.userId !== userId);
        if (!target) return { ...state, sessions };
        return record({ ...state, sessions }, {
          action: "session.revoked_all",
          targetType: "Account",
          targetId: target.email,
          reason: "Signed out of every device.",
          before: `${state.sessions.length - sessions.length} active`,
          after: "0 active",
        });
      });
    },
    [record],
  );

  const revokeAllSessions = useCallback(() => {
    setSnapshot((state) =>
      record({ ...state, sessions: [] }, {
        action: "session.revoked_organization",
        targetType: "Organization",
        targetId: "netra",
        reason: "Every session across the organization was ended.",
        before: `${state.sessions.length} active`,
        after: "0 active",
      }),
    );
  }, [record]);

  const grantPermission = useCallback(
    (userId: number, key: PermissionKey, expiresAt: string | null, reason: string) => {
      setSnapshot((state) => {
        const target = state.users.find((user) => user.id === userId);
        if (!target) return state;
        const permissions: EffectivePermission[] = [
          ...target.permissions.filter((permission) => permission.key !== key),
          { key, source: "granted", expiresAt, reason, grantedBy: CURRENT_OPERATOR.name },
        ];
        const users = state.users.map((user) => (user.id === userId ? { ...user, permissions } : user));
        return record({ ...state, users }, {
          action: "permission.granted",
          targetType: "Account",
          targetId: target.email,
          reason,
          before: "—",
          after: `+${key}${expiresAt ? ` until ${new Date(expiresAt).toLocaleDateString("en-IN")}` : ""}`,
        });
      });
    },
    [record],
  );

  const removeGrant = useCallback(
    (userId: number, key: PermissionKey) => {
      setSnapshot((state) => {
        const target = state.users.find((user) => user.id === userId);
        if (!target) return state;
        const role = ROLE_BY_SLUG.get(target.roleSlug);
        const permissions = target.permissions.filter((permission) => permission.key !== key);
        if (role?.permissions.includes(key)) {
          permissions.push({ key, source: "role", expiresAt: null, reason: "", grantedBy: "" });
        }
        const users = state.users.map((user) => (user.id === userId ? { ...user, permissions } : user));
        return record({ ...state, users }, {
          action: "permission.grant_removed",
          targetType: "Account",
          targetId: target.email,
          reason: "Temporary permission withdrawn.",
          before: `+${key}`,
          after: role?.permissions.includes(key) ? `${key} from role` : "—",
        });
      });
    },
    [record],
  );

  const value = useMemo<DirectoryValue>(
    () => ({
      ...snapshot,
      createUser,
      changeRole,
      setPassword,
      setStatus,
      resetAuthenticator,
      revokeSession,
      revokeUserSessions,
      revokeAllSessions,
      grantPermission,
      removeGrant,
    }),
    [
      snapshot,
      createUser,
      changeRole,
      setPassword,
      setStatus,
      resetAuthenticator,
      revokeSession,
      revokeUserSessions,
      revokeAllSessions,
      grantPermission,
      removeGrant,
    ],
  );

  return <DirectoryContext.Provider value={value}>{children}</DirectoryContext.Provider>;
}

export function useDirectory() {
  const value = useContext(DirectoryContext);
  if (!value) throw new Error("useDirectory must be used inside DirectoryProvider");
  return value;
}
