import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import { ApiFailure, directoryApi, type CreateUserInput, type DirectorySnapshot, type SetPasswordInput } from "./client";
import { CAPABILITIES, ORGANIZATION, PERMISSIONS, ROLES } from "./mock";
import type { AdminUser, OrganizationSettings, PermissionKey, Role, RoleSlug, UserStatus } from "./types";

/**
 * React state over the transport boundary.
 *
 * Holds no data logic of its own — that lives in client.ts. Its job is the
 * three things a screen needs to render honestly: what the data is, whether
 * it is still arriving, and whether it failed.
 */

const EMPTY: DirectorySnapshot = {
  users: [],
  sessions: [],
  activity: [],
  audit: [],
  roles: ROLES,
  organization: ORGANIZATION,
  permissions: PERMISSIONS,
  capabilities: CAPABILITIES,
};

type DirectoryValue = DirectorySnapshot & {
  loading: boolean;
  error: string;
  refetch: () => Promise<void>;

  createUser: (input: CreateUserInput) => Promise<AdminUser>;
  changeRole: (userId: number, roleSlug: RoleSlug, reason: string) => Promise<void>;
  setPassword: (input: SetPasswordInput) => Promise<void>;
  setStatus: (userId: number, status: UserStatus, reason: string) => Promise<void>;
  resetAuthenticator: (userId: number, reason: string) => Promise<void>;
  revokeSession: (sessionId: string) => Promise<void>;
  revokeUserSessions: (userId: number) => Promise<void>;
  revokeAllSessions: () => Promise<void>;
  grantPermission: (userId: number, key: PermissionKey, expiresAt: string | null, reason: string) => Promise<void>;
  removeGrant: (userId: number, key: PermissionKey) => Promise<void>;
  createRole: (input: { name: string; description: string; baseSlug: string }) => Promise<Role>;
  setRolePermission: (slug: string, key: PermissionKey, held: boolean) => Promise<void>;
  updateOrganization: (
    changes: Partial<Pick<OrganizationSettings, "name" | "maxQueuedAnalyses" | "accessLogRetentionDays">>,
  ) => Promise<void>;
  transferOwnership: (targetUserId: number, reason: string) => Promise<void>;
};

const DirectoryContext = createContext<DirectoryValue | null>(null);

function messageFor(cause: unknown, fallback: string) {
  if (cause instanceof ApiFailure) return cause.message;
  return fallback;
}

export function DirectoryProvider({ children }: { children: ReactNode }) {
  const [snapshot, setSnapshot] = useState<DirectorySnapshot>(EMPTY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refetch = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setSnapshot(await directoryApi.read());
    } catch (cause) {
      setError(messageFor(cause, "The directory could not be loaded."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refetch();
  }, [refetch]);

  /**
   * Mutations reject rather than swallowing failure, so the caller can keep a
   * dialog open with the operator's typed reason intact instead of closing it
   * over a write that never landed.
   */
  const run = useCallback(async <T,>(operation: () => Promise<T>): Promise<T> => {
    try {
      return await operation();
    } catch (cause) {
      throw new ApiFailure(
        cause instanceof ApiFailure ? cause.code : "request_failed",
        messageFor(cause, "That change could not be saved."),
        cause instanceof ApiFailure ? cause.status : 500,
      );
    }
  }, []);

  const createUser = useCallback(
    async (input: CreateUserInput) => {
      const { snapshot: next, created } = await run(() => directoryApi.createUser(input));
      setSnapshot(next);
      return created;
    },
    [run],
  );

  const changeRole = useCallback(
    async (userId: number, roleSlug: RoleSlug, reason: string) => {
      setSnapshot(await run(() => directoryApi.changeRole(userId, roleSlug, reason)));
    },
    [run],
  );

  const setPassword = useCallback(
    async (input: SetPasswordInput) => {
      setSnapshot(await run(() => directoryApi.setPassword(input)));
    },
    [run],
  );

  const setStatus = useCallback(
    async (userId: number, status: UserStatus, reason: string) => {
      setSnapshot(await run(() => directoryApi.setStatus(userId, status, reason)));
    },
    [run],
  );

  const resetAuthenticator = useCallback(
    async (userId: number, reason: string) => {
      setSnapshot(await run(() => directoryApi.resetAuthenticator(userId, reason)));
    },
    [run],
  );

  const revokeSession = useCallback(
    async (sessionId: string) => {
      setSnapshot(await run(() => directoryApi.revokeSession(sessionId)));
    },
    [run],
  );

  const revokeUserSessions = useCallback(
    async (userId: number) => {
      setSnapshot(await run(() => directoryApi.revokeUserSessions(userId)));
    },
    [run],
  );

  const revokeAllSessions = useCallback(async () => {
    setSnapshot(await run(() => directoryApi.revokeAllSessions()));
  }, [run]);

  const grantPermission = useCallback(
    async (userId: number, key: PermissionKey, expiresAt: string | null, reason: string) => {
      setSnapshot(await run(() => directoryApi.grantPermission(userId, key, expiresAt, reason)));
    },
    [run],
  );

  const removeGrant = useCallback(
    async (userId: number, key: PermissionKey) => {
      setSnapshot(await run(() => directoryApi.removeGrant(userId, key)));
    },
    [run],
  );

  const createRole = useCallback(
    async (input: { name: string; description: string; baseSlug: string }) => {
      const { snapshot: next, created } = await run(() => directoryApi.createRole(input));
      setSnapshot(next);
      return created;
    },
    [run],
  );

  const setRolePermission = useCallback(
    async (slug: string, key: PermissionKey, held: boolean) => {
      setSnapshot(await run(() => directoryApi.setRolePermission(slug, key, held)));
    },
    [run],
  );

  const updateOrganization = useCallback(
    async (changes: Partial<Pick<OrganizationSettings, "name" | "maxQueuedAnalyses" | "accessLogRetentionDays">>) => {
      setSnapshot(await run(() => directoryApi.updateOrganization(changes)));
    },
    [run],
  );

  const transferOwnership = useCallback(
    async (targetUserId: number, reason: string) => {
      setSnapshot(await run(() => directoryApi.transferOwnership(targetUserId, reason)));
    },
    [run],
  );

  const value = useMemo<DirectoryValue>(
    () => ({
      ...snapshot,
      loading,
      error,
      refetch,
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
      createRole,
      setRolePermission,
      updateOrganization,
      transferOwnership,
    }),
    [
      snapshot,
      loading,
      error,
      refetch,
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
      createRole,
      setRolePermission,
      updateOrganization,
      transferOwnership,
    ],
  );

  return <DirectoryContext.Provider value={value}>{children}</DirectoryContext.Provider>;
}

export function useDirectory() {
  const value = useContext(DirectoryContext);
  if (!value) throw new Error("useDirectory must be used inside DirectoryProvider");
  return value;
}

/* ---------------------------------------------------------------------------
   Password helpers — kept here because they are used by two dialogs and by
   tests, and they belong to no single screen.
   --------------------------------------------------------------------------- */

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
