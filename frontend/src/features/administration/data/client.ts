import { API_BASE_URL } from "../lib/env";
import { supabase } from "../lib/supabase";
import { ACTIVITY, AUDIT, CAPABILITIES, ORGANIZATION, PERMISSIONS, ROLES, SESSIONS, USERS } from "./mock";
import type {
  ActivityEvent,
  AdminUser,
  AuditEvent,
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
 * Passwords appear in exactly two shapes: the one that issues an account, and
 * the reveal call that reads a held one back. They travel nowhere else — not in
 * the directory snapshot, which only reports whether a credential is held. The
 * reveal endpoint records every call, because whoever reads a password can
 * afterwards sign in as that officer.
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
 * The last copy of what the server returned.
 *
 * Not a store — every operation posts and re-reads, so nothing is decided
 * here. It lets the tests inspect the last server snapshot without introducing
 * a second source of truth.
 *
 * It stays in memory for the lifetime of the tab and nowhere else. It used to
 * persist to localStorage, which put every officer's address, role and denial
 * count on what may be a shared machine, surviving sign-out — and undid the
 * memory-only session the console goes out of its way to keep.
 */
let state: DirectorySnapshot = seed();

/* ---------------------------------------------------------------------------
   The surface
   --------------------------------------------------------------------------- */

export type CreateUserInput = {
  name: string;
  email: string;
  department: string;
  roleSlug: RoleSlug;
  /** Optional. Absent means the server generates one. Either way its strength
   *  is checked server-side, because a rule enforced only in the browser holds
   *  until somebody posts to the endpoint directly. */
  password?: string;
  reason: string;
  /** "invite" sends a magic link and no credential. "password" generates one,
   *  shows it once, and mails it where the deployment has a mail host. Empty
   *  keeps whatever the deployment already does. */
  delivery?: "invite" | "password" | "";
};

export type SetPasswordInput = {
  userId: number;
  reason: string;
  password?: string;
};

/** The account shape the write endpoints return. Narrower than AdminUser: a
 *  write reports what it changed, and the full row comes from the re-read. */
type ServerAccount = {
  id: number;
  email: string;
  name: string;
  roleSlug: string;
  department: string;
  status: string;
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
  // Also a 401, and emphatically not a dead session — the operator is signed
  // in and permitted, they simply have not touched their authenticator
  // recently enough for a destructive action. Treating it as a dead session
  // would sign them out for asking to do their job.
  if (code === "step_up_required") return "Confirm this action with your authenticator.";
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
        ...(window.sessionStorage.getItem("netra-console-context-id")
          ? { "X-Netra-Context-ID": window.sessionStorage.getItem("netra-console-context-id")! }
          : {}),
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

/** The result of recomputing the audit chain server-side. */
export type ChainVerification = {
  verified: boolean;
  eventCount: number;
  rootHash: string;
  latestHash: string;
  /** Where the chain stops agreeing, or null when it is intact. An auditor
   *  needs to know how much of the record still stands, not just that
   *  something is wrong. */
  firstBrokenIndex: number | null;
  failures: number[];
  checkedAt: string;
};

/**
 * Ask the server to recompute the chain.
 *
 * This button used to raise a success toast unconditionally — it displayed a
 * verification it had never performed, which is worse than having no button at
 * all. The hashes it would need are computed and held server-side; the browser
 * cannot check them and must not appear to.
 */
export function verifyAuditChain(): Promise<ChainVerification> {
  return authorizedRequest<ChainVerification>("/admin/v1/audit/verify");
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

  /**
   * Create an account.
   *
   * The password travels to the server, is applied at the identity provider,
   * and comes back once so the dialog can show it for handover. It is not kept
   * anywhere on this side: not in the snapshot, not in the audit entry, and
   * not retrievable afterwards.
   */
  /** Read back a held password. POST, because the server records every call:
   *  whoever reads this can afterwards sign in as that officer. */
  async revealCredential(userId: number, reason: string) {
    const response = await authorizedRequest<{ password: string }>(`/admin/v1/users/${userId}/credential`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return response.password;
  },

  async createUser(input: CreateUserInput) {
    const response = await authorizedRequest<{
      user: ServerAccount;
      password: string;
      delivery: string;
      emailSent: boolean;
      emailFailure: string;
      mustChangePassword: boolean;
    }>("/admin/v1/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: input.email.trim().toLowerCase(),
        name: input.name.trim(),
        role: input.roleSlug,
        department: input.department.trim(),
        reason: input.reason,
        delivery: input.delivery,
      }),
    });

    // Re-read rather than patch the local copy. The server decides what the
    // directory now contains — joined dates, identity state, the audit entry
    // it just sealed — and guessing at that is how a console ends up showing
    // a row the database does not have.
    const snapshot = await this.read();
    const created = snapshot.users.find((row) => row.id === response.user.id) ?? snapshot.users[0];
    return {
      snapshot,
      created,
      password: response.password,
      delivery: response.delivery,
      emailSent: response.emailSent,
      emailFailure: response.emailFailure,
      mustChangePassword: response.mustChangePassword,
    };
  },

  async changeRole(userId: number, roleSlug: RoleSlug, reason: string) {
    await authorizedRequest(`/admin/v1/users/${userId}/role`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: roleSlug, reason }),
    });
    return this.read();
  },

  async setPassword({ userId, reason }: SetPasswordInput) {
    const response = await authorizedRequest<{ user: ServerAccount; password: string }>(
      `/admin/v1/users/${userId}/password`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason }),
      },
    );
    // Sessions always end with the password. A reset that leaves an existing
    // session signed in has locked nobody out, so the server does it
    // unconditionally rather than offering it as a choice.
    return { snapshot: await this.read(), password: response.password };
  },

  async setStatus(userId: number, status: UserStatus, reason: string) {
    await authorizedRequest(`/admin/v1/users/${userId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ active: status === "active", reason }),
    });
    return this.read();
  },

  async resetAuthenticator(userId: number, reason: string) {
    await authorizedRequest(`/admin/v1/users/${userId}/factors`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return this.read();
  },

  async revokeSession(sessionId: string, reason = "Session ended by an administrator.") {
    await authorizedRequest(`/admin/v1/sessions/${sessionId}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return this.read();
  },

  async revokeUserSessions(userId: number, reason = "Sessions ended by an administrator.") {
    await authorizedRequest(`/admin/v1/users/${userId}/sessions/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return this.read();
  },

  async revokeAllSessions(reason: string) {
    await authorizedRequest("/admin/v1/sessions/revoke-all", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return this.read();
  },

  async grantPermission(userId: number, key: PermissionKey, expiresAt: string | null, reason: string) {
    await authorizedRequest(`/admin/v1/users/${userId}/grants`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ permission: key, expiresAt, reason }),
    });
    return this.read();
  },

  async createRole(input: { name: string; description: string; baseSlug: string; reason: string }) {
    const { role } = await authorizedRequest<{ role: { slug: string; name: string } }>("/admin/v1/roles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });

    const snapshot = await this.read();
    const created = snapshot.roles.find((entry) => entry.slug === role.slug) ?? snapshot.roles[0];
    return { snapshot, created };
  },

  async setRolePermission(slug: string, key: PermissionKey, held: boolean, reason: string) {
    // Adding and removing are different verbs on the same resource, which is
    // how the server tells "grant this" from "take this away" — only the
    // first is checked against what the administrator themselves holds.
    await authorizedRequest(`/admin/v1/roles/${slug}/permissions/${key}`, {
      method: held ? "PUT" : "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason }),
    });
    return this.read();
  },

  async updateOrganization(
    changes: Partial<Pick<OrganizationSettings, "name" | "maxQueuedAnalyses">>,
    reason: string,
  ) {
    await authorizedRequest("/admin/v1/organization", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...changes, reason }),
    });
    return this.read();
  },

  async transferOwnership(targetUserId: number, reason: string) {
    await authorizedRequest("/admin/v1/organization/owner-transfer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targetUserId, reason }),
    });
    return this.read();
  },

  async removeGrant(userId: number, key: PermissionKey, reason: string) {
    await authorizedRequest(`/admin/v1/users/${userId}/grants`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ permission: key, reason }),
    });
    return this.read();
  },
};
