const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";
const STORAGE_KEY = "netra-console-context-id";
const WORKSPACE_KEY = "netra-last-workspace";

export type ConsoleContextState = {
  contextId: string;
  activeWorkspace: "investigation" | "administration";
  allowedWorkspaces: Array<"investigation" | "administration">;
  assuranceLevel: "aal2";
  expiresAt: string;
  lastSeenAt: string;
};

export function getConsoleContextId() {
  return typeof window === "undefined" ? "" : window.sessionStorage.getItem(STORAGE_KEY) ?? "";
}

export function clearConsoleContext() {
  if (typeof window !== "undefined") window.sessionStorage.removeItem(STORAGE_KEY);
}

export function getLastConsoleWorkspace(): "investigation" | "administration" | null {
  if (typeof window === "undefined") return null;
  const value = window.sessionStorage.getItem(WORKSPACE_KEY);
  return value === "investigation" || value === "administration" ? value : null;
}

export function rememberConsoleWorkspace(workspace: "investigation" | "administration") {
  if (typeof window !== "undefined") window.sessionStorage.setItem(WORKSPACE_KEY, workspace);
}

export function clearLastConsoleWorkspace() {
  if (typeof window !== "undefined") window.sessionStorage.removeItem(WORKSPACE_KEY);
}

async function contextRequest(accessToken: string, method: string, body?: object) {
  const contextId = getConsoleContextId();
  const response = await fetch(`${API_BASE}/auth/context`, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      ...(contextId ? { "X-Netra-Context-ID": contextId } : {}),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof payload.code === "string" ? payload.code : "console_context_failed");
  const context = payload.context as ConsoleContextState | undefined;
  if (context?.contextId) window.sessionStorage.setItem(STORAGE_KEY, context.contextId);
  return context;
}

export async function createConsoleContext(accessToken: string) {
  clearConsoleContext();
  return contextRequest(accessToken, "POST");
}

export async function switchConsoleWorkspace(accessToken: string, workspace: "investigation" | "administration") {
  return contextRequest(accessToken, "PATCH", { workspace });
}

export async function revokeConsoleContext(accessToken: string) {
  if (!getConsoleContextId()) return;
  try {
    await contextRequest(accessToken, "DELETE");
  } finally {
    clearConsoleContext();
  }
}
