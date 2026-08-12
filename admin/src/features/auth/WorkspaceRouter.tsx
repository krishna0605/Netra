import { MemoryRouter } from "react-router-dom";
import { useEffect, type ReactNode } from "react";

/** The single neutral path the address bar shows for the whole workspace. */
export const WORKSPACE_PATH = "/workspace";

/**
 * Decision A — frozen URL.
 *
 * Every administrative screen lives at one address. Navigation is application
 * state, never a browser path, so no page-specific or administrative context
 * reaches browser history, screenshots, screen shares, copied links, proxy
 * logs or support conversations. The `/workspace` entry itself still appears;
 * what does not is which section was open, which account was being examined,
 * or which role was being edited.
 *
 * MemoryRouter keeps the router API intact — every existing Link, NavLink,
 * useNavigate and useParams behaves exactly as before, it simply never writes
 * to the address bar.
 *
 * This is privacy hardening, not an authorization control. Knowing that
 * /workspace exists must reveal nothing about what an account may reach; the
 * server re-checks role, organization scope and assurance level on every
 * request regardless of which screen asked.
 */
export function WorkspaceRouter({ children }: { children: ReactNode }) {
  useEffect(() => {
    const previous = window.location.pathname + window.location.search;
    if (window.location.pathname !== WORKSPACE_PATH) {
      window.history.replaceState(null, "", WORKSPACE_PATH);
    }
    return () => {
      // Leaving the workspace restores a neutral path so the address bar never
      // implies an administrative session is still open.
      window.history.replaceState(null, "", previous === WORKSPACE_PATH ? "/" : previous);
    };
  }, []);

  return <MemoryRouter initialEntries={["/"]}>{children}</MemoryRouter>;
}
