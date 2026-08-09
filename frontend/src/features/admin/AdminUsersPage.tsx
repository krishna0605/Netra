import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";

import { Alert, Badge, Button, Dialog, DialogContent, DialogTitle, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../../components/ui/primitives";
import { getCurrentAccessToken } from "../../lib/supabase";
import { useAuth } from "../auth/AuthContext";


type OrganizationUser = {
  id: number;
  email: string;
  name: string;
  role: "Admin" | "Investigator" | "Analyst" | "Viewer";
  active: boolean;
  organization: { id: string; name: string; slug: string };
  authState: string;
  invitationState: string;
  mfaState: string;
  lastSignInAt: string;
  lastActivityAt: string;
};

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";

function authHeaders(extra?: HeadersInit) {
  const headers = new Headers(extra);
  const token = getCurrentAccessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  headers.set("Accept", "application/json");
  return headers;
}

function errorMessage(payload: unknown, fallback: string) {
  if (!payload || typeof payload !== "object") return fallback;
  const error = (payload as Record<string, unknown>).error;
  if (typeof error === "string") return error;
  if (error && typeof error === "object" && typeof (error as Record<string, unknown>).message === "string") {
    return String((error as Record<string, unknown>).message);
  }
  return fallback;
}

function dateLabel(value: string) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Not recorded" : date.toLocaleString();
}

export default function AdminUsersPage() {
  const { state } = useAuth();
  const [users, setUsers] = useState<OrganizationUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [authMetadataStatus, setAuthMetadataStatus] = useState("");
  const [invite, setInvite] = useState({ email: "", name: "", role: "Viewer" });
  const [inviteBusy, setInviteBusy] = useState(false);
  const [transferOpen, setTransferOpen] = useState(false);
  const [targetId, setTargetId] = useState("");
  const [typedOrganization, setTypedOrganization] = useState("");
  const [reason, setReason] = useState("");

  const load = useCallback(async (signal?: AbortSignal) => {
    const response = await fetch(`${API_BASE}/users?limit=100`, { headers: authHeaders(), signal });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorMessage(payload, "User administration is unavailable."));
    setUsers(Array.isArray(payload.results) ? payload.results : []);
    setAuthMetadataStatus(typeof payload.authMetadataStatus === "string" ? payload.authMetadataStatus : "unknown");
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${API_BASE}/users?limit=100`, { headers: authHeaders(), signal: controller.signal })
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(errorMessage(payload, "User administration is unavailable."));
        if (!controller.signal.aborted) {
          setUsers(Array.isArray(payload.results) ? payload.results : []);
          setAuthMetadataStatus(typeof payload.authMetadataStatus === "string" ? payload.authMetadataStatus : "unknown");
        }
      })
      .catch((loadError) => {
        if (!controller.signal.aborted) setError(loadError instanceof Error ? loadError.message : "User administration is unavailable.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, []);

  if (state.status !== "privileged" || state.profile.role !== "Admin") {
    return <Navigate to="/auth/mfa" replace />;
  }
  const organization = state.profile.organization;
  const nonAdminTargets = users.filter((user) => user.active && user.role !== "Admin");

  async function inviteUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setInviteBusy(true);
    setError("");
    setStatus("");
    const response = await fetch(`${API_BASE}/users`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(invite),
    });
    const payload = await response.json().catch(() => ({}));
    setInviteBusy(false);
    if (!response.ok) {
      setError(errorMessage(payload, "The invitation could not be sent."));
      return;
    }
    setInvite({ email: "", name: "", role: "Viewer" });
    setStatus("Invitation accepted for delivery. The user must use the signed email link.");
    await load();
  }

  async function updateUser(user: OrganizationUser, changes: { role?: string; active?: boolean }) {
    setError("");
    const response = await fetch(`${API_BASE}/users/${user.id}`, {
      method: "PATCH",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(changes),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      setError(errorMessage(payload, "The user could not be updated."));
      return;
    }
    setStatus(`${user.email} was updated.`);
    await load();
  }

  async function transferAdministrator(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (typedOrganization.trim() !== organization.name || reason.trim().length < 10) {
      setError("Type the exact organization name and provide a reason of at least 10 characters.");
      return;
    }
    const response = await fetch(`${API_BASE}/admin/organizations/${organization.id}/admin-transfer`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ targetUserId: Number(targetId), reason: reason.trim() }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      setError(errorMessage(payload, "Administrator transfer failed."));
      return;
    }
    setTransferOpen(false);
    setStatus("Administrator responsibility was transferred. Your role is now Investigator.");
    window.location.assign("/app");
  }

  return (
    <main className="min-w-0 p-4 sm:p-6" id="main-content">
      <div className="mx-auto grid max-w-7xl gap-6">
        <header>
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">NETRA / AAL2 administration</p>
          <h1 className="mt-2 text-3xl font-black text-strong">Organization users</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-muted">Invite and manage non-Administrator profiles in {organization.name}. Roles are enforced by Netra, never by editable identity metadata.</p>
        </header>
        {error ? <p className="rounded-xl border border-red-400/40 bg-red-950/20 p-4 text-sm text-red-200" role="alert">{error}</p> : null}
        {status ? <p className="rounded-xl border border-emerald-400/30 bg-emerald-950/20 p-4 text-sm text-emerald-100" role="status" aria-live="polite">{status}</p> : null}
        {authMetadataStatus === "degraded" ? <Alert>Supabase Auth metadata is temporarily unavailable. Local role and activation controls remain authoritative.</Alert> : null}

        <section className="surface rounded-[1.5rem] p-5" aria-labelledby="invite-heading">
          <h2 id="invite-heading" className="text-xl font-black text-strong">Invite a user</h2>
          <p className="mt-1 text-sm text-muted">Netra sends a signed invitation. No temporary password is generated or displayed.</p>
          <form className="mt-4 grid gap-3 md:grid-cols-4" onSubmit={inviteUser}>
            <div className="grid gap-1"><label htmlFor="invite-name" className="text-sm font-semibold">Name</label><Input id="invite-name" value={invite.name} onChange={(event) => setInvite((current) => ({ ...current, name: event.target.value }))} required /></div>
            <div className="grid gap-1"><label htmlFor="invite-email" className="text-sm font-semibold">Email</label><Input id="invite-email" type="email" autoComplete="email" value={invite.email} onChange={(event) => setInvite((current) => ({ ...current, email: event.target.value }))} required /></div>
            <div className="grid gap-1"><label htmlFor="invite-role" className="text-sm font-semibold">Role</label><Select value={invite.role} onValueChange={(role) => setInvite((current) => ({ ...current, role }))}><SelectTrigger id="invite-role"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="Investigator">Investigator</SelectItem><SelectItem value="Analyst">Analyst</SelectItem><SelectItem value="Viewer">Viewer</SelectItem></SelectContent></Select></div>
            <Button className="self-end" type="submit" disabled={inviteBusy}>{inviteBusy ? "Sending…" : "Send invitation"}</Button>
          </form>
        </section>

        <section className="surface overflow-hidden rounded-[1.5rem]" aria-labelledby="users-heading">
          <div className="flex flex-wrap items-center justify-between gap-3 p-5">
            <div><h2 id="users-heading" className="text-xl font-black text-strong">Provisioned users</h2><p className="mt-1 text-sm text-muted">Authentication metadata is read only when this page is opened.</p></div>
            <Button type="button" variant="secondary" onClick={() => setTransferOpen(true)} disabled={!nonAdminTargets.length}>Transfer Administrator</Button>
          </div>
          <div
            aria-label="Organization users table"
            className="overflow-x-auto p-4 pt-0"
            role="region"
            tabIndex={0}
          >
            <table className="w-full min-w-[980px] text-left text-sm">
              <caption className="sr-only">Organization users, roles, authentication status, MFA status, and recent activity</caption>
              <thead className="border-b border-[var(--border)] text-xs uppercase text-muted"><tr><th scope="col" className="py-3">User</th><th scope="col">Role</th><th scope="col">Account</th><th scope="col">Invitation</th><th scope="col">MFA</th><th scope="col">Last sign in</th><th scope="col">Last activity</th><th scope="col">Actions</th></tr></thead>
              <tbody>{loading ? <tr><td colSpan={8} className="py-8 text-center text-muted">Loading organization users…</td></tr> : users.map((user) => (
                <tr key={user.id} className="border-b border-[var(--border)] align-top">
                  <th scope="row" className="py-4 pr-4 text-left font-normal"><strong className="block text-strong">{user.name}</strong><span className="text-xs text-muted">{user.email}</span></th>
                  <td className="pr-4">{user.role === "Admin" ? <Badge>Admin</Badge> : <Select value={user.role} onValueChange={(role) => void updateUser(user, { role })}><SelectTrigger aria-label={`Role for ${user.email}`} className="min-w-36"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="Investigator">Investigator</SelectItem><SelectItem value="Analyst">Analyst</SelectItem><SelectItem value="Viewer">Viewer</SelectItem></SelectContent></Select>}</td>
                  <td><Badge variant={user.active ? "secondary" : "warning"}>{user.active ? user.authState : "inactive"}</Badge></td>
                  <td>{user.invitationState}</td><td>{user.mfaState}</td><td>{dateLabel(user.lastSignInAt)}</td><td>{dateLabel(user.lastActivityAt)}</td>
                  <td>{user.role === "Admin" ? <span className="text-xs text-muted">Use transfer</span> : <Button size="sm" variant="secondary" onClick={() => void updateUser(user, { active: !user.active })}>{user.active ? "Deactivate" : "Activate"}</Button>}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      </div>

      <Dialog open={transferOpen} onOpenChange={setTransferOpen}>
        <DialogContent>
          <DialogTitle>Transfer Administrator responsibility</DialogTitle>
          <form className="mt-4 grid gap-4" onSubmit={transferAdministrator}>
            <Alert>This atomic operation demotes your profile to Investigator and promotes one active same-organization user.</Alert>
            <div className="grid gap-1"><label htmlFor="transfer-target" className="text-sm font-semibold">New Administrator</label><Select value={targetId} onValueChange={setTargetId}><SelectTrigger id="transfer-target"><SelectValue placeholder="Select an active user" /></SelectTrigger><SelectContent>{nonAdminTargets.map((user) => <SelectItem key={user.id} value={String(user.id)}>{user.name} — {user.email}</SelectItem>)}</SelectContent></Select></div>
            <div className="grid gap-1"><label htmlFor="transfer-organization" className="text-sm font-semibold">Type “{organization.name}” to confirm</label><Input id="transfer-organization" value={typedOrganization} onChange={(event) => setTypedOrganization(event.target.value)} autoComplete="off" /></div>
            <div className="grid gap-1"><label htmlFor="transfer-reason" className="text-sm font-semibold">Approved reason</label><Input id="transfer-reason" value={reason} onChange={(event) => setReason(event.target.value)} minLength={10} maxLength={1000} /></div>
            <Button type="submit" disabled={!targetId || typedOrganization.trim() !== organization.name || reason.trim().length < 10}>Transfer Administrator</Button>
          </form>
        </DialogContent>
      </Dialog>
    </main>
  );
}
