import { ArrowLeft, KeyRound, LogOut, RotateCcw, ShieldOff, UserMinus, X } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { useState } from "react";

import { PERMISSION_BY_KEY } from "../data/mock";
import { useDirectory } from "../data/store";
import { ErrorState, SkeletonList } from "../components/states";
import {
  Avatar,
  Button,
  EmptyState,
  Field,
  NativeSelect,
  Panel,
  PanelHeader,
  Status,
  Table,
  TableWrap,
  Tag,
  Td,
  Th,
} from "../components/ui/primitives";
import { MfaBadge, PageBody, PageHeader, ResultBadge, RoleBadge, UserStatusBadge } from "../components/common";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { GrantPermissionDialog } from "../components/GrantPermissionDialog";
import { PasswordDialog } from "../components/PasswordDialog";
import { dateTimeLabel, initials, relativeLabel, timeLabel } from "../lib/utils";
import type { PermissionSource } from "../data/types";

const SOURCE: Record<PermissionSource, { label: string; tone: "neutral" | "accent" | "crit" }> = {
  role: { label: "From role", tone: "neutral" },
  granted: { label: "Granted", tone: "accent" },
  revoked: { label: "Revoked", tone: "crit" },
};

export function UserDetailPage() {
  const { userId } = useParams();
  const {
    users,
    activity,
    sessions,
    changeRole,
    setStatus,
    resetAuthenticator,
    revokeSession,
    revokeUserSessions,
    removeGrant,
    roles,
    loading,
    error,
    refetch,
  } = useDirectory();
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [grantOpen, setGrantOpen] = useState(false);
  const [confirming, setConfirming] = useState<"authenticator" | "deactivate" | null>(null);

  const user = users.find((entry) => String(entry.id) === userId);

  if (loading) {
    return (
      <>
        <PageHeader title="Loading" summary="Fetching this account." />
        <PageBody>
          <Panel>
            <SkeletonList rows={6} />
          </Panel>
        </PageBody>
      </>
    );
  }

  if (error) {
    return (
      <>
        <PageHeader title="Could not load" summary="This account could not be fetched." />
        <PageBody>
          <Panel>
            <ErrorState detail={error} onRetry={() => void refetch()} />
          </Panel>
        </PageBody>
      </>
    );
  }

  if (!user) {
    return (
      <>
        <PageHeader title="User not found" summary="No account with that identifier exists in this organization." />
        <PageBody>
          <Button asChild variant="outline" className="self-start">
            <Link to="/users">Back to users</Link>
          </Button>
        </PageBody>
      </>
    );
  }

  const role = roles.find((entry) => entry.slug === user.roleSlug);
  const userActivity = activity.filter((event) => event.actorEmail === user.email);
  const userSessions = sessions.filter((session) => session.userId === user.id);
  const deniedCount = userActivity.filter((event) => event.result === "denied").length;

  async function onRoleChange(nextSlug: string) {
    if (!user || nextSlug === user.roleSlug) return;
    const nextName = roles.find((entry) => entry.slug === nextSlug)?.name ?? nextSlug;
    try {
      await changeRole(user.id, nextSlug, `Role changed to ${nextName} by an administrator.`);
      toast.success("Role updated", { description: `${user.name} is now ${nextName}.` });
    } catch (cause) {
      toast.error("Role not changed", {
        description: cause instanceof Error ? cause.message : "The change was not saved.",
      });
    }
  }

  /** Mutations report their own failure; nothing is assumed to have worked. */
  function apply(operation: Promise<void>, success: string, detail: string) {
    void operation
      .then(() => toast.success(success, { description: detail }))
      .catch((cause: unknown) =>
        toast.error("Could not complete", {
          description: cause instanceof Error ? cause.message : "Try again.",
        }),
      );
  }

  return (
    <>
      <header className="border-b border-hairline px-5 pt-6 pb-6 md:px-8 md:pt-8">
        <Button asChild variant="ghost" size="sm" className="mb-5 -ml-3">
          <Link to="/users">
            <ArrowLeft className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            All users
          </Link>
        </Button>

        <div className="flex flex-wrap items-start gap-5">
          <Avatar initials={initials(user.name)} tone={user.isOwner ? "accent" : "neutral"} className="size-14 rounded-panel text-lg" />
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-semibold text-cream-bright md:text-[28px]">{user.name}</h1>
            <p className="mt-1.5 font-mono text-[13px] text-sand-muted/85">{user.email}</p>
            <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2">
              <RoleBadge name={role?.name ?? user.roleSlug} isOwner={user.isOwner} />
              <UserStatusBadge status={user.status} />
              <MfaBadge state={user.mfa} />
              {deniedCount > 0 ? <Status tone="crit">{deniedCount} denied in 24h</Status> : null}
            </div>
          </div>
        </div>
      </header>

      <PageBody className="lg:grid lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:items-start lg:gap-6">
        <div className="flex flex-col gap-6">
          <Panel>
            <PanelHeader title="Identity" />
            <dl className="px-5 py-3">
              <Field label="Department" mono={false}>
                {user.department}
              </Field>
              <Field label="Account id">{user.id}</Field>
              <Field label="Directory id">{user.supabaseId || "Not provisioned"}</Field>
              <Field label="Joined">{dateTimeLabel(user.joinedAt)}</Field>
              <Field label="Last sign-in">{user.lastSignInAt ? dateTimeLabel(user.lastSignInAt) : "Never"}</Field>
            </dl>
          </Panel>

          <Panel>
            <PanelHeader
              title="Role & permissions"
              hint={role?.description}
              action={
                <div className="flex items-center gap-2">
                  {user.isOwner ? (
                    <Tag tone="accent">Owner — transfer to change</Tag>
                  ) : (
                    <NativeSelect
                      value={user.roleSlug}
                      onChange={(event) => void onRoleChange(event.target.value)}
                      aria-label="Change role"
                    >
                      {roles
                        .filter((entry) => entry.slug !== "admin")
                        .map((entry) => (
                          <option key={entry.slug} value={entry.slug}>
                            {entry.name}
                          </option>
                        ))}
                    </NativeSelect>
                  )}
                  <Button variant="outline" size="sm" onClick={() => setGrantOpen(true)}>
                    Grant
                  </Button>
                </div>
              }
            />
            {user.permissions.length === 0 ? (
              <EmptyState title="No effective permissions" hint="This account is deactivated, so nothing resolves." />
            ) : (
              <TableWrap>
                <Table className="min-w-[26rem]">
                  <thead>
                    <tr>
                      <Th>Permission</Th>
                      <Th>Source</Th>
                      <Th>Expires</Th>
                      <Th className="w-10" />
                    </tr>
                  </thead>
                  <tbody>
                    {user.permissions.map((permission) => (
                      <tr key={permission.key} className="transition-colors hover:bg-cream-primary/3">
                        <Td>
                          <span className="font-mono text-[13px] text-cream-primary">{permission.key}</span>
                          <span className="mt-0.5 block max-w-md text-xs text-sand-muted/70">
                            {permission.reason || PERMISSION_BY_KEY.get(permission.key)?.description}
                          </span>
                        </Td>
                        <Td>
                          <Tag tone={SOURCE[permission.source].tone}>{SOURCE[permission.source].label}</Tag>
                        </Td>
                        <Td className="text-[13px] whitespace-nowrap text-sand-muted">
                          {permission.expiresAt ? dateTimeLabel(permission.expiresAt) : "—"}
                        </Td>
                        <Td>
                          {permission.source === "granted" ? (
                            <button
                              type="button"
                              onClick={() =>
                                apply(
                                  removeGrant(user.id, permission.key),
                                  "Grant withdrawn",
                                  `${permission.key} removed from ${user.name}.`,
                                )
                              }
                              className="grid size-6 place-items-center rounded-control text-sand-muted/50 hover:text-state-crit"
                              aria-label={`Withdraw ${permission.key}`}
                            >
                              <X className="size-3.5" strokeWidth={2} aria-hidden="true" />
                            </button>
                          ) : null}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </Panel>

          <Panel>
            <PanelHeader title="Active sessions" hint={userSessions.length === 1 ? "1 open" : `${userSessions.length} open`} />
            {userSessions.length === 0 ? (
              <EmptyState title="No active sessions" />
            ) : (
              <TableWrap>
                <Table className="min-w-[26rem]">
                  <thead>
                    <tr>
                      <Th>Started</Th>
                      <Th>Origin</Th>
                      <Th>Assurance</Th>
                      <Th className="text-right">Action</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {userSessions.map((session) => (
                      <tr key={session.id} className="transition-colors hover:bg-cream-primary/3">
                        <Td className="text-[13px] whitespace-nowrap text-sand-muted">{relativeLabel(session.startedAt)}</Td>
                        <Td className="font-mono text-[13px] text-cream-primary">{session.origin}</Td>
                        <Td>
                          <Status tone={session.aal === "aal2" ? "ok" : "warn"}>
                            {session.aal === "aal2" ? "Two factor" : "Single factor"}
                          </Status>
                        </Td>
                        <Td className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              apply(
                                revokeSession(session.id),
                                "Session ended",
                                `${user.name} signed out of ${session.origin}.`,
                              )
                            }
                          >
                            Revoke
                          </Button>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </Panel>
        </div>

        <div className="mt-6 flex flex-col gap-6 lg:mt-0">
          <Panel>
            <PanelHeader
              title="Activity"
              action={
                <Button asChild variant="ghost" size="sm">
                  <Link to="/activity">View all</Link>
                </Button>
              }
            />
            {userActivity.length === 0 ? (
              <EmptyState title="Nothing recorded yet" hint="This account has not signed in." />
            ) : (
              <ul className="divide-y divide-[color:var(--color-hairline)]">
                {userActivity.slice(0, 12).map((event) => (
                  <li key={event.id} className="flex items-baseline gap-4 px-5 py-3">
                    <time className="shrink-0 font-mono text-xs text-sand-muted/60">{timeLabel(event.at)}</time>
                    <div className="min-w-0 flex-1">
                      <p className={`truncate font-mono text-[13px] ${event.result === "denied" ? "text-state-crit" : "text-cream-primary"}`}>
                        {event.action}
                      </p>
                      <p className="mt-0.5 truncate text-xs text-sand-muted/70">{event.target}</p>
                    </div>
                    <ResultBadge result={event.result} />
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel>
            <PanelHeader title="Case memberships" hint={`${user.caseMemberships.length} assigned`} />
            {user.caseMemberships.length === 0 ? (
              <EmptyState title="Not a member of any case" />
            ) : (
              <ul className="divide-y divide-[color:var(--color-hairline)]">
                {user.caseMemberships.map((membership) => (
                  <li key={membership.caseId} className="flex items-baseline gap-4 px-5 py-3">
                    <span className="shrink-0 font-mono text-xs text-signal">{membership.caseId}</span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-[13px] text-cream-primary">{membership.caseTitle}</p>
                      <p className="mt-0.5 text-xs text-sand-muted/70">
                        {membership.role} · added {relativeLabel(membership.addedAt)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel className="border-state-crit/45">
            <PanelHeader
              title="Credential & account actions"
              className="border-state-crit/25"
              hint="Each requires a fresh authenticator code and a written reason"
            />
            <div className="flex flex-wrap gap-2 px-5 py-4">
              <Button variant="outline" size="sm" onClick={() => setPasswordOpen(true)}>
                <KeyRound className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Set password
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={user.mfa === "unenrolled"}
                onClick={() => setConfirming("authenticator")}
              >
                <ShieldOff className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Reset authenticator
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={userSessions.length === 0}
                onClick={() =>
                  apply(revokeUserSessions(user.id), "All sessions ended", `${user.name} was signed out everywhere.`)
                }
              >
                <LogOut className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Revoke all sessions
              </Button>
              {user.status === "deactivated" ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    apply(
                      setStatus(user.id, "active", "Account restored by an administrator."),
                      "Account reactivated",
                      `${user.name} can sign in again.`,
                    )
                  }
                >
                  <RotateCcw className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  Reactivate
                </Button>
              ) : (
                <Button
                  variant="danger"
                  size="sm"
                  disabled={user.isOwner}
                  onClick={() => setConfirming("deactivate")}
                >
                  <UserMinus className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  Deactivate
                </Button>
              )}
            </div>
            {user.isOwner ? (
              <p className="border-t border-hairline px-5 py-3 text-xs text-sand-muted/70">
                The owner cannot be deactivated. Transfer ownership first.
              </p>
            ) : null}
          </Panel>
        </div>
      </PageBody>

      <PasswordDialog user={user} open={passwordOpen} onOpenChange={setPasswordOpen} />
      <GrantPermissionDialog user={user} open={grantOpen} onOpenChange={setGrantOpen} />

      <ConfirmDialog
        open={confirming === "authenticator"}
        onOpenChange={(next) => setConfirming(next ? "authenticator" : null)}
        title="Reset authenticator"
        subject={`${user.name} · ${user.email}`}
        consequences={[
          "Their enrolled authenticator is removed and cannot be restored.",
          "Until they enrol a new one, their account is protected by password alone.",
          "Verify their identity through a channel you trust before continuing — this request is a common target for impersonation.",
        ]}
        confirmLabel="Reset authenticator"
        onConfirm={(reason) => resetAuthenticator(user.id, reason)}
      />

      <ConfirmDialog
        open={confirming === "deactivate"}
        onOpenChange={(next) => setConfirming(next ? "deactivate" : null)}
        title="Deactivate account"
        subject={`${user.name} · ${user.email}`}
        consequences={[
          "They are signed out of every device immediately, mid-task.",
          "They will not be able to sign in until reactivated.",
          "Their history, case memberships and audit entries are kept — nothing is deleted.",
        ]}
        confirmLabel="Deactivate"
        onConfirm={(reason) => setStatus(user.id, "deactivated", reason)}
      />
    </>
  );
}
