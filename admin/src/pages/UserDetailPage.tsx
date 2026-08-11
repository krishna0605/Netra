import { ArrowLeft, KeyRound, LogOut, ShieldOff, UserMinus } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { toast } from "sonner";
import { useState } from "react";

import { ACTIVITY, PERMISSION_BY_KEY, ROLE_BY_SLUG, SESSIONS, USERS } from "../data/mock";
import { Badge, Button, EmptyState, Field, Panel, PanelHeader, Table, TableWrap, Td, Th } from "../components/ui/primitives";
import { MfaBadge, PageBody, PageHeader, RoleBadge, ResultBadge, UserStatusBadge } from "../components/common";
import { RecoveryDialog } from "../components/RecoveryDialog";
import { dateTimeLabel, relativeLabel, timeLabel } from "../lib/utils";
import type { PermissionSource } from "../data/types";

const SOURCE_TONE: Record<PermissionSource, "neutral" | "accent" | "crit"> = {
  role: "neutral",
  granted: "accent",
  revoked: "crit",
};

const SOURCE_LABEL: Record<PermissionSource, string> = {
  role: "From role",
  granted: "Granted",
  revoked: "Revoked",
};

export function UserDetailPage() {
  const { userId } = useParams();
  const [recoveryOpen, setRecoveryOpen] = useState(false);
  const user = USERS.find((entry) => String(entry.id) === userId);

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

  const role = ROLE_BY_SLUG.get(user.roleSlug);
  const userActivity = ACTIVITY.filter((event) => event.actorEmail === user.email);
  const userSessions = SESSIONS.filter((session) => session.userId === user.id);
  const deniedCount = userActivity.filter((event) => event.result === "denied").length;

  return (
    <>
      <PageHeader
        back={
          <Button asChild variant="ghost" size="sm">
            <Link to="/users">
              <ArrowLeft className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
              All users
            </Link>
          </Button>
        }
        title={
          <>
            {user.name}
            <RoleBadge name={role?.name ?? user.roleSlug} isOwner={user.isOwner} />
            <UserStatusBadge status={user.status} />
            {user.mfa !== "verified" ? <MfaBadge state={user.mfa} /> : null}
          </>
        }
        summary={`${user.email} · django id ${user.id} · joined ${dateTimeLabel(user.joinedAt)}`}
      />

      <PageBody className="lg:grid lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:items-start lg:gap-5">
        <div className="flex flex-col gap-5">
          <Panel>
            <PanelHeader title="Identity" />
            <dl className="px-4 py-2">
              <Field label="Display name">{user.name}</Field>
              <Field label="Department">{user.department}</Field>
              <Field label="Supabase id">{user.supabaseId || "not provisioned"}</Field>
              <Field label="Last sign-in">{user.lastSignInAt ? dateTimeLabel(user.lastSignInAt) : "Never"}</Field>
              <Field label="Invitation">{user.invitationState}</Field>
              <Field label="Auth metadata">
                <Badge tone="ok">live</Badge>
              </Field>
            </dl>
          </Panel>

          <Panel>
            <PanelHeader
              title="Role & permissions"
              hint={role?.description}
              action={
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => toast("Grant permission", { description: "Per-user grants land in phase 3 alongside the permission resolver." })}
                >
                  + Grant
                </Button>
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
                    </tr>
                  </thead>
                  <tbody>
                    {user.permissions.map((permission) => (
                      <tr key={permission.key}>
                        <Td>
                          <span className="font-mono text-xs text-cream-primary">{permission.key}</span>
                          {permission.reason ? (
                            <span className="mt-0.5 block max-w-md text-[11px] text-sand-muted/70">{permission.reason}</span>
                          ) : (
                            <span className="mt-0.5 block text-[11px] text-sand-muted/60">
                              {PERMISSION_BY_KEY.get(permission.key)?.description}
                            </span>
                          )}
                        </Td>
                        <Td>
                          <Badge tone={SOURCE_TONE[permission.source]}>{SOURCE_LABEL[permission.source]}</Badge>
                        </Td>
                        <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">
                          {permission.expiresAt ? dateTimeLabel(permission.expiresAt) : "—"}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </Panel>

          <Panel>
            <PanelHeader title="Active sessions" hint={`${userSessions.length} open`} />
            {userSessions.length === 0 ? (
              <EmptyState title="No active sessions" />
            ) : (
              <TableWrap>
                <Table className="min-w-[26rem]">
                  <thead>
                    <tr>
                      <Th>Started</Th>
                      <Th>Origin</Th>
                      <Th>AAL</Th>
                      <Th className="text-right">Action</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {userSessions.map((session) => (
                      <tr key={session.id}>
                        <Td className="font-mono text-xs whitespace-nowrap text-sand-muted">{relativeLabel(session.startedAt)}</Td>
                        <Td className="font-mono text-xs text-cream-primary">{session.origin}</Td>
                        <Td>
                          <Badge tone={session.aal === "aal2" ? "ok" : "warn"}>{session.aal}</Badge>
                        </Td>
                        <Td className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toast("Revoke session", { description: "Requires a fresh TOTP challenge. Phase 2." })}
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

        <div className="mt-5 flex flex-col gap-5 lg:mt-0">
          <Panel>
            <PanelHeader
              title="Activity"
              hint={deniedCount > 0 ? `${userActivity.length} events · ${deniedCount} denied` : `${userActivity.length} events`}
              action={
                <Button asChild variant="ghost" size="sm">
                  <Link to="/activity">Full timeline</Link>
                </Button>
              }
            />
            {userActivity.length === 0 ? (
              <EmptyState title="Nothing recorded yet" hint="This account has not signed in." />
            ) : (
              <ul className="divide-y divide-[color:var(--color-hairline)]">
                {userActivity.map((event) => (
                  <li key={event.id} className="flex items-baseline gap-3 px-4 py-2.5">
                    <time className="shrink-0 font-mono text-[11px] text-sand-muted/60">{timeLabel(event.at)}</time>
                    <div className="min-w-0 flex-1">
                      <p className={`truncate font-mono text-xs ${event.result === "denied" ? "text-state-crit" : "text-cream-primary"}`}>
                        {event.action}
                      </p>
                      <p className="mt-0.5 truncate text-[11px] text-sand-muted/70">{event.target}</p>
                    </div>
                    <ResultBadge result={event.result} />
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel>
            <PanelHeader title={`Case memberships · ${user.caseMemberships.length}`} />
            {user.caseMemberships.length === 0 ? (
              <EmptyState title="Not a member of any case" />
            ) : (
              <ul className="divide-y divide-[color:var(--color-hairline)]">
                {user.caseMemberships.map((membership) => (
                  <li key={membership.caseId} className="flex items-baseline gap-3 px-4 py-2.5">
                    <span className="shrink-0 font-mono text-[11px] text-signal">{membership.caseId}</span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-xs text-cream-primary">{membership.caseTitle}</p>
                      <p className="mt-0.5 font-mono text-[10px] text-sand-muted/70">
                        {membership.role} · added {relativeLabel(membership.addedAt)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel className="border-state-crit/70">
            <PanelHeader
              title="Credential & account actions"
              className="border-state-crit/40"
              hint="Each requires a fresh TOTP challenge and a written reason"
            />
            <div className="flex flex-wrap gap-2 px-4 py-3.5">
              <Button variant="outline" size="sm" onClick={() => setRecoveryOpen(true)}>
                <KeyRound className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Restore access
              </Button>
              <Button variant="outline" size="sm" onClick={() => toast("Reset MFA factor", { description: "Follow docs/MFA_RECOVERY_RUNBOOK.md. Phase 2." })}>
                <ShieldOff className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Reset MFA factor
              </Button>
              <Button variant="outline" size="sm" onClick={() => toast("Revoke all sessions", { description: "Kills every refresh token for this account. Phase 2." })}>
                <LogOut className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Revoke all sessions
              </Button>
              <Button variant="danger" size="sm" onClick={() => toast("Deactivate account", { description: "Requires step-up and a written reason. Phase 2." })}>
                <UserMinus className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                Deactivate
              </Button>
            </div>
            <p className="border-t border-hairline px-4 py-2.5 text-[11px] text-sand-muted/70">
              Every action here appends to the tamper-evident admin audit chain. An administrator cannot perform any of them on their own account.
            </p>
          </Panel>
        </div>
      </PageBody>

      <RecoveryDialog user={user} open={recoveryOpen} onOpenChange={setRecoveryOpen} />
    </>
  );
}
