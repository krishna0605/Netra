import { ArrowUpRight, Clock, KeyRound, ShieldAlert, UserMinus } from "lucide-react";
import { Link } from "react-router-dom";

import { ORGANIZATION, OVERVIEW } from "../data/mock";
import { useDirectory } from "../data/store";
import { ErrorState, SkeletonList, SkeletonTiles } from "../components/states";
import { Button, Panel, PanelHeader, Tag } from "../components/ui/primitives";
import { PageBody, PageHeader, StatTile } from "../components/common";
import { relativeLabel, timeLabel } from "../lib/utils";

export function OverviewPage() {
  const { users, activity, audit, loading, error, refetch } = useDirectory();

  const recentDenials = activity.filter((event) => event.result === "denied").slice(0, 5);
  const recentAdminActions = audit.slice(0, 5);

  const live = {
    activeUsers: users.filter((user) => user.status === "active").length,
    denied: activity.filter((event) => event.result === "denied").length,
    mfaEnrolled: users.filter((user) => user.mfa === "verified").length,
    mfaTotal: users.filter((user) => user.status !== "deactivated").length,
    invites: users.filter((user) => user.status === "invited").length,
    grants: users.flatMap((user) => user.permissions).filter((permission) => permission.expiresAt).length,
    stale: users.filter(
      (user) => user.status === "active" && user.lastActivityAt && Date.now() - Date.parse(user.lastActivityAt) > 90 * 864e5,
    ).length,
  };

  // Ranked by how strongly each suggests something is actively wrong, not by
  // recency. A denial burst outranks a dormant account.
  const attention = [
    live.denied > 0 && {
      icon: ShieldAlert,
      tone: "crit" as const,
      lead: `${live.denied} denied ${live.denied === 1 ? "action" : "actions"}`,
      detail: `${OVERVIEW.deniedTopActor} accounts for most of them, all against export`,
      to: "/activity",
      cta: "Triage",
    },
    live.mfaTotal - live.mfaEnrolled > 0 && {
      icon: KeyRound,
      tone: "crit" as const,
      lead: `${live.mfaTotal - live.mfaEnrolled} accounts without an authenticator`,
      detail: "Policy requires enrolment for administrators only — these sit below that line",
      to: "/users",
      cta: "Review",
    },
    live.invites > 0 && {
      icon: Clock,
      tone: "warn" as const,
      lead: `${live.invites} invitation ${live.invites === 1 ? "is" : "are"} unaccepted`,
      detail: `${OVERVIEW.invitesExpiringToday} expiring today`,
      to: "/users",
      cta: "Resend",
    },
    live.stale > 0 && {
      icon: UserMinus,
      tone: "warn" as const,
      lead: `${live.stale} accounts inactive over 90 days`,
      detail: "Candidates for deactivation",
      to: "/users",
      cta: "Review",
    },
  ].filter((item): item is Exclude<typeof item, false> => item !== false);

  return (
    <>
      <PageHeader
        title="Overview"
        summary={`${ORGANIZATION.name} · last 24 hours`}
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/activity">
              Full activity
              <ArrowUpRight className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            </Link>
          </Button>
        }
      />

      <PageBody>
        {error ? <Panel><ErrorState detail={error} onRetry={() => void refetch()} /></Panel> : null}

        {loading ? <SkeletonTiles count={5} /> : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <StatTile
            label="Active users"
            value={live.activeUsers}
            trend={OVERVIEW.activeUsersTrend}
            delta={{ direction: "up", text: `${OVERVIEW.newUsersThisWeek} this week` }}
          />
          <StatTile
            label="Denied actions"
            value={live.denied}
            trend={OVERVIEW.deniedTrend}
            delta={{ direction: "up", text: "sharp rise", good: false }}
            hint={`Most from ${OVERVIEW.deniedTopActor}`}
            alert
          />
          <StatTile
            label="Authenticator enrolled"
            value={live.mfaEnrolled}
            of={live.mfaTotal}
            hint={`${live.mfaTotal - live.mfaEnrolled} outstanding`}
          />
          <StatTile label="Pending invitations" value={live.invites} hint={`${OVERVIEW.invitesExpiringToday} expiring today`} />
          <StatTile label="Temporary grants" value={live.grants} hint="Expire 01 September" />
        </div>
        )}

        <Panel>
          <PanelHeader title="Needs attention" />
          <ul className="divide-y divide-[color:var(--color-hairline)]">
            {attention.map((item) => (
              <li key={item.lead} className="flex flex-wrap items-center gap-4 px-5 py-4 transition-colors hover:bg-cream-primary/3">
                <span
                  className={
                    item.tone === "crit"
                      ? "grid size-9 shrink-0 place-items-center rounded-control border border-state-crit/40 bg-state-crit/10 text-state-crit"
                      : "grid size-9 shrink-0 place-items-center rounded-control border border-state-warn/40 bg-state-warn/10 text-state-warn"
                  }
                >
                  <item.icon className="size-4" strokeWidth={1.75} aria-hidden="true" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-[15px] text-cream-bright">{item.lead}</p>
                  <p className="mt-0.5 text-[13px] text-sand-muted/75">{item.detail}</p>
                </div>
                <Button asChild variant="outline" size="sm">
                  <Link to={item.to}>{item.cta}</Link>
                </Button>
              </li>
            ))}
          </ul>
        </Panel>

        <div className="grid gap-6 lg:grid-cols-2">
          <Panel>
            <PanelHeader
              title="Recent denials"
              action={
                <Button asChild variant="ghost" size="sm">
                  <Link to="/activity">View all</Link>
                </Button>
              }
            />
            {loading ? <SkeletonList rows={5} /> : (
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {recentDenials.map((event) => (
                <li key={event.id} className="flex items-baseline gap-4 px-5 py-3">
                  <time className="shrink-0 font-mono text-xs text-sand-muted/60">{timeLabel(event.at)}</time>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px] text-state-crit">{event.action}</p>
                    <p className="mt-0.5 truncate text-xs text-sand-muted/70">
                      {event.actor} · {event.target}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
            )}
          </Panel>

          <Panel>
            <PanelHeader
              title="Recent administrator actions"
              action={
                <Button asChild variant="ghost" size="sm">
                  <Link to="/audit">View all</Link>
                </Button>
              }
            />
            {loading ? <SkeletonList rows={5} /> : (
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {recentAdminActions.map((event) => (
                <li key={event.id} className="flex items-baseline gap-4 px-5 py-3">
                  <time className="shrink-0 text-xs text-sand-muted/60">{relativeLabel(event.at)}</time>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px] text-cream-primary">{event.action}</p>
                    <p className="mt-0.5 truncate text-xs text-sand-muted/70">{event.after}</p>
                  </div>
                  <Tag tone="neutral" mono>
                    {event.chainIndex}
                  </Tag>
                </li>
              ))}
            </ul>
            )}
          </Panel>
        </div>
      </PageBody>
    </>
  );
}
