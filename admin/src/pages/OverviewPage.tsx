import { ArrowUpRight, Clock, KeyRound, ShieldAlert, UserMinus } from "lucide-react";
import { Link } from "react-router-dom";
import { useMemo } from "react";

import { Button, Panel, PanelHeader, Tag } from "../components/ui/primitives";
import { ErrorState, SkeletonList, SkeletonTiles } from "../components/states";
import { PageBody, PageHeader, StatTile } from "../components/common";
import {
  dailyCounts,
  dormantAccounts,
  invitationsExpiringToday,
  joinTrend,
  joinedSince,
  topDeniedActor,
} from "../lib/derive";
import { relativeLabel, timeLabel } from "../lib/utils";
import { useDirectory } from "../data/store";

export function OverviewPage() {
  const { users, activity, audit, organization, loading, error, refetch } = useDirectory();

  const recentDenials = activity.filter((event) => event.result === "denied").slice(0, 5);
  const recentAdminActions = audit.slice(0, 5);

  // Every figure below is computed from the data. Nothing is carried as a
  // constant, and anything with no history to compute from is omitted rather
  // than filled in.
  const live = useMemo(() => {
    const active = users.filter((user) => user.status !== "deactivated");
    return {
      activeUsers: users.filter((user) => user.status === "active").length,
      activeUsersTrend: joinTrend(users),
      joinedThisWeek: joinedSince(users, 7),
      denied: activity.filter((event) => event.result === "denied").length,
      deniedTrend: dailyCounts(activity, (event) => event.result === "denied"),
      topDenied: topDeniedActor(activity),
      mfaEnrolled: users.filter((user) => user.mfa === "verified").length,
      mfaTotal: active.length,
      invites: users.filter((user) => user.status === "invited").length,
      expiringToday: invitationsExpiringToday(users),
      grants: users.flatMap((user) => user.permissions).filter((permission) => permission.expiresAt).length,
      dormant: dormantAccounts(users),
    };
  }, [users, activity]);

  const missingAuthenticator = live.mfaTotal - live.mfaEnrolled;

  // Ranked by how strongly each suggests something is actively wrong, not by
  // recency. A denial burst outranks a dormant account.
  const attention = [
    live.denied > 0 && {
      icon: ShieldAlert,
      tone: "crit" as const,
      lead: `${live.denied} denied ${live.denied === 1 ? "action" : "actions"}`,
      detail: live.topDenied
        ? `${live.topDenied.name} accounts for ${live.topDenied.count} of them`
        : "Spread across several accounts",
      to: "/activity",
      cta: "Triage",
    },
    missingAuthenticator > 0 && {
      icon: KeyRound,
      tone: "crit" as const,
      lead: `${missingAuthenticator} ${missingAuthenticator === 1 ? "account has" : "accounts have"} no authenticator`,
      detail: "Policy requires enrolment for administrators — these sit below that line",
      to: "/users",
      cta: "Review",
    },
    live.invites > 0 && {
      icon: Clock,
      tone: "warn" as const,
      lead: `${live.invites} ${live.invites === 1 ? "invitation is" : "invitations are"} unaccepted`,
      detail: live.expiringToday > 0 ? `${live.expiringToday} expiring today` : "None expiring today",
      to: "/users",
      cta: "Review",
    },
    live.dormant > 0 && {
      icon: UserMinus,
      tone: "warn" as const,
      lead: `${live.dormant} ${live.dormant === 1 ? "account" : "accounts"} inactive over 90 days`,
      detail: "Candidates for deactivation",
      to: "/users",
      cta: "Review",
    },
  ].filter((item): item is Exclude<typeof item, false> => item !== false);

  return (
    <>
      <PageHeader
        title="Overview"
        summary={loading ? "Loading…" : `${organization.name} · last 24 hours`}
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
        {error ? (
          <Panel>
            <ErrorState detail={error} onRetry={() => void refetch()} />
          </Panel>
        ) : null}

        {loading ? (
          <SkeletonTiles count={5} />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <StatTile
              label="Active users"
              value={live.activeUsers}
              trend={live.activeUsersTrend ?? undefined}
              delta={live.joinedThisWeek > 0 ? { direction: "up", text: `${live.joinedThisWeek} this week` } : undefined}
            />
            <StatTile
              label="Denied actions"
              value={live.denied}
              trend={live.deniedTrend ?? undefined}
              hint={live.topDenied ? `Most from ${live.topDenied.name}` : undefined}
              alert={live.denied > 0}
            />
            <StatTile
              label="Authenticator enrolled"
              value={live.mfaEnrolled}
              of={live.mfaTotal}
              hint={missingAuthenticator > 0 ? `${missingAuthenticator} outstanding` : "All enrolled"}
            />
            <StatTile
              label="Pending invitations"
              value={live.invites}
              hint={live.expiringToday > 0 ? `${live.expiringToday} expiring today` : undefined}
            />
            <StatTile label="Temporary grants" value={live.grants} hint={live.grants > 0 ? "With an expiry set" : undefined} />
          </div>
        )}

        <Panel>
          <PanelHeader title="Needs attention" />
          {loading ? (
            <SkeletonList rows={4} />
          ) : attention.length === 0 ? (
            <p className="px-5 py-10 text-center text-[13.5px] text-sand-muted">Nothing needs attention right now.</p>
          ) : (
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
          )}
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
            {loading ? (
              <SkeletonList rows={5} />
            ) : recentDenials.length === 0 ? (
              <p className="px-5 py-10 text-center text-[13.5px] text-sand-muted">No denials recorded.</p>
            ) : (
              <ul className="divide-y divide-[color:var(--color-hairline)]">
                {recentDenials.map((event) => (
                  <li key={event.id} className="flex items-baseline gap-4 px-5 py-3">
                    <time className="shrink-0 font-mono text-xs text-sand-muted/70">{timeLabel(event.at)}</time>
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
            {loading ? (
              <SkeletonList rows={5} />
            ) : (
              <ul className="divide-y divide-[color:var(--color-hairline)]">
                {recentAdminActions.map((event) => (
                  <li key={event.id} className="flex items-baseline gap-4 px-5 py-3">
                    <time className="shrink-0 text-xs text-sand-muted/70">{relativeLabel(event.at)}</time>
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
