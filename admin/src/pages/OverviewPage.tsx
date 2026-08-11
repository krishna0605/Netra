import { ArrowUpRight, Clock, KeyRound, ShieldAlert, UserMinus } from "lucide-react";
import { Link } from "react-router-dom";

import { ACTIVITY, AUDIT, ORGANIZATION, OVERVIEW } from "../data/mock";
import { Button, Panel, PanelHeader, Tag } from "../components/ui/primitives";
import { PageBody, PageHeader, StatTile } from "../components/common";
import { relativeLabel, timeLabel } from "../lib/utils";

/** Ranked by how strongly each suggests something is actively wrong, not by
 *  recency. A denial burst outranks a stale account. */
const ATTENTION = [
  {
    icon: ShieldAlert,
    tone: "crit" as const,
    lead: `${OVERVIEW.deniedLast24h} denied actions`,
    detail: `${OVERVIEW.deniedTopActor} accounts for most of them, all against export`,
    to: "/activity",
    cta: "Triage",
  },
  {
    icon: KeyRound,
    tone: "crit" as const,
    lead: `${OVERVIEW.mfaTotal - OVERVIEW.mfaEnrolled} accounts without an authenticator`,
    detail: "Policy requires enrolment for administrators only — these sit below that line",
    to: "/users",
    cta: "Review",
  },
  {
    icon: Clock,
    tone: "warn" as const,
    lead: "1 invitation expiring today",
    detail: "r.shah@gcc.gov.in has not accepted since it was sent",
    to: "/users",
    cta: "Resend",
  },
  {
    icon: UserMinus,
    tone: "warn" as const,
    lead: `${OVERVIEW.staleAccounts} accounts inactive over 90 days`,
    detail: "Candidates for deactivation",
    to: "/users",
    cta: "Review",
  },
];

export function OverviewPage() {
  const recentDenials = ACTIVITY.filter((event) => event.result === "denied").slice(0, 5);
  const recentAdminActions = AUDIT.slice(0, 5);

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
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          <StatTile
            label="Active users"
            value={OVERVIEW.activeUsers}
            trend={OVERVIEW.activeUsersTrend}
            delta={{ direction: "up", text: `${OVERVIEW.newUsersThisWeek} this week` }}
          />
          <StatTile
            label="Denied actions"
            value={OVERVIEW.deniedLast24h}
            trend={OVERVIEW.deniedTrend}
            delta={{ direction: "up", text: "sharp rise", good: false }}
            hint={`Most from ${OVERVIEW.deniedTopActor}`}
            alert
          />
          <StatTile
            label="Authenticator enrolled"
            value={OVERVIEW.mfaEnrolled}
            of={OVERVIEW.mfaTotal}
            hint={`${OVERVIEW.mfaTotal - OVERVIEW.mfaEnrolled} outstanding`}
          />
          <StatTile label="Pending invitations" value={OVERVIEW.pendingInvites} hint={`${OVERVIEW.invitesExpiringToday} expiring today`} />
          <StatTile label="Temporary grants" value={OVERVIEW.temporaryGrants} hint="Expire 01 September" />
        </div>

        <Panel>
          <PanelHeader title="Needs attention" />
          <ul className="divide-y divide-[color:var(--color-hairline)]">
            {ATTENTION.map((item) => (
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
          </Panel>
        </div>
      </PageBody>
    </>
  );
}
