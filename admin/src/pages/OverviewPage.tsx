import { AlertTriangle, ArrowUpRight, Clock, KeyRound, ShieldAlert, UserPlus } from "lucide-react";
import { Link } from "react-router-dom";

import { ACTIVITY, AUDIT, ORGANIZATION, OVERVIEW } from "../data/mock";
import { Badge, Button, Panel, PanelHeader } from "../components/ui/primitives";
import { PageBody, PageHeader, StatTile } from "../components/common";
import { relativeLabel, timeLabel } from "../lib/utils";

/** Attention items are ranked by how much they suggest something is actively
 *  wrong, not by recency. A denial burst outranks a stale account. */
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
    lead: `${OVERVIEW.mfaTotal - OVERVIEW.mfaEnrolled} accounts without MFA`,
    detail: "Policy requires MFA for administrators only — these are below that line",
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
    icon: UserPlus,
    tone: "warn" as const,
    lead: `${OVERVIEW.staleAccounts} stale accounts`,
    detail: "No sign-in in over 90 days — candidates for deactivation",
    to: "/users",
    cta: "Review",
  },
];

export function OverviewPage() {
  const recentAdminActions = AUDIT.slice(0, 5);
  const recentDenials = ACTIVITY.filter((event) => event.result === "denied").slice(0, 5);

  return (
    <>
      <PageHeader
        title="Overview"
        summary={`${ORGANIZATION.name} · ${ORGANIZATION.slug} · last 24 hours`}
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
          <StatTile label="Active users" value={OVERVIEW.activeUsers} hint={`+${OVERVIEW.newUsersThisWeek} this week`} />
          <StatTile label="Denied actions" value={OVERVIEW.deniedLast24h} hint={`most from ${OVERVIEW.deniedTopActor}`} alert />
          <StatTile label="MFA enrolled" value={OVERVIEW.mfaEnrolled} of={OVERVIEW.mfaTotal} hint={`${OVERVIEW.mfaTotal - OVERVIEW.mfaEnrolled} outstanding`} />
          <StatTile label="Pending invites" value={OVERVIEW.pendingInvites} hint={`${OVERVIEW.invitesExpiringToday} expiring today`} />
          <StatTile label="Temporary grants" value={OVERVIEW.temporaryGrants} hint="expire 01 Sep 2026" />
        </div>

        <Panel>
          <PanelHeader title="Needs attention" hint="Ranked by how strongly each suggests an active problem" />
          <ul className="divide-y divide-[color:var(--color-hairline)]">
            {ATTENTION.map((item) => (
              <li key={item.lead} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <item.icon
                  className={item.tone === "crit" ? "size-4 shrink-0 text-state-crit" : "size-4 shrink-0 text-state-warn"}
                  strokeWidth={1.75}
                  aria-hidden="true"
                />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-cream-bright">{item.lead}</p>
                  <p className="mt-0.5 text-xs text-sand-muted/75">{item.detail}</p>
                </div>
                <Button asChild variant="ghost" size="sm">
                  <Link to={item.to}>{item.cta}</Link>
                </Button>
              </li>
            ))}
          </ul>
        </Panel>

        <div className="grid gap-5 lg:grid-cols-2">
          <Panel>
            <PanelHeader
              title="Recent denials"
              hint="Every denial is already recorded — this is the cheapest signal you have"
              action={
                <Button asChild variant="ghost" size="sm">
                  <Link to="/activity">All</Link>
                </Button>
              }
            />
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {recentDenials.map((event) => (
                <li key={event.id} className="flex items-baseline gap-3 px-4 py-2.5">
                  <time className="shrink-0 font-mono text-[11px] text-sand-muted/60">{timeLabel(event.at)}</time>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-xs text-state-crit">{event.action}</p>
                    <p className="mt-0.5 truncate text-[11px] text-sand-muted/70">
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
              hint="From the tamper-evident admin audit chain"
              action={
                <Button asChild variant="ghost" size="sm">
                  <Link to="/audit">All</Link>
                </Button>
              }
            />
            <ul className="divide-y divide-[color:var(--color-hairline)]">
              {recentAdminActions.map((event) => (
                <li key={event.id} className="flex items-baseline gap-3 px-4 py-2.5">
                  <time className="shrink-0 font-mono text-[11px] text-sand-muted/60">{relativeLabel(event.at)}</time>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-xs text-cream-primary">{event.action}</p>
                    <p className="mt-0.5 truncate text-[11px] text-sand-muted/70">{event.after}</p>
                  </div>
                  <Badge tone="neutral">#{event.chainIndex}</Badge>
                </li>
              ))}
            </ul>
          </Panel>
        </div>

        <Panel className="flex flex-wrap items-center gap-3 px-4 py-3">
          <AlertTriangle className="size-4 shrink-0 text-state-warn" strokeWidth={1.75} aria-hidden="true" />
          <p className="min-w-0 flex-1 text-xs text-sand-muted">
            Running on mock data. No backend is attached — the{" "}
            <span className="font-mono text-cream-primary">/api/admin/v1/*</span> namespace is phase 1 of the implementation plan.
          </p>
          <Badge tone="warn">Design preview</Badge>
        </Panel>
      </PageBody>
    </>
  );
}
