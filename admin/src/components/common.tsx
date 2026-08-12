import type { ReactNode } from "react";

import { Panel, Status, Tag } from "./ui/primitives";
import { cn } from "../lib/utils";
import type { ActivityResult, MfaState, RiskLevel, UserStatus } from "../data/types";

/* ---------------------------------------------------------------------------
   Page header
   --------------------------------------------------------------------------- */
export function PageHeader({
  title,
  summary,
  action,
  back,
}: {
  title: ReactNode;
  summary: ReactNode;
  action?: ReactNode;
  back?: ReactNode;
}) {
  return (
    <header className="border-b border-hairline px-5 pt-6 pb-6 md:px-8 md:pt-8">
      {back ? <div className="mb-4">{back}</div> : null}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="flex flex-wrap items-center gap-3 text-2xl font-semibold text-cream-bright md:text-[28px]">{title}</h1>
          <p className="mt-2 text-sm text-sand-muted/85">{summary}</p>
        </div>
        {action ? <div className="flex shrink-0 flex-wrap items-center gap-2">{action}</div> : null}
      </div>
    </header>
  );
}

export function PageBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("flex flex-col gap-6 px-5 py-7 md:px-8", className)}>{children}</div>;
}

/* ---------------------------------------------------------------------------
   Sparkline — one series, no axes, no per-point labels. The endpoint is
   emphasised because "where it is now" is the only reading anyone takes from
   a mark this small.
   --------------------------------------------------------------------------- */
export function Sparkline({ points, tone = "accent" }: { points: number[]; tone?: "accent" | "crit" }) {
  const width = 58;
  const height = 18;
  const max = Math.max(...points, 1);
  const step = width / Math.max(points.length - 1, 1);
  const coords = points.map((value, index) => [index * step, height - (value / max) * (height - 2) - 1] as const);
  const line = coords.map(([x, y], index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${line} L${width},${height} L0,${height} Z`;
  const [lastX, lastY] = coords[coords.length - 1];
  const stroke = tone === "crit" ? "var(--color-state-crit)" : "var(--color-signal)";

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible" aria-hidden="true">
      <path d={area} fill={stroke} opacity="0.12" />
      <path d={line} fill="none" stroke={stroke} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.85" />
      <circle cx={lastX} cy={lastY} r="2.5" fill={stroke} />
    </svg>
  );
}

/* ---------------------------------------------------------------------------
   Stat tile
   --------------------------------------------------------------------------- */
export function StatTile({
  label,
  value,
  of,
  hint,
  delta,
  trend,
  alert = false,
}: {
  label: string;
  value: ReactNode;
  of?: ReactNode;
  hint?: string;
  delta?: { direction: "up" | "down"; text: string; good?: boolean };
  trend?: number[];
  alert?: boolean;
}) {
  return (
    <Panel className={cn("px-4 py-4", alert && "border-state-crit/50")}>
      <div className="flex items-start justify-between gap-2">
        <p className="text-[13px] text-sand-muted/75">{label}</p>
        {trend ? <Sparkline points={trend} tone={alert ? "crit" : "accent"} /> : null}
      </div>
      <div className="mt-2.5 flex flex-wrap items-baseline gap-2">
        <p className={cn("font-mono text-[26px] leading-none font-semibold", alert ? "text-state-crit" : "text-cream-bright")}>
          {value}
          {of ? <span className="text-base text-sand-muted/70">/{of}</span> : null}
        </p>
        {delta ? (
          <span className={cn("text-xs font-medium", delta.good === false ? "text-state-crit" : "text-state-ok")}>
            {delta.direction === "up" ? "↑" : "↓"} {delta.text}
          </span>
        ) : null}
      </div>
      {hint ? <p className="mt-2 text-xs text-sand-muted/70">{hint}</p> : null}
    </Panel>
  );
}

/* ---------------------------------------------------------------------------
   Shared state indicators. Centralised so "denied" looks identical on every
   screen — an operator should recognise it without reading.
   --------------------------------------------------------------------------- */
const USER_STATUS: Record<UserStatus, { label: string; tone: "ok" | "warn" | "neutral" }> = {
  active: { label: "Active", tone: "ok" },
  invited: { label: "Invited", tone: "warn" },
  locked_out: { label: "Locked out", tone: "warn" },
  deactivated: { label: "Deactivated", tone: "neutral" },
};

export function UserStatusBadge({ status }: { status: UserStatus }) {
  const entry = USER_STATUS[status];
  return <Status tone={entry.tone}>{entry.label}</Status>;
}

const MFA_STATE: Record<MfaState, { label: string; tone: "ok" | "warn" | "crit" }> = {
  verified: { label: "Authenticator", tone: "ok" },
  unenrolled: { label: "Not enrolled", tone: "crit" },
  factor_lost: { label: "Factor lost", tone: "warn" },
};

export function MfaBadge({ state }: { state: MfaState }) {
  const entry = MFA_STATE[state];
  return <Status tone={entry.tone}>{entry.label}</Status>;
}

const RESULT: Record<ActivityResult, { label: string; tone: "ok" | "crit" | "info" }> = {
  allowed: { label: "Allowed", tone: "ok" },
  denied: { label: "Denied", tone: "crit" },
  recorded: { label: "Recorded", tone: "info" },
};

export function ResultBadge({ result }: { result: ActivityResult }) {
  const entry = RESULT[result];
  return <Status tone={entry.tone}>{entry.label}</Status>;
}

const RISK: Record<RiskLevel, { label: string; tone: "neutral" | "warn" | "crit" }> = {
  standard: { label: "Standard", tone: "neutral" },
  elevated: { label: "Elevated", tone: "warn" },
  high: { label: "High risk", tone: "crit" },
};

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  const entry = RISK[risk];
  return <Status tone={entry.tone}>{entry.label}</Status>;
}

/** Role is categorical, not state — so it keeps the bordered pill. */
export function RoleBadge({ name, isOwner = false }: { name: string; isOwner?: boolean }) {
  if (isOwner) return <Tag tone="accent">Owner</Tag>;
  return <Tag tone="neutral">{name}</Tag>;
}
