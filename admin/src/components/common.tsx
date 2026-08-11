import type { ReactNode } from "react";

import { Badge, Panel } from "./ui/primitives";
import { cn } from "../lib/utils";
import type { ActivityResult, MfaState, RiskLevel, UserStatus } from "../data/types";

/* ---------------------------------------------------------------------------
   Page header — every screen opens the same way: what this is, what is in it,
   and the one action that belongs here.
   --------------------------------------------------------------------------- */
export function PageHeader({
  title,
  summary,
  action,
  back,
}: {
  title: ReactNode;
  summary: string;
  action?: ReactNode;
  back?: ReactNode;
}) {
  return (
    <header className="border-b border-hairline px-5 py-5 md:px-8 md:py-6">
      {back ? <div className="mb-3">{back}</div> : null}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="flex flex-wrap items-center gap-2.5 text-xl font-semibold text-cream-bright md:text-2xl">{title}</h1>
          <p className="mt-1.5 font-mono text-xs text-sand-muted/80">{summary}</p>
        </div>
        {action ? <div className="flex shrink-0 flex-wrap items-center gap-2">{action}</div> : null}
      </div>
    </header>
  );
}

export function PageBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("flex flex-col gap-5 px-5 py-6 md:px-8", className)}>{children}</div>;
}

/* ---------------------------------------------------------------------------
   Stat tile — the summary layer. Anything that needs attention gets the alert
   treatment so it reads before the numbers that are merely informational.
   --------------------------------------------------------------------------- */
export function StatTile({
  label,
  value,
  of,
  hint,
  alert = false,
}: {
  label: string;
  value: ReactNode;
  of?: ReactNode;
  hint?: string;
  alert?: boolean;
}) {
  return (
    <Panel className={cn("px-4 py-3", alert && "border-state-crit/70")}>
      <p className="font-mono text-[9.5px] tracking-[0.13em] text-sand-muted/70 uppercase">{label}</p>
      <p className={cn("mt-1.5 font-mono text-2xl leading-none font-semibold", alert ? "text-state-crit" : "text-cream-bright")}>
        {value}
        {of ? <span className="text-sm text-sand-muted/60">/{of}</span> : null}
      </p>
      {hint ? <p className="mt-1.5 font-mono text-[10px] text-sand-muted/60">{hint}</p> : null}
    </Panel>
  );
}

/* ---------------------------------------------------------------------------
   Shared state badges. Centralised so "denied" looks identical on every screen
   — an operator should recognise it without reading.
   --------------------------------------------------------------------------- */
const USER_STATUS: Record<UserStatus, { label: string; tone: "ok" | "warn" | "neutral" }> = {
  active: { label: "Active", tone: "ok" },
  invited: { label: "Invited", tone: "warn" },
  locked_out: { label: "Locked out", tone: "warn" },
  deactivated: { label: "Deactivated", tone: "neutral" },
};

export function UserStatusBadge({ status }: { status: UserStatus }) {
  const entry = USER_STATUS[status];
  return <Badge tone={entry.tone}>{entry.label}</Badge>;
}

const MFA_STATE: Record<MfaState, { label: string; tone: "ok" | "warn" | "crit" }> = {
  verified: { label: "TOTP", tone: "ok" },
  unenrolled: { label: "None", tone: "crit" },
  factor_lost: { label: "Factor lost", tone: "warn" },
};

export function MfaBadge({ state }: { state: MfaState }) {
  const entry = MFA_STATE[state];
  return <Badge tone={entry.tone}>{entry.label}</Badge>;
}

const RESULT: Record<ActivityResult, { label: string; tone: "ok" | "crit" | "info" }> = {
  allowed: { label: "Allowed", tone: "ok" },
  denied: { label: "Denied", tone: "crit" },
  recorded: { label: "Recorded", tone: "info" },
};

export function ResultBadge({ result }: { result: ActivityResult }) {
  const entry = RESULT[result];
  return <Badge tone={entry.tone}>{entry.label}</Badge>;
}

const RISK: Record<RiskLevel, { label: string; tone: "neutral" | "warn" | "crit" }> = {
  standard: { label: "Standard", tone: "neutral" },
  elevated: { label: "Elevated", tone: "warn" },
  high: { label: "High risk", tone: "crit" },
};

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  const entry = RISK[risk];
  return <Badge tone={entry.tone}>{entry.label}</Badge>;
}

export function RoleBadge({ name, isOwner = false }: { name: string; isOwner?: boolean }) {
  if (isOwner) return <Badge tone="accent">Owner</Badge>;
  return <Badge tone="info">{name}</Badge>;
}
