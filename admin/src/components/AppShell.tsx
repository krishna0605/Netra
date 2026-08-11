import {
  Activity,
  Building2,
  KeyRound,
  LayoutDashboard,
  MonitorSmartphone,
  ScrollText,
  ShieldCheck,
  ToggleLeft,
  Users,
  type LucideIcon,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

import { Avatar } from "./ui/primitives";
import { CURRENT_OPERATOR, ORGANIZATION } from "../data/mock";
import { cn, initials, relativeLabel } from "../lib/utils";

type NavItem = { to: string; label: string; icon: LucideIcon; end?: boolean };

const PRIMARY_NAV: NavItem[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/users", label: "Users", icon: Users },
  { to: "/roles", label: "Roles & permissions", icon: KeyRound },
  { to: "/activity", label: "Activity", icon: Activity },
  { to: "/sessions", label: "Sessions", icon: MonitorSmartphone },
];

const SECONDARY_NAV: NavItem[] = [
  { to: "/organization", label: "Organization", icon: Building2 },
  { to: "/capabilities", label: "Capabilities", icon: ToggleLeft },
  { to: "/audit", label: "Audit trail", icon: ScrollText },
];

function NavSection({ items, label }: { items: NavItem[]; label: string }) {
  return (
    <div className="flex flex-col gap-0.5 px-2.5">
      <p className="px-2.5 pt-5 pb-2 text-[11px] font-medium tracking-[0.1em] text-sand-muted/45 uppercase">{label}</p>
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-2.5 rounded-control px-2.5 py-2 text-[13.5px] transition-colors",
              isActive ? "bg-signal/12 font-medium text-signal" : "text-sand-muted hover:bg-cream-primary/5 hover:text-cream-bright",
            )
          }
        >
          <item.icon className="size-4 shrink-0" strokeWidth={1.75} aria-hidden="true" />
          <span className="truncate">{item.label}</span>
        </NavLink>
      ))}
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="app-theme flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-[16rem] shrink-0 flex-col border-r border-hairline bg-charcoal-panel/70 md:flex">
        <div className="px-4 py-4">
          <div className="flex items-center gap-2.5">
            <img src="/brand/netra-logo-mark.svg" alt="" className="size-8 shrink-0" aria-hidden="true" />
            <div className="min-w-0">
              <p className="font-mono text-[15px] leading-tight font-semibold tracking-[0.05em] text-cream-bright">NETRA</p>
              <p className="truncate text-[11px] leading-tight text-sand-muted/70">Administration</p>
            </div>
          </div>
          <p className="mt-3.5 truncate rounded-control border border-hairline bg-cream-primary/4 px-2.5 py-1.5 text-[12px] text-sand-muted">
            {ORGANIZATION.name}
          </p>
        </div>

        <nav className="flex-1 overflow-y-auto pb-5" aria-label="Sections">
          <NavSection items={PRIMARY_NAV} label="Access" />
          <NavSection items={SECONDARY_NAV} label="Record" />
        </nav>

        <div className="border-t border-hairline px-4 py-3.5">
          <div className="flex items-center gap-2.5">
            <Avatar initials={initials(CURRENT_OPERATOR.name)} tone="accent" />
            <div className="min-w-0">
              <p className="truncate text-[13px] text-cream-bright">{CURRENT_OPERATOR.name}</p>
              <p className="truncate text-[11px] text-sand-muted/70">{CURRENT_OPERATOR.role}</p>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-[11px] text-sand-muted/60">
            <ShieldCheck className="size-3.5 shrink-0 text-state-ok" strokeWidth={2} aria-hidden="true" />
            <span>Verified {relativeLabel(CURRENT_OPERATOR.stepUpVerifiedAt)}</span>
          </div>
        </div>
      </aside>

      {/* The console is operated at a desk, but a narrow window must not make it
          unusable. */}
      <nav className="fixed inset-x-0 bottom-0 z-20 flex overflow-x-auto border-t border-hairline bg-charcoal-panel md:hidden" aria-label="Sections">
        {[...PRIMARY_NAV, ...SECONDARY_NAV].map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                "flex min-w-[4.5rem] flex-1 flex-col items-center gap-1 px-2 py-2.5 text-[10px]",
                isActive ? "text-signal" : "text-sand-muted/70",
              )
            }
          >
            <item.icon className="size-4" strokeWidth={1.75} aria-hidden="true" />
            <span className="truncate">{item.label.split(" ")[0]}</span>
          </NavLink>
        ))}
      </nav>

      <main className="min-w-0 flex-1 pb-20 md:pb-0">{children}</main>
    </div>
  );
}
