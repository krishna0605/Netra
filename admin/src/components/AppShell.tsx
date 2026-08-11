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

import { Badge } from "./ui/primitives";
import { CURRENT_OPERATOR } from "../data/mock";
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
  { to: "/audit", label: "Admin audit", icon: ScrollText },
];

function NavSection({ items, label }: { items: NavItem[]; label: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <p className="px-4 pt-4 pb-1.5 font-mono text-[9.5px] tracking-[0.15em] text-sand-muted/50 uppercase">{label}</p>
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            cn(
              "flex items-center gap-2.5 border-l-2 px-4 py-2 text-[13px] transition-colors",
              isActive
                ? "border-signal bg-signal/10 text-signal"
                : "border-transparent text-sand-muted hover:bg-cream-primary/5 hover:text-cream-bright",
            )
          }
        >
          <item.icon className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
          <span className="truncate">{item.label}</span>
        </NavLink>
      ))}
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="app-theme flex min-h-screen flex-col">
      {/* A permanent accent rule across the top. Combined with the ADMIN tag in
          the rail, it means you can never be a beat unsure which of the two
          consoles you are typing into. */}
      <div className="h-0.5 shrink-0 bg-signal" aria-hidden="true" />

      <div className="flex min-h-0 flex-1">
        <aside className="sticky top-0 hidden h-screen w-[15rem] shrink-0 flex-col border-r border-hairline bg-charcoal-panel/80 backdrop-blur-sm md:flex">
          <div className="flex items-center gap-2.5 border-b border-hairline px-4 py-3.5">
            <img src="/brand/netra-logo-mark.svg" alt="" className="size-7 shrink-0" aria-hidden="true" />
            <div className="min-w-0">
              <p className="font-mono text-sm leading-tight font-semibold tracking-[0.04em] text-cream-bright">NETRA</p>
              <p className="font-mono text-[9.5px] leading-tight tracking-[0.18em] text-signal uppercase">Admin console</p>
            </div>
          </div>

          <nav className="flex-1 overflow-y-auto pb-4" aria-label="Admin sections">
            <NavSection items={PRIMARY_NAV} label="Access" />
            <NavSection items={SECONDARY_NAV} label="Record" />
          </nav>

          <div className="border-t border-hairline px-4 py-3">
            <div className="flex items-center gap-2.5">
              <span
                className="grid size-7 shrink-0 place-items-center rounded-sm border border-signal/50 bg-signal/12 font-mono text-[10px] font-semibold text-signal"
                aria-hidden="true"
              >
                {initials(CURRENT_OPERATOR.name)}
              </span>
              <div className="min-w-0">
                <p className="truncate text-xs text-cream-bright">{CURRENT_OPERATOR.name}</p>
                <p className="truncate font-mono text-[10px] text-sand-muted/70">{CURRENT_OPERATOR.role}</p>
              </div>
            </div>
            <div className="mt-2.5 flex items-center gap-1.5">
              <Badge tone="ok">
                <ShieldCheck className="size-2.5" strokeWidth={2.5} aria-hidden="true" />
                aal2
              </Badge>
              <span className="font-mono text-[10px] text-sand-muted/60">
                step-up {relativeLabel(CURRENT_OPERATOR.stepUpVerifiedAt)}
              </span>
            </div>
          </div>
        </aside>

        {/* Mobile rail replacement — the console is desktop-first (it is operated
            at a desk) but must not become unusable on a narrow window. */}
        <nav className="fixed inset-x-0 bottom-0 z-20 flex overflow-x-auto border-t border-hairline bg-charcoal-panel md:hidden" aria-label="Admin sections">
          {[...PRIMARY_NAV, ...SECONDARY_NAV].map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "flex min-w-[4.5rem] flex-1 flex-col items-center gap-1 px-2 py-2 font-mono text-[9px] tracking-wide uppercase",
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
    </div>
  );
}
