import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { ArrowLeftRight, ChevronsUpDown, LogOut, ShieldCheck } from "lucide-react";

import { Avatar } from "./ui/primitives";
import { cn, initials, relativeLabel } from "../lib/utils";
import { useAuth } from "../features/auth/AuthContext";
import { LANGUAGES, useLanguage } from "../i18n";

export function UserMenu() {
  const { profile, verifiedAt, returnToChooser, signOut, isStepUpFresh } = useAuth();
  const { language, setLanguage, t } = useLanguage();
  if (!profile) return null;

  const fresh = isStepUpFresh(10 * 60 * 1000);

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger
        className="flex w-full items-center gap-2.5 rounded-control px-1.5 py-1.5 text-left transition-colors hover:bg-cream-primary/6"
        aria-label={t("accountMenu")}
      >
        <Avatar initials={initials(profile.displayName)} tone="accent" />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] text-cream-bright">{profile.displayName}</span>
          <span className="block truncate text-[11px] text-sand-muted/70">{profile.role}</span>
        </span>
        <ChevronsUpDown className="size-3.5 shrink-0 text-sand-muted/70" strokeWidth={1.75} aria-hidden="true" />
      </DropdownMenu.Trigger>

      <DropdownMenu.Portal>
        <DropdownMenu.Content
          side="top"
          align="start"
          sideOffset={8}
          className="z-50 w-[15rem] rounded-panel border border-hairline-strong bg-charcoal-panel p-1.5 shadow-raised"
        >
          <div className="px-2.5 py-2">
            <p className="truncate font-mono text-[11.5px] text-sand-muted/80">{profile.email}</p>
            <p className="mt-1.5 flex items-center gap-1.5 text-[11px]">
              <ShieldCheck
                className={cn("size-3.5 shrink-0", fresh ? "text-state-ok" : "text-state-warn")}
                strokeWidth={2}
                aria-hidden="true"
              />
              <span className={fresh ? "text-sand-muted/70" : "text-state-warn"}>
                {t("verifiedAgo")} {verifiedAt ? relativeLabel(verifiedAt) : "—"}
              </span>
            </p>
          </div>

          <DropdownMenu.Separator className="my-1 h-px bg-[color:var(--color-hairline)]" />

          <div className="px-2.5 py-1.5">
            <p className="mb-1.5 text-[11px] text-sand-muted/70">{t("language")}</p>
            <div className="flex gap-1">
              {LANGUAGES.map((entry) => (
                <button
                  key={entry.id}
                  type="button"
                  onClick={() => setLanguage(entry.id)}
                  aria-pressed={language === entry.id}
                  className={cn(
                    "flex-1 rounded-control border px-1.5 py-1 text-[11.5px] transition-colors",
                    language === entry.id
                      ? "border-signal/60 bg-signal/12 text-signal"
                      : "border-hairline text-sand-muted hover:text-cream-bright",
                  )}
                >
                  {entry.label}
                </button>
              ))}
            </div>
          </div>

          <DropdownMenu.Separator className="my-1 h-px bg-[color:var(--color-hairline)]" />

          {/* Decision B — a person can hold both roles, so leaving Administration
              must not require signing out and back in. */}
          <DropdownMenu.Item
            onSelect={returnToChooser}
            className="flex cursor-pointer items-center gap-2.5 rounded-control px-2.5 py-2 text-[13px] text-cream-primary outline-none data-[highlighted]:bg-cream-primary/8"
          >
            <ArrowLeftRight className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
            {t("switchWorkspace")}
          </DropdownMenu.Item>

          <DropdownMenu.Item
            onSelect={() => void signOut()}
            className="flex cursor-pointer items-center gap-2.5 rounded-control px-2.5 py-2 text-[13px] text-state-crit outline-none data-[highlighted]:bg-state-crit/10"
          >
            <LogOut className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
            {t("signOut")}
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
