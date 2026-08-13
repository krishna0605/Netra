import { FolderSearch, KeyRound } from "lucide-react";
import { useState } from "react";

import { AuthLayout } from "./AuthLayout";
import { Avatar, Tag } from "../../components/ui/primitives";
import { CONSOLE_URL, IS_LOCAL } from "../../lib/env";
import { cn, initials } from "../../lib/utils";
import { useAuth } from "./AuthContext";
import { useT } from "../../i18n";

const REMEMBER_KEY = "netra.admin.preferInvestigation";

/**
 * Leaving for the investigator console is a full navigation to a different
 * origin in local development, and a different path in a deployment. Either
 * way the administrative session ends here, which is intended — it lives in
 * memory and should not survive leaving the workspace.
 */
function leaveForConsole() {
  window.location.assign(CONSOLE_URL);
}

/**
 * Reads as an ordinary workspace picker, not a secret door. If it felt
 * dramatic it would advertise that something valuable sits behind it.
 */
export function ChooserPage() {
  const { profile, chooseAdministration, signOut } = useAuth();
  const t = useT();
  const [remember, setRemember] = useState(() => localStorage.getItem(REMEMBER_KEY) === "1");

  function toggleRemember(next: boolean) {
    setRemember(next);
    // Safe to persist: it only ever routes somewhere *less* privileged. There
    // is deliberately no equivalent for Administration — entering it should be
    // a decision taken each time, never a default you drift into.
    if (next) localStorage.setItem(REMEMBER_KEY, "1");
    else localStorage.removeItem(REMEMBER_KEY);
  }

  return (
    <AuthLayout title={t("chooseWorkspace")} subtitle={t("chooseWorkspaceSubtitle")} width="wide">
      <div className="flex flex-col gap-5">
        {profile ? (
          <div className="flex items-center gap-3 rounded-panel border border-hairline bg-charcoal-panel px-4 py-3">
            <Avatar initials={initials(profile.displayName)} tone="accent" />
            <div className="min-w-0 flex-1">
              <p className="truncate text-[13.5px] font-medium text-cream-bright">{profile.displayName}</p>
              <p className="truncate font-mono text-[11.5px] text-sand-muted/70">
                {profile.email} · {profile.organizationName}
              </p>
            </div>
            <Tag tone="ok">{t("verified")}</Tag>
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          <WorkspaceCard
            icon={FolderSearch}
            name={t("investigationConsole")}
            description={t("investigationConsoleBlurb")}
            action={t("open")}
            // Locally this is a separate dev server. Naming it means a console
            // that is not running reads as "nothing at that address" rather
            // than as a broken button.
            footnote={IS_LOCAL ? CONSOLE_URL.replace(/^https?:\/\//, "") : undefined}
            onSelect={leaveForConsole}
          />
          <WorkspaceCard
            elevated
            icon={KeyRound}
            name={t("administration")}
            description={t("administrationBlurb")}
            note={t("elevatedPrivileges")}
            action={t("open")}
            onSelect={chooseAdministration}
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <label className="flex cursor-pointer items-center gap-2.5 text-[12.5px] text-sand-muted">
            <input
              type="checkbox"
              checked={remember}
              onChange={(event) => toggleRemember(event.target.checked)}
              className="size-4 shrink-0 accent-[var(--color-signal)]"
            />
            {t("alwaysInvestigation")}
          </label>
          <button
            type="button"
            onClick={() => void signOut()}
            className="text-[12.5px] text-sand-muted/70 underline underline-offset-2 hover:text-cream-bright"
          >
            {t("signOut")}
          </button>
        </div>
      </div>
    </AuthLayout>
  );
}

function WorkspaceCard({
  icon: Icon,
  name,
  description,
  note,
  footnote,
  action,
  elevated = false,
  onSelect,
}: {
  icon: typeof KeyRound;
  name: string;
  description: string;
  note?: string;
  footnote?: string;
  action: string;
  elevated?: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "group flex flex-col gap-3 rounded-panel border px-5 py-5 text-left transition-colors",
        elevated
          ? "border-signal/60 bg-signal/8 hover:border-signal"
          : "border-hairline-strong bg-charcoal-panel hover:border-sand-muted/50",
      )}
    >
      <span
        className={cn(
          "grid size-10 place-items-center rounded-control border",
          elevated ? "border-signal/50 bg-signal/12 text-signal" : "border-hairline-strong text-sand-muted",
        )}
      >
        <Icon className="size-5" strokeWidth={1.75} aria-hidden="true" />
      </span>

      <span className="text-[16px] font-semibold text-cream-bright">{name}</span>
      <span className="text-[13px] leading-relaxed text-sand-muted/85">{description}</span>

      <span className="mt-auto pt-1">
        {note ? <Tag tone="accent">{note}</Tag> : null}
        {footnote ? <span className="block font-mono text-[11px] text-sand-muted/70">{footnote}</span> : null}
      </span>

      <span
        className={cn(
          "mt-1 rounded-control px-3 py-2 text-center text-[13px] font-semibold transition-colors",
          elevated
            ? "bg-signal text-charcoal-deep group-hover:bg-signal-dark"
            : "border border-hairline-strong text-cream-primary group-hover:border-signal/60 group-hover:text-signal",
        )}
      >
        {action}
      </span>
    </button>
  );
}
