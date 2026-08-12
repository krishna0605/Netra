import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useMemo, useState } from "react";

import { Button, Input, NativeSelect } from "./ui/primitives";
import { PERMISSIONS } from "../data/mock";
import { RiskBadge } from "./common";
import { cn } from "../lib/utils";
import { useDirectory } from "../data/store";
import type { AdminUser, PermissionKey } from "../data/types";

/** Common windows, plus an explicit no-expiry that has to be chosen. */
const WINDOWS = [
  { label: "7 days", days: 7 },
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "No expiry", days: 0 },
];

export function GrantPermissionDialog({
  user,
  open,
  onOpenChange,
}: {
  user: AdminUser;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { grantPermission } = useDirectory();

  const available = useMemo(
    () => PERMISSIONS.filter((permission) => !user.permissions.some((held) => held.key === permission.key && held.source === "granted")),
    [user.permissions],
  );

  const [key, setKey] = useState<PermissionKey | "">("");
  const [days, setDays] = useState(30);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const permission = PERMISSIONS.find((entry) => entry.key === key);

  // High-risk permissions always carry a written justification. For the rest a
  // reason is still asked for, just not enforced — the audit entry reads better
  // with one, and most people write it if the field is there.
  const reasonRequired = permission?.risk === "high";
  const reasonOk = !reasonRequired || reason.trim().length >= 10;
  const canSubmit = Boolean(key) && reasonOk && !busy;

  function reset() {
    setKey("");
    setDays(30);
    setReason("");
    setFailure("");
    setBusy(false);
  }

  function close(next: boolean) {
    onOpenChange(next);
    if (!next) window.setTimeout(reset, 200);
  }

  async function submit() {
    if (!key) return;
    setBusy(true);
    setFailure("");
    try {
      const expiresAt = days > 0 ? new Date(Date.now() + days * 864e5).toISOString() : null;
      await grantPermission(user.id, key, expiresAt, reason.trim() || `Granted ${key} to ${user.name}.`);
      close(false);
    } catch (cause) {
      setFailure(cause instanceof Error ? cause.message : "The permission could not be granted.");
      setBusy(false);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={close}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[92vh] w-[min(36rem,94vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-panel border border-hairline-strong bg-charcoal-panel shadow-raised">
          <header className="flex items-start justify-between gap-4 border-b border-hairline px-6 py-4">
            <div className="min-w-0">
              <Dialog.Title className="text-lg font-semibold text-cream-bright">Grant a permission</Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">
                In addition to what {user.name} already holds through their role.
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close" disabled={busy}>
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
            <div className="flex flex-col gap-2">
              <span className="text-[13px] text-sand-muted/80">Permission</span>
              <div className="flex flex-col gap-1.5">
                {available.map((entry) => (
                  <button
                    key={entry.key}
                    type="button"
                    onClick={() => setKey(entry.key)}
                    aria-pressed={key === entry.key}
                    aria-label={`Grant ${entry.key} — ${entry.risk} risk`}
                    className={cn(
                      "flex items-start gap-3 rounded-control border px-3.5 py-2.5 text-left transition-colors",
                      key === entry.key ? "border-signal bg-signal/8" : "border-hairline hover:border-hairline-strong",
                    )}
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block font-mono text-[13px] text-cream-bright">{entry.key}</span>
                      <span className="mt-0.5 block text-xs text-sand-muted/75">{entry.description}</span>
                    </span>
                    <RiskBadge risk={entry.risk} />
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="grant-window">
                Expires after
              </label>
              <NativeSelect
                id="grant-window"
                value={days}
                onChange={(event) => setDays(Number(event.target.value))}
                className="w-full"
              >
                {WINDOWS.map((window) => (
                  <option key={window.label} value={window.days}>
                    {window.label}
                  </option>
                ))}
              </NativeSelect>
              {days === 0 ? (
                <p className="mt-1.5 text-xs text-state-warn">
                  A permission with no expiry has to be withdrawn by hand, and usually is not. Prefer a window.
                </p>
              ) : null}
            </div>

            <div>
              <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="grant-reason">
                Reason {reasonRequired ? "" : <span className="text-sand-muted/70">(optional)</span>}
              </label>
              <Input
                id="grant-reason"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="What is this needed for?"
                autoComplete="off"
              />
              {reasonRequired ? (
                <p className="mt-1.5 text-xs text-state-warn">
                  {permission?.key} is high-risk, so a written reason is required.
                </p>
              ) : null}
            </div>

            {failure ? (
              <p role="alert" className="rounded-control border border-state-crit/50 bg-state-crit/10 px-4 py-3 text-[13px] text-state-crit">
                {failure}
              </p>
            ) : null}
          </div>

          <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-hairline px-6 py-4">
            <p className="text-xs text-sand-muted/70">Recorded in the audit trail.</p>
            <div className="flex gap-2">
              <Dialog.Close asChild>
                <Button variant="ghost" size="sm" disabled={busy}>
                  Cancel
                </Button>
              </Dialog.Close>
              <Button variant="primary" size="sm" disabled={!canSubmit} onClick={() => void submit()}>
                {busy ? "Granting…" : "Grant permission"}
              </Button>
            </div>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
