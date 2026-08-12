import * as Dialog from "@radix-ui/react-dialog";
import { AlertTriangle, X } from "lucide-react";
import { useState, type ReactNode } from "react";

import { Button, Input } from "./ui/primitives";
import { cn } from "../lib/utils";

/**
 * Confirmation for actions that take effect immediately, affect someone other
 * than the operator, and let that person find out by being interrupted.
 *
 * The reason is not bureaucracy. It lands in the audit trail, so months later
 * "why did this account lose its second factor on 12 August" has an answer
 * written by the person who did it rather than a shrug.
 *
 * Reserved for the consequential ones. Revoking a single session stays a
 * single click — it is small, recoverable, and a dialog there is friction
 * with nothing bought.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  subject,
  consequences,
  confirmLabel,
  tone = "danger",
  requireReason = true,
  requireCode = true,
  typeToConfirm,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  subject?: ReactNode;
  consequences: string[];
  confirmLabel: string;
  tone?: "danger" | "caution";
  requireReason?: boolean;
  requireCode?: boolean;
  /** When set, the operator must type this string exactly. */
  typeToConfirm?: string;
  onConfirm: (reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [code, setCode] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const reasonOk = !requireReason || reason.trim().length >= 10;
  const codeOk = !requireCode || code.trim().length === 6;
  const typedOk = !typeToConfirm || typed.trim() === typeToConfirm;
  const canConfirm = reasonOk && codeOk && typedOk && !busy;

  function reset() {
    setReason("");
    setCode("");
    setTyped("");
    setFailure("");
    setBusy(false);
  }

  function close(next: boolean) {
    onOpenChange(next);
    if (!next) window.setTimeout(reset, 200);
  }

  async function confirm() {
    setBusy(true);
    setFailure("");
    try {
      await onConfirm(reason.trim());
      close(false);
    } catch (cause) {
      setFailure(cause instanceof Error ? cause.message : "That action could not be completed.");
      setBusy(false);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={close}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[92vh] w-[min(34rem,94vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-panel border border-hairline-strong bg-charcoal-panel shadow-raised">
          <header className="flex items-start gap-3.5 border-b border-hairline px-6 py-4">
            <span
              className={cn(
                "grid size-10 shrink-0 place-items-center rounded-control border",
                tone === "danger"
                  ? "border-state-crit/40 bg-state-crit/10 text-state-crit"
                  : "border-state-warn/40 bg-state-warn/10 text-state-warn",
              )}
            >
              <AlertTriangle className="size-5" strokeWidth={1.75} aria-hidden="true" />
            </span>
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-[17px] font-semibold text-cream-bright">{title}</Dialog.Title>
              {subject ? <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">{subject}</Dialog.Description> : null}
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close" disabled={busy}>
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
            <ul className="flex flex-col gap-2">
              {consequences.map((line) => (
                <li key={line} className="flex gap-2.5 text-[13.5px] leading-relaxed text-sand-muted">
                  <span aria-hidden="true" className="mt-[0.55em] size-1 shrink-0 rounded-full bg-sand-muted/50" />
                  {line}
                </li>
              ))}
            </ul>

            {typeToConfirm ? (
              <div>
                <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="confirm-typed">
                  Type <span className="font-mono text-cream-bright">{typeToConfirm}</span> to continue
                </label>
                <Input id="confirm-typed" value={typed} onChange={(event) => setTyped(event.target.value)} autoComplete="off" />
              </div>
            ) : null}

            {requireReason ? (
              <div>
                <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="confirm-reason">
                  Reason
                </label>
                <Input
                  id="confirm-reason"
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  placeholder="Why is this necessary?"
                  autoComplete="off"
                />
                <p className="mt-1.5 text-xs text-sand-muted/70">
                  {reason.trim().length > 0 && !reasonOk ? "At least 10 characters" : "Stored with your name in the audit trail"}
                </p>
              </div>
            ) : null}

            {requireCode ? (
              <div className="rounded-panel border border-signal/40 bg-signal/8 px-5 py-4">
                <label className="block text-[13px] font-medium text-signal" htmlFor="confirm-code">
                  Confirm with your authenticator
                </label>
                <Input
                  id="confirm-code"
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                  inputMode="numeric"
                  placeholder="000000"
                  className="mt-2.5 w-32 text-center font-mono tracking-[0.3em]"
                  autoComplete="off"
                />
              </div>
            ) : null}

            {failure ? (
              <p role="alert" className="rounded-control border border-state-crit/50 bg-state-crit/10 px-4 py-3 text-[13px] text-state-crit">
                {failure}
              </p>
            ) : null}
          </div>

          <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-hairline px-6 py-4">
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" disabled={busy}>
                Cancel
              </Button>
            </Dialog.Close>
            <Button variant="danger" size="sm" disabled={!canConfirm} onClick={() => void confirm()}>
              {busy ? "Working…" : confirmLabel}
            </Button>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
