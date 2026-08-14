import * as Dialog from "@radix-ui/react-dialog";
import { Check, Copy, X } from "lucide-react";
import { useState } from "react";

import { Button, Input, Panel } from "./ui/primitives";
import { PasswordField } from "./PasswordField";
import { generatePassword, passwordStrength, useDirectory } from "../data/store";
import type { AdminUser } from "../data/types";

export function PasswordDialog({
  user,
  open,
  onOpenChange,
}: {
  user: AdminUser;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { setPassword } = useDirectory();

  const [password, setPasswordValue] = useState(generatePassword);
  const [reason, setReason] = useState("");
  const [code, setCode] = useState("");
  const [issued, setIssued] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const reasonValid = reason.trim().length >= 10;
  const canSubmit = passwordStrength(password).score >= 3 && reasonValid && code.trim().length === 6 && !busy;

  function reset() {
    setPasswordValue(generatePassword());
    setReason("");
    setCode("");
    setIssued(null);
    setCopied(false);
    setFailure("");
  }

  async function submit() {
    setBusy(true);
    setFailure("");
    try {
      const applied = await setPassword({ userId: user.id, reason: reason.trim(), password });
      // Hand over what the server applied, not what this dialog proposed. The
      // server may have generated its own, and passing on the wrong one gives
      // an officer a credential that does not work.
      setIssued(applied);
    } catch (cause) {
      setFailure(cause instanceof Error ? cause.message : "The password could not be replaced.");
    } finally {
      setBusy(false);
    }
  }

  async function copyDetails() {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(`Netra sign-in\nEmail: ${user.email}\nPassword: ${issued}`);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // Clipboard unavailable — the credentials are on screen.
    }
  }

  function close(next: boolean) {
    onOpenChange(next);
    if (!next) window.setTimeout(reset, 200);
  }

  return (
    <Dialog.Root open={open} onOpenChange={close}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[92vh] w-[min(38rem,94vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-panel border border-hairline-strong bg-charcoal-panel shadow-raised">
          <header className="flex items-start justify-between gap-4 border-b border-hairline px-6 py-4">
            <div className="min-w-0">
              <Dialog.Title className="text-lg font-semibold text-cream-bright">
                {issued ? "Password replaced" : `Set a password for ${user.name}`}
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">
                {issued ? "Pass this on now — it is not shown again." : <span className="font-mono text-xs">{user.email}</span>}
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close">
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          {issued ? (
            <>
              <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
                <Panel className="bg-charcoal-deep/50 px-5 py-4">
                  <dl className="flex flex-col gap-3">
                    <div className="flex flex-wrap items-baseline gap-3">
                      <dt className="w-20 text-[13px] text-sand-muted/70">Email</dt>
                      <dd className="font-mono text-[13px] text-cream-bright">{user.email}</dd>
                    </div>
                    <div className="flex flex-wrap items-baseline gap-3">
                      <dt className="w-20 text-[13px] text-sand-muted/70">Password</dt>
                      <dd className="font-mono text-[15px] font-semibold text-signal">{issued}</dd>
                    </div>
                  </dl>
                </Panel>
                <ul className="flex flex-col gap-1.5 text-[13px] text-sand-muted">
                  <li>· Every existing session has been ended.</li>
                  <li>· Recorded in the audit trail with your reason.</li>
                </ul>
              </div>
              <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-hairline px-6 py-4">
                <Button variant="outline" size="sm" onClick={copyDetails}>
                  {copied ? (
                    <Check className="size-3.5 text-state-ok" strokeWidth={2.5} aria-hidden="true" />
                  ) : (
                    <Copy className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  )}
                  Copy details
                </Button>
                <Button variant="primary" size="sm" onClick={() => close(false)}>
                  Done
                </Button>
              </footer>
            </>
          ) : (
            <>
              <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
                <PasswordField value={password} onChange={setPasswordValue} label="New password" />

                {/* Two checkboxes stood here. "Require a new password at their
                    next sign-in" promised something nothing enforces, and
                    ending sessions was offered as a choice when the server now
                    always does it — a reset that leaves an old session signed
                    in has locked nobody out, which is the whole point of one. */}
                <p className="rounded-panel border border-[color:var(--color-control-edge)] bg-cream-primary/4 px-4 py-3 text-[13px] leading-relaxed text-sand-muted/70">
                  Every session this account has open will end. They will need the new password to sign in again.
                </p>

                <div>
                  <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="password-reason">
                    Reason
                  </label>
                  <Input
                    id="password-reason"
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    placeholder="Why is this necessary?"
                  />
                  <p className="mt-1.5 text-xs text-sand-muted/70">
                    {reason.trim().length > 0 && !reasonValid ? "At least 10 characters" : "Stored with your name in the audit trail"}
                  </p>
                </div>

                <div className="rounded-panel border border-signal/40 bg-signal/8 px-5 py-4">
                  <label className="block text-[13px] font-medium text-signal" htmlFor="password-code">
                    Confirm with your authenticator
                  </label>
                  <Input
                    id="password-code"
                    value={code}
                    onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                    inputMode="numeric"
                    placeholder="000000"
                    className="mt-2.5 w-32 text-center font-mono tracking-[0.3em]"
                    autoComplete="off"
                  />
                </div>

                {failure ? (
                  <p
                    role="alert"
                    className="rounded-control border border-state-crit/50 bg-state-crit/10 px-4 py-3 text-[13px] text-state-crit"
                  >
                    {failure}
                  </p>
                ) : null}
              </div>

              <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-hairline px-6 py-4">
                <p className="text-xs text-sand-muted/70">You will see this password once.</p>
                <div className="flex gap-2">
                  <Dialog.Close asChild>
                    <Button variant="ghost" size="sm" disabled={busy}>
                      Cancel
                    </Button>
                  </Dialog.Close>
                  <Button variant="primary" size="sm" disabled={!canSubmit} onClick={() => void submit()}>
                    {busy ? "Applying…" : "Set password"}
                  </Button>
                </div>
              </footer>
            </>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
