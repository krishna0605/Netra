import * as Dialog from "@radix-ui/react-dialog";
import { Check, X } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

import { Button, Input, Tag, Textarea } from "./ui/primitives";
import { CAPABILITIES } from "../data/mock";
import { cn } from "../lib/utils";
import type { AdminUser } from "../data/types";

type PathId = "email" | "link" | "force";

type RecoveryPath = {
  id: PathId;
  rank: string;
  name: string;
  blurb: string;
  endpoint: string;
};

/**
 * Ordered by how little trust each path requires the administrator to hold.
 * The email path never exposes a credential; the force path briefly does.
 */
const PATHS: RecoveryPath[] = [
  {
    id: "email",
    rank: "Preferred",
    name: "Email a reset link",
    blurb: "The account holder sets their own password. Nobody else ever sees a credential.",
    endpoint: "Sent to the registered address",
  },
  {
    id: "link",
    rank: "Recommended",
    name: "Generate a one-time link",
    blurb: "Produces a single-use link, shown once. Deliver it through a channel that already verifies this person.",
    endpoint: "Expires 60 minutes after issue",
  },
  {
    id: "force",
    rank: "Last resort",
    name: "Set a temporary password",
    blurb: "You will briefly hold their credential. Every session is revoked and a change is forced at next sign-in.",
    endpoint: "Generated automatically and shown once",
  },
];

export function RecoveryDialog({
  user,
  open,
  onOpenChange,
}: {
  user: AdminUser;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const emailEnabled = CAPABILITIES.find((flag) => flag.key === "password_recovery")?.state === "available";
  const [selected, setSelected] = useState<PathId>("link");
  const [reason, setReason] = useState("");
  const [code, setCode] = useState("");

  const reasonValid = reason.trim().length >= 10 && reason.trim().length <= 1000;
  const codeValid = code.trim().length === 6;
  const canSubmit = reasonValid && codeValid;

  function submit() {
    const path = PATHS.find((entry) => entry.id === selected)!;
    toast.success(path.name, { description: `Recorded against ${user.name} in the audit trail.` });
    onOpenChange(false);
    setReason("");
    setCode("");
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[92vh] w-[min(56rem,94vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-panel border border-hairline-strong bg-charcoal-panel shadow-raised">
          <header className="flex items-start justify-between gap-4 border-b border-hairline px-6 py-4">
            <div className="min-w-0">
              <Dialog.Title className="text-lg font-semibold text-cream-bright">Restore access for {user.name}</Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">
                <span className="font-mono text-xs">{user.email}</span>
                {user.mfa === "factor_lost" ? " · authenticator lost" : ""}
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close">
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          <div className="flex flex-col gap-5 overflow-y-auto px-6 py-5">
            <div className="grid gap-3 md:grid-cols-3">
              {PATHS.map((path) => {
                const disabled = path.id === "email" && !emailEnabled;
                const active = selected === path.id;
                return (
                  <button
                    key={path.id}
                    type="button"
                    disabled={disabled}
                    onClick={() => setSelected(path.id)}
                    aria-pressed={active}
                    className={cn(
                      "flex flex-col items-start gap-2.5 rounded-panel border px-4 py-4 text-left transition-colors",
                      disabled && "cursor-not-allowed border-hairline opacity-45",
                      !disabled && active && path.id === "force" && "border-state-crit bg-state-crit/8",
                      !disabled && active && path.id !== "force" && "border-state-ok bg-state-ok/8",
                      !disabled && !active && "border-hairline hover:border-hairline-strong",
                    )}
                  >
                    <span className="flex w-full items-center justify-between gap-2">
                      <Tag tone={disabled ? "neutral" : path.id === "force" ? "crit" : "ok"}>{disabled ? "Unavailable" : path.rank}</Tag>
                      {active && !disabled ? <Check className="size-4 text-signal" strokeWidth={2.5} aria-hidden="true" /> : null}
                    </span>
                    <span className="text-[15px] font-semibold text-cream-bright">{path.name}</span>
                    <span className="text-[13px] leading-relaxed text-sand-muted/80">{path.blurb}</span>
                    <span className="mt-auto pt-1 text-xs text-sand-muted/55">
                      {disabled ? "Requires an approved mail domain for this deployment" : path.endpoint}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="rounded-panel border border-signal/40 bg-signal/8 px-5 py-4">
              <p className="text-[13px] font-medium text-signal">Confirm with your authenticator</p>
              <div className="mt-3 flex flex-wrap items-start gap-3">
                <Input
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                  inputMode="numeric"
                  placeholder="000000"
                  aria-label="Six digit authenticator code"
                  className="w-32 text-center font-mono tracking-[0.3em]"
                />
                <div className="min-w-[16rem] flex-1">
                  <Textarea
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    rows={2}
                    placeholder="Why is this recovery necessary?"
                    aria-label="Reason for recovery"
                  />
                  <p className="mt-1.5 text-xs text-sand-muted/60">
                    {reason.trim().length > 0 && !reasonValid ? "At least 10 characters" : `${reason.trim().length} of 1000 characters`}
                  </p>
                </div>
              </div>
            </div>

            {user.mfa === "factor_lost" ? (
              <p className="rounded-control border-l-2 border-state-warn bg-state-warn/8 px-4 py-3 text-[13px] text-sand-muted">
                This account's authenticator is also lost. Resetting the factor is a separate action with its own identity verification.
              </p>
            ) : null}
          </div>

          <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-hairline px-6 py-4">
            <p className="text-xs text-sand-muted/60">Recorded in the audit trail with your identity and reason.</p>
            <div className="flex gap-2">
              <Dialog.Close asChild>
                <Button variant="ghost" size="sm">
                  Cancel
                </Button>
              </Dialog.Close>
              <Button variant="primary" size="sm" disabled={!canSubmit} onClick={submit}>
                {PATHS.find((path) => path.id === selected)?.name}
              </Button>
            </div>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
