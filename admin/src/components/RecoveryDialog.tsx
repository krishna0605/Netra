import * as Dialog from "@radix-ui/react-dialog";
import { Check, X } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

import { Badge, Button, Input, Textarea } from "./ui/primitives";
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
 * See plan §7 — this dialog does the decision tree for the operator.
 */
const PATHS: RecoveryPath[] = [
  {
    id: "email",
    rank: "Preferred",
    name: "Send recovery email",
    blurb: "Supabase mails a reset link. Nobody but the account holder ever sees a credential.",
    endpoint: "POST /auth/v1/recover",
  },
  {
    id: "link",
    rank: "Recommended",
    name: "Generate recovery link",
    blurb: "Produces a single-use link, shown once. Deliver it through a channel that already verifies this person.",
    endpoint: "POST /auth/v1/admin/generate_link",
  },
  {
    id: "force",
    rank: "Last resort",
    name: "Set temporary password",
    blurb: "You will briefly hold their credential. Every session is revoked and a change is forced at next sign-in.",
    endpoint: "PUT /auth/v1/admin/users/{id}",
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
  // The email path is gated on the same capability flag the backend already
  // publishes, so the UI degrades exactly the way the platform does.
  const emailEnabled = CAPABILITIES.find((flag) => flag.key === "password_recovery")?.state === "available";
  const [selected, setSelected] = useState<PathId>("link");
  const [reason, setReason] = useState("");
  const [code, setCode] = useState("");

  const reasonValid = reason.trim().length >= 10 && reason.trim().length <= 1000;
  const codeValid = code.trim().length === 6;
  const canSubmit = reasonValid && codeValid;

  function submit() {
    const path = PATHS.find((entry) => entry.id === selected)!;
    toast.success(`${path.name} — preview only`, {
      description: "No backend is attached. In phase 2 this calls the Supabase Auth Admin API and appends to the audit chain.",
    });
    onOpenChange(false);
    setReason("");
    setCode("");
  }

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[92vh] w-[min(56rem,94vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden border border-hairline-strong bg-charcoal-panel shadow-2xl">
          <header className="flex items-start justify-between gap-4 border-b border-hairline px-5 py-4">
            <div className="min-w-0">
              <Dialog.Title className="text-base font-semibold text-cream-bright">Restore access for {user.name}</Dialog.Title>
              <Dialog.Description className="mt-1 font-mono text-xs text-sand-muted/80">
                {user.email} · {user.status.replace("_", " ")}
                {user.mfa === "factor_lost" ? " · authenticator lost" : ""}
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close">
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          <div className="flex flex-col gap-4 overflow-y-auto px-5 py-4">
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
                      "flex flex-col items-start gap-2 border px-3.5 py-3 text-left transition-colors",
                      disabled && "cursor-not-allowed border-hairline opacity-50",
                      !disabled && active && path.id === "force" && "border-state-crit bg-state-crit/10",
                      !disabled && active && path.id !== "force" && "border-state-ok bg-state-ok/10",
                      !disabled && !active && "border-hairline hover:border-hairline-strong",
                    )}
                  >
                    <span className="flex w-full items-center justify-between gap-2">
                      <Badge tone={disabled ? "neutral" : path.id === "force" ? "crit" : "ok"}>
                        {disabled ? "Unavailable" : path.rank}
                      </Badge>
                      {active && !disabled ? <Check className="size-3.5 text-signal" strokeWidth={2.5} aria-hidden="true" /> : null}
                    </span>
                    <span className="font-mono text-[13px] font-semibold text-cream-bright">{path.name}</span>
                    <span className="text-[11px] leading-relaxed text-sand-muted/80">{path.blurb}</span>
                    <span className="mt-auto font-mono text-[10px] break-all text-sand-muted/60">
                      {disabled ? "requires an approved custom SMTP domain — capability password_recovery is disabled" : path.endpoint}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="border border-signal/50 bg-signal/8 px-4 py-3.5">
              <p className="font-mono text-[10px] tracking-[0.12em] text-signal uppercase">Confirm with your authenticator</p>
              <div className="mt-3 flex flex-wrap items-start gap-3">
                <Input
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                  inputMode="numeric"
                  placeholder="000000"
                  aria-label="Six digit authenticator code"
                  className="w-32 text-center font-mono tracking-[0.35em]"
                />
                <div className="min-w-[16rem] flex-1">
                  <Textarea
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    rows={2}
                    placeholder="Why is this recovery necessary? (10–1000 characters)"
                    aria-label="Reason for recovery"
                  />
                  <p className="mt-1 font-mono text-[10px] text-sand-muted/60">
                    {reason.trim().length}/1000{reason.trim().length > 0 && !reasonValid ? " · at least 10 characters" : ""}
                  </p>
                </div>
              </div>
            </div>

            {user.mfa === "factor_lost" ? (
              <p className="border-l-2 border-state-warn bg-state-warn/8 px-3.5 py-2.5 text-[11px] text-sand-muted">
                This account's MFA factor is also lost. Resetting the factor is a separate action with its own identity verification — see{" "}
                <span className="font-mono text-cream-primary">docs/MFA_RECOVERY_RUNBOOK.md</span>.
              </p>
            ) : null}
          </div>

          <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-hairline px-5 py-3.5">
            <p className="font-mono text-[10px] text-sand-muted/60">Recorded in the admin audit chain with your identity and reason.</p>
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
