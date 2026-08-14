import * as Dialog from "@radix-ui/react-dialog";
import { Search, X } from "lucide-react";
import { useMemo, useState } from "react";

import { Avatar, Button, Input } from "./ui/primitives";
import { cn, initials } from "../lib/utils";
import { useDirectory } from "../data/store";
import { useAuth } from "../features/auth/AuthContext";

/**
 * The most consequential action in the console: it demotes the person doing it.
 *
 * Four independent conditions must be satisfied — a chosen recipient, the
 * organization name typed exactly, a written reason, and an authenticator code
 * — because there is no undo that does not require the new owner's
 * cooperation.
 */
export function OwnerTransferDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { users, organization, transferOwnership } = useDirectory();
  const { stepUp } = useAuth();

  const [query, setQuery] = useState("");
  const [targetId, setTargetId] = useState<number | null>(null);
  const [typed, setTyped] = useState("");
  const [reason, setReason] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const candidates = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return users
      .filter((user) => !user.isOwner && user.status === "active")
      .filter((user) => !needle || user.name.toLowerCase().includes(needle) || user.email.toLowerCase().includes(needle));
  }, [users, query]);

  const target = users.find((user) => user.id === targetId);
  const current = users.find((user) => user.isOwner);

  const canSubmit =
    Boolean(target) && typed.trim() === organization.name && reason.trim().length >= 10 && code.trim().length === 6 && !busy;

  function reset() {
    setQuery("");
    setTargetId(null);
    setTyped("");
    setReason("");
    setCode("");
    setFailure("");
    setBusy(false);
  }

  function close(next: boolean) {
    onOpenChange(next);
    if (!next) window.setTimeout(reset, 200);
  }

  async function submit() {
    if (!targetId) return;
    setBusy(true);
    setFailure("");
    try {
      const problem = await stepUp(code);
      if (problem) {
        setFailure(problem);
        return;
      }
      await transferOwnership(targetId, reason.trim());
      close(false);
    } catch (cause) {
      setFailure(cause instanceof Error ? cause.message : "Ownership could not be transferred.");
      setBusy(false);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={close}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[92vh] w-[min(38rem,94vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-panel border border-state-crit/50 bg-charcoal-panel shadow-raised">
          <header className="flex items-start justify-between gap-4 border-b border-hairline px-6 py-4">
            <div className="min-w-0">
              <Dialog.Title className="text-lg font-semibold text-cream-bright">Transfer ownership</Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">
                {current ? `${current.name} will become an administrator.` : "The current owner will be demoted."}
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close" disabled={busy}>
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
            <ul className="flex flex-col gap-2">
              {[
                "The new owner gains full authority over this organization, including the ability to transfer it onward.",
                "You will keep administrative access but lose ownership.",
                "This cannot be undone without the new owner's cooperation.",
              ].map((line) => (
                <li key={line} className="flex gap-2.5 text-[13.5px] leading-relaxed text-sand-muted">
                  <span aria-hidden="true" className="mt-[0.55em] size-1 shrink-0 rounded-full bg-state-crit/70" />
                  {line}
                </li>
              ))}
            </ul>

            <div>
              <span className="mb-1.5 block text-[13px] text-sand-muted/80">New owner</span>
              <div className="relative mb-2">
                <Search
                  className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-sand-muted/70"
                  strokeWidth={1.75}
                  aria-hidden="true"
                />
                <Input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search active accounts"
                  className="pl-9"
                  aria-label="Search for the new owner"
                />
              </div>

              <div className="max-h-44 overflow-y-auto rounded-control border border-hairline">
                {candidates.length === 0 ? (
                  <p className="px-4 py-6 text-center text-[13px] text-sand-muted/70">No eligible accounts.</p>
                ) : (
                  candidates.map((user) => (
                    <button
                      key={user.id}
                      type="button"
                      onClick={() => setTargetId(user.id)}
                      aria-pressed={targetId === user.id}
                      className={cn(
                        "flex w-full items-center gap-3 border-b border-hairline px-3.5 py-2.5 text-left transition-colors last:border-b-0",
                        targetId === user.id ? "bg-signal/10" : "hover:bg-cream-primary/5",
                      )}
                    >
                      <Avatar initials={initials(user.name)} tone={targetId === user.id ? "accent" : "neutral"} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[13.5px] text-cream-bright">{user.name}</span>
                        <span className="block truncate font-mono text-[11.5px] text-sand-muted/70">{user.email}</span>
                      </span>
                    </button>
                  ))
                )}
              </div>
            </div>

            <div>
              <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="transfer-typed">
                Type <span className="font-mono text-cream-bright">{organization.name}</span> to continue
              </label>
              <Input id="transfer-typed" value={typed} onChange={(event) => setTyped(event.target.value)} autoComplete="off" />
            </div>

            <div>
              <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="transfer-reason">
                Reason
              </label>
              <Input
                id="transfer-reason"
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                placeholder="Why is ownership moving?"
                autoComplete="off"
              />
            </div>

            <div className="rounded-panel border border-signal/40 bg-signal/8 px-5 py-4">
              <label className="block text-[13px] font-medium text-signal" htmlFor="transfer-code">
                Confirm with your authenticator
              </label>
              <Input
                id="transfer-code"
                value={code}
                onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                inputMode="numeric"
                placeholder="000000"
                className="mt-2.5 w-32 text-center font-mono tracking-[0.3em]"
                autoComplete="off"
              />
            </div>

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
            <Button variant="danger" size="sm" disabled={!canSubmit} onClick={() => void submit()}>
              {busy ? "Transferring…" : target ? `Transfer to ${target.name}` : "Transfer ownership"}
            </Button>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
