import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useState } from "react";

import { Button, Input, NativeSelect } from "./ui/primitives";
import { useDirectory } from "../data/store";

/**
 * Standard roles are immutable, so customising means cloning. Starting from an
 * existing role rather than an empty one means a new role always begins from a
 * known-good set instead of whatever someone remembered to tick.
 */
export function CloneRoleDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (slug: string) => void;
}) {
  const { roles, createRole } = useDirectory();

  const [baseSlug, setBaseSlug] = useState("analyst");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const base = roles.find((role) => role.slug === baseSlug);
  const canSubmit = name.trim().length >= 3 && !busy;

  function reset() {
    setBaseSlug("analyst");
    setName("");
    setDescription("");
    setFailure("");
    setBusy(false);
  }

  function close(next: boolean) {
    onOpenChange(next);
    if (!next) window.setTimeout(reset, 200);
  }

  async function submit() {
    setBusy(true);
    setFailure("");
    try {
      const created = await createRole({ name, description, baseSlug });
      onCreated?.(created.slug);
      close(false);
    } catch (cause) {
      setFailure(cause instanceof Error ? cause.message : "The role could not be created.");
      setBusy(false);
    }
  }

  return (
    <Dialog.Root open={open} onOpenChange={close}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/70 backdrop-blur-[2px]" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[92vh] w-[min(34rem,94vw)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-panel border border-hairline-strong bg-charcoal-panel shadow-raised">
          <header className="flex items-start justify-between gap-4 border-b border-hairline px-6 py-4">
            <div className="min-w-0">
              <Dialog.Title className="text-lg font-semibold text-cream-bright">Clone a role</Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">
                The new role starts with the same permissions and can then be adjusted.
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close" disabled={busy}>
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
            <div>
              <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="clone-base">
                Start from
              </label>
              <NativeSelect id="clone-base" value={baseSlug} onChange={(event) => setBaseSlug(event.target.value)} className="w-full">
                {roles.map((role) => (
                  <option key={role.slug} value={role.slug}>
                    {role.name} — {role.permissions.length} permissions
                  </option>
                ))}
              </NativeSelect>
              {base ? <p className="mt-1.5 text-xs text-sand-muted/70">{base.description}</p> : null}
            </div>

            <div>
              <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="clone-name">
                Name
              </label>
              <Input
                id="clone-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Evidence Clerk"
                autoComplete="off"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="clone-description">
                Description <span className="text-sand-muted/55">(optional)</span>
              </label>
              <Input
                id="clone-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder="Who is this role for?"
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
            <Button variant="primary" size="sm" disabled={!canSubmit} onClick={() => void submit()}>
              {busy ? "Creating…" : "Create role"}
            </Button>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
