import * as Dialog from "@radix-ui/react-dialog";
import { Check, Copy, X } from "lucide-react";
import { useState } from "react";

import { Button, Input, NativeSelect, Panel, Tag } from "./ui/primitives";
import { PasswordField } from "./PasswordField";
import { ORGANIZATION, ROLES } from "../data/mock";
import { generatePassword, passwordStrength, useDirectory } from "../data/store";

type Handover = { name: string; email: string; password: string; roleName: string };

export function AddUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { createUser } = useDirectory();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [department, setDepartment] = useState(ORGANIZATION.name);
  const [roleSlug, setRoleSlug] = useState("viewer");
  const [password, setPassword] = useState(generatePassword);
  const [requireChange, setRequireChange] = useState(true);
  const [code, setCode] = useState("");

  // After a successful create the dialog swaps to a handover panel. The password
  // is shown exactly once, here, and never stored — the operator has to pass it
  // on before closing.
  const [handover, setHandover] = useState<Handover | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  const strongEnough = passwordStrength(password).score >= 3;
  const canSubmit = name.trim().length >= 2 && emailValid && strongEnough && code.trim().length === 6 && !busy;

  function reset() {
    setName("");
    setEmail("");
    setDepartment(ORGANIZATION.name);
    setRoleSlug("viewer");
    setPassword(generatePassword());
    setRequireChange(true);
    setCode("");
    setHandover(null);
    setCopied(false);
    setFailure("");
  }

  async function submit() {
    setBusy(true);
    setFailure("");
    try {
      const created = await createUser({ name, email, department, roleSlug, mustChangePassword: requireChange });
      setHandover({
        name: created.name,
        email: created.email,
        password,
        roleName: ROLES.find((role) => role.slug === roleSlug)?.name ?? roleSlug,
      });
    } catch (cause) {
      // The dialog stays open with everything the operator typed intact. Closing
      // it here would discard the form over a write that never landed.
      setFailure(cause instanceof Error ? cause.message : "The account could not be created.");
    } finally {
      setBusy(false);
    }
  }

  async function copyHandover() {
    if (!handover) return;
    try {
      await navigator.clipboard.writeText(`Netra sign-in\nEmail: ${handover.email}\nPassword: ${handover.password}`);
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
                {handover ? "Account created" : "Add a user"}
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">
                {handover
                  ? "Pass these details on now — the password is not shown again."
                  : "The account is active immediately. No email is sent."}
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm" aria-label="Close">
                <X className="size-4" strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Dialog.Close>
          </header>

          {handover ? (
            <>
              <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
                <Panel className="bg-charcoal-deep/50 px-5 py-4">
                  <dl className="flex flex-col gap-3">
                    <div className="flex flex-wrap items-baseline gap-3">
                      <dt className="w-20 text-[13px] text-sand-muted/70">Name</dt>
                      <dd className="text-[15px] text-cream-bright">{handover.name}</dd>
                    </div>
                    <div className="flex flex-wrap items-baseline gap-3">
                      <dt className="w-20 text-[13px] text-sand-muted/70">Email</dt>
                      <dd className="font-mono text-[13px] text-cream-bright">{handover.email}</dd>
                    </div>
                    <div className="flex flex-wrap items-baseline gap-3">
                      <dt className="w-20 text-[13px] text-sand-muted/70">Password</dt>
                      <dd className="font-mono text-[15px] font-semibold text-signal">{handover.password}</dd>
                    </div>
                    <div className="flex flex-wrap items-baseline gap-3">
                      <dt className="w-20 text-[13px] text-sand-muted/70">Role</dt>
                      <dd>
                        <Tag tone="neutral">{handover.roleName}</Tag>
                      </dd>
                    </div>
                  </dl>
                </Panel>

                <p className="rounded-control border-l-2 border-state-warn bg-state-warn/8 px-4 py-3 text-[13px] leading-relaxed text-sand-muted">
                  Deliver these over a channel that already identifies this person — in the room, or a number you hold on record. Never by
                  the same email address they are about to sign in with.
                </p>
              </div>

              <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-hairline px-6 py-4">
                <Button variant="outline" size="sm" onClick={copyHandover}>
                  {copied ? (
                    <Check className="size-3.5 text-state-ok" strokeWidth={2.5} aria-hidden="true" />
                  ) : (
                    <Copy className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  )}
                  Copy details
                </Button>
                <Button variant="ghost" size="sm" onClick={() => reset()}>
                  Add another
                </Button>
                <Button variant="primary" size="sm" onClick={() => close(false)}>
                  Done
                </Button>
              </footer>
            </>
          ) : (
            <>
              <div className="flex flex-col gap-4 overflow-y-auto px-6 py-5">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="new-name">
                      Full name
                    </label>
                    <Input id="new-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="K. Desai" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="new-email">
                      Official email
                    </label>
                    <Input
                      id="new-email"
                      type="email"
                      value={email}
                      onChange={(event) => setEmail(event.target.value)}
                      placeholder="name@gcc.gov.in"
                      className="font-mono"
                      autoComplete="off"
                    />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="new-department">
                      Department
                    </label>
                    <Input id="new-department" value={department} onChange={(event) => setDepartment(event.target.value)} />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="new-role">
                      Role
                    </label>
                    <NativeSelect
                      id="new-role"
                      value={roleSlug}
                      onChange={(event) => setRoleSlug(event.target.value)}
                      className="h-9 w-full"
                    >
                      {ROLES.filter((role) => role.slug !== "admin").map((role) => (
                        <option key={role.slug} value={role.slug}>
                          {role.name}
                        </option>
                      ))}
                    </NativeSelect>
                  </div>
                </div>

                <p className="-mt-1 text-xs text-sand-muted/65">
                  {ROLES.find((role) => role.slug === roleSlug)?.description}
                </p>

                <PasswordField value={password} onChange={setPassword} />

                <label className="flex cursor-pointer items-start gap-2.5">
                  <input
                    type="checkbox"
                    checked={requireChange}
                    onChange={(event) => setRequireChange(event.target.checked)}
                    className="mt-0.5 size-4 shrink-0 accent-[var(--color-signal)]"
                  />
                  <span className="text-[13px] text-sand-muted">
                    Require a new password at first sign-in
                    <span className="mt-0.5 block text-xs text-sand-muted/60">
                      Recommended. You will have seen this password, so it should not stay in use.
                    </span>
                  </span>
                </label>

                <div className="rounded-panel border border-signal/40 bg-signal/8 px-5 py-4">
                  <label className="block text-[13px] font-medium text-signal" htmlFor="new-code">
                    Confirm with your authenticator
                  </label>
                  <Input
                    id="new-code"
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
                <p className="text-xs text-sand-muted/60">Recorded in the audit trail.</p>
                <div className="flex gap-2">
                  <Dialog.Close asChild>
                    <Button variant="ghost" size="sm" disabled={busy}>
                      Cancel
                    </Button>
                  </Dialog.Close>
                  <Button variant="primary" size="sm" disabled={!canSubmit} onClick={() => void submit()}>
                    {busy ? "Creating…" : "Create account"}
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
