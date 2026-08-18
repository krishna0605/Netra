import * as Dialog from "@radix-ui/react-dialog";
import { Check, Copy, X } from "lucide-react";
import { useState } from "react";

import { Button, Input, NativeSelect, Panel, Tag } from "./ui/primitives";
import { useDirectory } from "../data/store";
import { useAuth } from "../features/auth/AuthContext";

type Handover = { name: string; email: string; password: string; roleName: string };

// Mirrors _MIN_REASON in backend/apps/forensics/services/admin_users.py. Kept
// in one named place so the console and the server cannot drift apart silently.
const REASON_MINIMUM = 10;

// Netra ships two roles. Investigator is the safer landing point for a new
// account, so it is what the dialog opens on.
const DEFAULT_ROLE_SLUG = "investigator";

export function AddUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { createUser, roles, organization } = useDirectory();
  const { stepUp } = useAuth();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [department, setDepartment] = useState(organization.name);
  const [roleSlug, setRoleSlug] = useState(DEFAULT_ROLE_SLUG);
  const [reason, setReason] = useState("");
  const [code, setCode] = useState("");

  // After a successful create the dialog swaps to a handover panel. The password
  // is shown exactly once, here, and never stored — the operator has to pass it
  // on before closing.
  const [handover, setHandover] = useState<Handover | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");

  const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  // The reason floor matches the server's, so the button is disabled rather
  // than the write refused after the operator has filled everything in. The
  // floor is stated in the UI as well — a disabled button that will not say
  // what it is waiting for reads as a broken console.
  const reasonValid = reason.trim().length >= REASON_MINIMUM;
  const canSubmit =
    name.trim().length >= 2 && emailValid && reasonValid && code.trim().length === 6 && !busy;

  // What the operator still has to do, in the order the fields appear.
  const blocking = [
    name.trim().length >= 2 ? "" : "a full name",
    emailValid ? "" : "a valid email address",
    reasonValid ? "" : `a reason of at least ${REASON_MINIMUM} characters`,
    code.trim().length === 6 ? "" : "the 6-digit authenticator code",
  ].filter(Boolean);

  function reset() {
    setName("");
    setEmail("");
    setDepartment(organization.name);
    setRoleSlug(DEFAULT_ROLE_SLUG);
    setReason("");
    setCode("");
    setHandover(null);
    setCopied(false);
    setFailure("");
  }

  async function submit() {
    setBusy(true);
    setFailure("");
    try {
      const problem = await stepUp(code);
      if (problem) {
        setFailure(problem);
        return;
      }
      const { created, password: applied } = await createUser({
        name,
        email,
        department,
        roleSlug,
        reason: reason.trim(),
      });
      setHandover({
        name: created.name,
        email: created.email,
        // What the server applied, not what this dialog proposed.
        password: applied,
        roleName: roles.find((role) => role.slug === roleSlug)?.name ?? roleSlug,
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
                {handover ? (handover.password ? "Account created" : "Invitation sent") : "Add a user"}
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-[13px] text-sand-muted/80">
                {handover
                  ? (handover.password ? "Pass these details on now — the password is not shown again." : "The officer must use the expiring invitation and enroll MFA before entering Netra.")
                  : "Netra sends an expiring invitation when approved email delivery is enabled."}
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
                    {handover.password ? <div className="flex flex-wrap items-baseline gap-3">
                      <dt className="w-20 text-[13px] text-sand-muted/70">Temporary password</dt>
                      <dd className="font-mono text-[15px] font-semibold text-signal">{handover.password}</dd>
                    </div> : null}
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
                {handover.password ? <Button variant="outline" size="sm" onClick={copyHandover}>
                  {copied ? (
                    <Check className="size-3.5 text-state-ok" strokeWidth={2.5} aria-hidden="true" />
                  ) : (
                    <Copy className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                  )}
                  Copy details
                </Button> : null}
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
                      {roles.map((role) => (
                        <option key={role.slug} value={role.slug}>
                          {role.name}
                        </option>
                      ))}
                    </NativeSelect>
                  </div>
                </div>

                <p className="-mt-1 text-xs text-sand-muted/70">
                  {roles.find((role) => role.slug === roleSlug)?.description}
                </p>

                <p className="rounded-panel border border-[color:var(--color-control-edge)] bg-cream-primary/4 px-4 py-3 text-[13px] leading-relaxed text-sand-muted/70">
                  Netra generates the temporary credential on the server. The officer must replace it at first sign-in.
                </p>
                <div>
                  <label className="block text-[13px] font-medium text-sand" htmlFor="new-reason">
                    Reason
                  </label>
                  <Input
                    id="new-reason"
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    placeholder="Why this account is being created"
                    className="mt-2"
                    autoComplete="off"
                  />
                  <p className="mt-1.5 flex items-center justify-between gap-3 text-xs text-sand-muted/70">
                    <span>
                      Sealed into the audit trail. It is what answers &ldquo;why&rdquo; when someone reads this back in a
                      year.
                    </span>
                    <span
                      className={
                        reasonValid
                          ? "shrink-0 tabular-nums text-sand-muted/60"
                          : "shrink-0 tabular-nums font-medium text-signal"
                      }
                    >
                      {reason.trim().length}/{REASON_MINIMUM}
                    </span>
                  </p>
                </div>

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
                <p className="text-xs text-sand-muted/70">
                  {blocking.length ? (
                    <span className="text-signal">Still needed: {blocking.join(", ")}.</span>
                  ) : (
                    "Recorded in the audit trail."
                  )}
                </p>
                <div className="flex gap-2">
                  <Dialog.Close asChild>
                    <Button variant="ghost" size="sm" disabled={busy}>
                      Cancel
                    </Button>
                  </Dialog.Close>
                  <Button
                    variant="primary"
                    size="sm"
                    disabled={!canSubmit}
                    title={blocking.length ? `Still needed: ${blocking.join(", ")}` : undefined}
                    onClick={() => void submit()}
                  >
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
