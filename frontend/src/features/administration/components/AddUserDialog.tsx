import * as Dialog from "@radix-ui/react-dialog";
import { Check, Copy, RefreshCw, X } from "lucide-react";
import { useState } from "react";

import { Button, Input, NativeSelect, Panel, Tag } from "./ui/primitives";
import { useDirectory } from "../data/store";
import { useAuth } from "../features/auth/AuthContext";

type PasswordMode = "auto" | "custom";

// How the account reaches its owner. An invitation is the ordinary path: the
// officer sets their own password and enrols an authenticator from the link, so
// no credential is ever handled by a second person. A password exists for the
// case the invitation cannot cover — an address that does not receive mail from
// this deployment — and is the reason the choice is the operator's rather than
// the deployment's.
type Delivery = "invite" | "password";

// Mirrors _MIN_PASSWORD and the class rule in admin_users.resolve_password. The
// server is the authority — this only spares the operator a round trip.
const PASSWORD_MINIMUM = 12;

function generatePassword() {
  // Excludes the characters that are misread when a credential is dictated
  // aloud, which is how these are handed over.
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
  const bytes = new Uint32Array(20);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join("");
}

function passwordAcceptable(value: string) {
  if (value.length < PASSWORD_MINIMUM) return false;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(value)).length;
  return classes >= 3;
}

type Handover = {
  name: string;
  email: string;
  password: string;
  roleName: string;
  delivery: string;
  mustChangePassword: boolean;
};

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
  // Invitation first. It is the only path where the credential is never known
  // to anyone but the officer, which is what keeps the access log meaningful.
  const [delivery, setDelivery] = useState<Delivery>("invite");
  // Only consulted on the password path. The field opens pre-filled so the
  // common case is one click, and stays editable for a specific credential.
  const [mode, setMode] = useState<PasswordMode>("auto");
  const [password, setPassword] = useState(() => generatePassword());

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
  // An invitation carries no credential, so the password rule is not a rule
  // there. Applying it anyway would disable the button over a field the
  // operator cannot even see.
  const passwordValid = delivery === "invite" || passwordAcceptable(password);
  const canSubmit =
    name.trim().length >= 2 && emailValid && reasonValid && passwordValid && code.trim().length === 6 && !busy;

  // What the operator still has to do, in the order the fields appear.
  const blocking = [
    name.trim().length >= 2 ? "" : "a full name",
    emailValid ? "" : "a valid email address",
    reasonValid ? "" : `a reason of at least ${REASON_MINIMUM} characters`,
    passwordValid ? "" : `a password of at least ${PASSWORD_MINIMUM} characters using three character types`,
    code.trim().length === 6 ? "" : "the 6-digit authenticator code",
  ].filter(Boolean);

  function reset() {
    setName("");
    setEmail("");
    setDepartment(organization.name);
    setRoleSlug(DEFAULT_ROLE_SLUG);
    setReason("");
    setCode("");
    setDelivery("invite");
    setMode("auto");
    setPassword(generatePassword());
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
      const {
        created,
        password: applied,
        delivery: appliedDelivery,
        mustChangePassword,
      } = await createUser({
        name,
        email,
        department,
        roleSlug,
        reason: reason.trim(),
        delivery,
        // Sent only where it means something. On the invitation path the server
        // issues no credential at all.
        ...(delivery === "password" ? { password } : {}),
      });
      setHandover({
        name: created.name,
        email: created.email,
        // What the server applied, not what this dialog proposed.
        password: applied,
        roleName: roles.find((role) => role.slug === roleSlug)?.name ?? roleSlug,
        delivery: appliedDelivery,
        mustChangePassword,
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
                  ? handover.password
                    ? "Hand these details over now. The password is kept on the officer's profile if you need it again."
                    : "The invitation takes them through setting a password and enrolling an authenticator."
                  : "Send an invitation, or issue a password when the officer cannot receive mail from this deployment."}
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
                      <dt className="w-20 text-[13px] text-sand-muted/70">
                        {handover.mustChangePassword ? "Temporary password" : "Password"}
                      </dt>
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

                {handover.password ? null : (
                  <p className="rounded-control border-l-2 border-state-ok bg-state-ok/8 px-4 py-3 text-[13px] leading-relaxed text-sand-muted">
                    An invitation is on its way to {handover.email}. Opening it is what puts the account into service —
                    they choose a password and enrol an authenticator from the link.
                  </p>
                )}
                {handover.password && !handover.mustChangePassword ? (
                  <p className="rounded-control border-l-2 border-state-warn bg-state-warn/8 px-4 py-3 text-[13px] leading-relaxed text-sand-muted">
                    This password does not expire and the officer is not asked to replace it, so you and they both know
                    the credential they sign in with. Replace it from their profile when the handover is done.
                  </p>
                ) : null}
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

                <fieldset className="rounded-panel border border-[color:var(--color-control-edge)] px-4 py-3">
                  <legend className="px-1 text-[13px] font-medium text-sand">Handover</legend>
                  <div className="mt-1 flex flex-wrap gap-4">
                    <label className="flex cursor-pointer items-center gap-2">
                      <input
                        type="radio"
                        name="delivery"
                        checked={delivery === "invite"}
                        onChange={() => setDelivery("invite")}
                        className="accent-[color:var(--color-signal)]"
                      />
                      <span className="text-[13px] text-sand">Send an invitation</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-2">
                      <input
                        type="radio"
                        name="delivery"
                        checked={delivery === "password"}
                        onChange={() => setDelivery("password")}
                        className="accent-[color:var(--color-signal)]"
                      />
                      <span className="text-[13px] text-sand">Issue a password</span>
                    </label>
                  </div>
                  <p className="mt-1.5 text-xs text-sand-muted/70">
                    {delivery === "invite"
                      ? "A sign-in link goes to the address above. They set their own password and enrol an authenticator from it, so nobody else ever holds the credential."
                      : "Netra generates the credential and shows it here. Use this when the officer cannot receive mail from this deployment."}
                  </p>
                </fieldset>

                {delivery === "password" ? (
                <fieldset className="rounded-panel border border-[color:var(--color-control-edge)] px-4 py-3">
                  <legend className="px-1 text-[13px] font-medium text-sand">Password</legend>
                  <div className="mt-1 flex flex-wrap gap-4">
                    <label className="flex cursor-pointer items-center gap-2">
                      <input
                        type="radio"
                        name="pwmode"
                        checked={mode === "auto"}
                        onChange={() => setMode("auto")}
                        className="accent-[color:var(--color-signal)]"
                      />
                      <span className="text-[13px] text-sand">Auto-generate</span>
                    </label>
                    <label className="flex cursor-pointer items-center gap-2">
                      <input
                        type="radio"
                        name="pwmode"
                        checked={mode === "custom"}
                        onChange={() => setMode("custom")}
                        className="accent-[color:var(--color-signal)]"
                      />
                      <span className="text-[13px] text-sand">Set one myself</span>
                    </label>
                  </div>

                  <div className="mt-3 flex flex-wrap items-start gap-2">
                    <Input
                      id="new-password"
                      value={password}
                      readOnly={mode === "auto"}
                      onChange={(event) => setPassword(event.target.value)}
                      placeholder={mode === "auto" ? "Press Generate" : "At least 12 characters"}
                      className="min-w-[16rem] flex-1 font-mono"
                      autoComplete="off"
                      aria-label="Password"
                    />
                    {mode === "auto" ? (
                      <Button variant="outline" size="sm" onClick={() => setPassword(generatePassword())}>
                        <RefreshCw className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                        Generate
                      </Button>
                    ) : null}
                  </div>
                  <p className="mt-1.5 text-xs text-sand-muted/70">
                    {passwordValid
                      ? "Shown here and kept on the officer's profile so you can read it back."
                      : "At least 12 characters, using three of: lowercase, uppercase, digits, symbols."}
                  </p>
                </fieldset>
                ) : null}
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
