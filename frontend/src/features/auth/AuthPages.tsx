import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";

import { Alert, Button, Input } from "../../components/ui/primitives";
import { clearNetraSessionState, supabase, SUPABASE_AUTH_ENABLED } from "../../lib/supabase";
import { passwordChecks, validPassword } from "./passwordPolicy";


function AuthShell({ eyebrow, title, description, children }: {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <main className="auth-shell flex min-h-screen items-center justify-center px-4" id="main-content">
      <section className="auth-panel w-full max-w-md border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm" aria-labelledby="auth-heading">
        <Link to="/" className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-accent">
          {eyebrow}
        </Link>
        <h1 id="auth-heading" className="mt-6 text-4xl font-normal text-strong">{title}</h1>
        <p className="mt-2 text-sm leading-6 text-muted">{description}</p>
        {children}
      </section>
    </main>
  );
}


export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (!supabase) {
      setError("Password recovery is not configured for this deployment.");
      return;
    }
    setBusy(true);
    try {
      await supabase.auth.resetPasswordForEmail(email.trim().toLowerCase(), {
        redirectTo: `${window.location.origin}/auth/recovery`,
      });
      setSubmitted(true);
    } catch {
      // Keep the response enumeration-resistant even for provider failures.
      setSubmitted(true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell eyebrow="NETRA / Account recovery" title="Reset your password." description="Use the email address assigned by your Netra administrator.">
      {!SUPABASE_AUTH_ENABLED ? <Alert>Password recovery is unavailable in this build.</Alert> : null}
      {submitted ? (
        <div className="mt-5 grid gap-4" role="status" aria-live="polite">
          <Alert>If an eligible account exists, recovery instructions have been sent. Check your inbox and spam folder.</Alert>
          <Link className="text-sm font-semibold text-accent underline" to="/login">Return to sign in</Link>
        </div>
      ) : (
        <form className="mt-5 grid gap-4" onSubmit={submit} noValidate>
          <div className="grid gap-1">
            <label htmlFor="recovery-email" className="text-sm font-semibold text-strong">Email</label>
            <Input id="recovery-email" value={email} onChange={(event) => setEmail(event.target.value)} type="email" autoComplete="email" required aria-invalid={Boolean(error)} aria-describedby={error ? "recovery-error" : undefined} />
          </div>
          {error ? <p id="recovery-error" className="text-sm text-red-300" role="alert">{error}</p> : null}
          <Button type="submit" disabled={busy || !email}>{busy ? "Requesting…" : "Send recovery instructions"}</Button>
          <Link className="text-sm font-semibold text-accent underline" to="/login">Return to sign in</Link>
        </form>
      )}
    </AuthShell>
  );
}


function PasswordCompletionPage({ mode }: { mode: "recovery" | "invite" }) {
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [sessionReady, setSessionReady] = useState(false);
  const [checking, setChecking] = useState(Boolean(supabase));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const checks = useMemo(() => passwordChecks(password), [password]);
  const acceptedLink = mode === "invite" || window.location.search.includes("code=") || window.location.hash.includes("type=recovery");

  useEffect(() => {
    if (!supabase) {
      return undefined;
    }
    let mounted = true;
    supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      setSessionReady(Boolean(data.session) && acceptedLink);
      setChecking(false);
    }).catch(() => {
      if (!mounted) return;
      setSessionReady(false);
      setChecking(false);
    });
    return () => {
      mounted = false;
    };
  }, [acceptedLink]);

  async function complete(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (!supabase || !sessionReady) {
      setError("This secure link is invalid or has expired.");
      return;
    }
    if (!validPassword(password) || password !== confirmation) {
      setError("Meet every password requirement and confirm the same password.");
      return;
    }
    setBusy(true);
    const { error: updateError } = await supabase.auth.updateUser({ password });
    if (updateError) {
      setBusy(false);
      setError("The password could not be updated. Request a new secure link.");
      return;
    }
    await supabase.auth.signOut({ scope: "global" });
    clearNetraSessionState();
    navigate("/login", { replace: true, state: { passwordUpdated: true } });
  }

  return (
    <AuthShell
      eyebrow={mode === "invite" ? "NETRA / Invitation" : "NETRA / Recovery"}
      title={mode === "invite" ? "Complete your account." : "Choose a new password."}
      description="This link proves control of your email account. It never assigns a Netra organization or role."
    >
      {checking ? <Alert>Validating the secure link…</Alert> : null}
      {!checking && !sessionReady ? (
        <div className="mt-5 grid gap-4" role="alert">
          <Alert>This secure link is invalid, already used, or expired.</Alert>
          <Link className="text-sm font-semibold text-accent underline" to={mode === "invite" ? "/login" : "/auth/forgot-password"}>
            {mode === "invite" ? "Return to sign in" : "Request a new recovery link"}
          </Link>
        </div>
      ) : null}
      {!checking && sessionReady ? (
        <form className="mt-5 grid gap-4" onSubmit={complete} noValidate>
          <div className="grid gap-1">
            <label htmlFor={`${mode}-password`} className="text-sm font-semibold text-strong">New password</label>
            <Input id={`${mode}-password`} type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} aria-describedby={`${mode}-requirements ${mode}-error`} aria-invalid={Boolean(error)} />
          </div>
          <ul id={`${mode}-requirements`} className="grid gap-1 text-xs text-muted" aria-live="polite">
            {checks.map((check) => <li key={check.key}>{check.met ? "✓" : "○"} {check.label}</li>)}
          </ul>
          <div className="grid gap-1">
            <label htmlFor={`${mode}-confirmation`} className="text-sm font-semibold text-strong">Confirm password</label>
            <Input id={`${mode}-confirmation`} type="password" autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} aria-invalid={Boolean(confirmation && confirmation !== password)} />
          </div>
          {error ? <p id={`${mode}-error`} className="text-sm text-red-300" role="alert">{error}</p> : null}
          <Button type="submit" disabled={busy || !validPassword(password) || password !== confirmation}>{busy ? "Updating…" : "Set password and sign out"}</Button>
        </form>
      ) : null}
    </AuthShell>
  );
}


export function RecoveryPage() {
  return <PasswordCompletionPage mode="recovery" />;
}


export function InvitationPage() {
  return <PasswordCompletionPage mode="invite" />;
}
