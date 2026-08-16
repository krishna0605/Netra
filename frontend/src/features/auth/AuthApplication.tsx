import { useState, type FormEvent } from "react";
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Toaster } from "sonner";

import { Alert, Button, Input } from "../../components/ui/primitives";
import { useCapabilities } from "../../lib/useCapabilities";
import { SUPABASE_AUTH_ENABLED } from "../../lib/supabase";
import { clearLastConsoleWorkspace } from "../../lib/consoleContext";
import { AuthProvider } from "./AuthProvider";
import { AuthLayout } from "./AuthLayout";
import { ForgotPasswordPage, InvitationPage, RecoveryPage } from "./AuthPages";
import { useAuth } from "./AuthContext";
import { MfaPage } from "./MfaPage";


function safeDestination(value: string | null) {
  return value === "/" ? value : "/";
}


function LoginPage() {
  const { available } = useCapabilities();
  const location = useLocation();
  const { session, signIn, signOut, state } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const destination = safeDestination(new URLSearchParams(location.search).get("from"));

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const result = await signIn(email, password);
    setBusy(false);
    if (!result.ok) {
      setError(result.message ?? "Invalid login credentials.");
      return;
    }
    window.location.assign(destination);
  }

  function continueToConsole() {
    clearLastConsoleWorkspace();
    window.location.assign(destination);
  }

  return (
    <AuthLayout
      title="Sign in"
      subtitle="Authorized personnel only. All access is recorded."
      footer={<Link className="font-semibold text-[var(--accent)] underline underline-offset-2" to="/">Return to the public site</Link>}
    >
        {!SUPABASE_AUTH_ENABLED ? <Alert>Authentication is unavailable in this build.</Alert> : null}
        {state.status === "initializing" || state.status === "resolving_profile" ? <Alert>Checking the current secure session.</Alert> : null}
        {error ? <p id="login-error" className="mt-4 text-sm text-red-300" role="alert">{error}</p> : null}
        {session ? (
          <div className="mt-5 grid gap-3">
            <Alert>This browser already has an authenticated session.</Alert>
            <Button type="button" onClick={continueToConsole}>Continue</Button>
            <Button type="button" variant="secondary" onClick={() => void signOut()}>Sign out</Button>
          </div>
        ) : (
          <form className="mt-5 grid gap-4" onSubmit={submit} noValidate>
            <div>
              <label htmlFor="login-email" className="mb-1.5 block text-[13px] text-[var(--muted)]">Official email</label>
              <Input id="login-email" className="font-mono" type="email" autoComplete="username" placeholder="name@gcc.gov.in" autoFocus required value={email} onChange={(event) => setEmail(event.target.value)} aria-invalid={Boolean(error)} aria-describedby={error ? "login-error" : undefined} />
            </div>
            <div>
              <label htmlFor="login-password" className="mb-1.5 block text-[13px] text-[var(--muted)]">Password</label>
              <Input id="login-password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} aria-invalid={Boolean(error)} aria-describedby={error ? "login-error" : undefined} />
            </div>
            <Button type="submit" className="mt-1 w-full" disabled={busy || !email.trim() || !password} aria-busy={busy}>{busy ? "Checking…" : "Continue"}</Button>
            {available("password_recovery") ? <Link className="text-sm font-semibold text-[var(--accent)] underline underline-offset-2" to="/login/forgot-password">Forgot password?</Link> : null}
          </form>
        )}
    </AuthLayout>
  );
}


function LeaveAuthApplication() {
  window.location.replace("/");
  return <main id="main-content" aria-busy="true"><p role="status">Opening the investigation console…</p></main>;
}


export default function AuthApplication() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster position="top-right" />
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/login/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/login/recovery" element={<RecoveryPage />} />
          <Route path="/login/invite" element={<InvitationPage />} />
          <Route path="/login/mfa" element={<MfaPage />} />
          <Route path="/" element={<LeaveAuthApplication />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
