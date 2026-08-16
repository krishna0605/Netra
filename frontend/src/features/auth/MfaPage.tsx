import { useMemo, useState, type FormEvent } from "react";
import { Link, Navigate } from "react-router-dom";

import { Alert, Button, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../../components/ui/primitives";
import { supabase } from "../../lib/supabase";
import { useAuth } from "./AuthContext";
import { AuthLayout } from "./AuthLayout";


export function MfaPage({ allowAdditional = false }: { allowAdditional?: boolean }) {
  const { state, refreshAssurance, signOut } = useAuth();
  const [factorId, setFactorId] = useState("");
  const [qr, setQr] = useState("");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const challengeFactors = state.status === "mfa_challenge_required" ? state.factors : [];
  const selectedFactorId = factorId || challengeFactors[0]?.id || "";
  const enrollmentRequired = state.status === "mfa_enrollment_required" || allowAdditional;
  const validCode = /^\d{6}$/.test(code);
  const title = useMemo(() => enrollmentRequired ? "Set up an authenticator." : "Verify your authenticator.", [enrollmentRequired]);

  if (!supabase) return <Navigate to="/login" replace />;
  if (state.status === "initializing" || state.status === "resolving_profile") {
    return <main className="auth-shell min-h-screen" id="main-content" aria-busy="true" />;
  }
  if (!allowAdditional && !["mfa_enrollment_required", "mfa_challenge_required"].includes(state.status)) {
    return <Navigate to="/" replace />;
  }

  async function beginEnrollment() {
    setBusy(true);
    setError("");
    const { data, error: enrollError } = await supabase!.auth.mfa.enroll({
      factorType: "totp",
      friendlyName: `Netra authenticator ${new Date().toISOString().slice(0, 10)}`,
    });
    setBusy(false);
    if (enrollError) {
      setError("Authenticator enrollment could not be started. Try again.");
      return;
    }
    setFactorId(data.id);
    setQr(data.totp.qr_code);
    setSecret(data.totp.secret);
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (!selectedFactorId || !validCode) {
      setError("Enter the six-digit code from your authenticator.");
      return;
    }
    setBusy(true);
    const { error: verifyError } = await supabase!.auth.mfa.challengeAndVerify({ factorId: selectedFactorId, code });
    setBusy(false);
    if (verifyError) {
      setError("The verification code was not accepted. Wait for a new code and try again.");
      return;
    }
    setCode("");
    setQr("");
    setSecret("");
    await refreshAssurance();
  }

  async function cancelEnrollment() {
    if (factorId) await supabase!.auth.mfa.unenroll({ factorId });
    setFactorId("");
    setQr("");
    setSecret("");
  }

  return (
    <AuthLayout title={title} subtitle="Every Netra workspace requires a verified authenticator. Netra never stores the QR code or manual secret." width="wide">

        {enrollmentRequired && !factorId ? (
          <div className="mt-5 grid gap-3">
            <Alert>Use an authenticator application. Recovery codes are not available for this flow.</Alert>
            <Button type="button" onClick={beginEnrollment} disabled={busy}>{busy ? "Starting…" : "Begin secure setup"}</Button>
          </div>
        ) : null}

        {qr ? (
          <div className="mt-5 grid gap-4">
            <img className="mx-auto size-56 rounded-xl bg-white p-3" src={qr} alt="QR code containing the one-time Netra authenticator enrollment secret" />
            <div className="grid gap-1">
              <span className="text-sm font-semibold text-strong">Manual setup key</span>
              <code className="break-all rounded-lg border border-[var(--border)] p-3 text-xs" aria-label="Manual authenticator setup key">{secret}</code>
              <Button type="button" variant="secondary" onClick={() => navigator.clipboard.writeText(secret)}>Copy setup key</Button>
            </div>
          </div>
        ) : null}

        {!enrollmentRequired && challengeFactors.length > 1 ? (
          <div className="mt-5 grid gap-1">
            <label className="text-sm font-semibold text-strong" htmlFor="mfa-factor">Authenticator</label>
            <Select value={selectedFactorId} onValueChange={setFactorId}>
              <SelectTrigger id="mfa-factor"><SelectValue /></SelectTrigger>
              <SelectContent>{challengeFactors.map((factor) => <SelectItem key={factor.id} value={factor.id}>{factor.friendly_name || "Authenticator"}</SelectItem>)}</SelectContent>
            </Select>
          </div>
        ) : null}

        {(factorId || (!enrollmentRequired && selectedFactorId)) ? (
          <form className="mt-5 grid gap-3" onSubmit={verify} noValidate>
            <label htmlFor="mfa-code" className="text-sm font-semibold text-strong">Six-digit code</label>
            <Input id="mfa-code" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" aria-invalid={Boolean(error)} aria-describedby={error ? "mfa-error" : "mfa-help"} />
            <p id="mfa-help" className="text-xs text-muted">Codes change every 30 seconds. Paste is supported.</p>
            {error ? <p id="mfa-error" className="text-sm text-red-300" role="alert">{error}</p> : null}
            <Button type="submit" disabled={busy || !validCode}>{busy ? "Verifying…" : "Verify and continue"}</Button>
            {qr ? <Button type="button" variant="secondary" onClick={cancelEnrollment}>Cancel this enrollment</Button> : null}
          </form>
        ) : null}

        <div className="mt-5 flex flex-wrap gap-4 text-sm">
          {allowAdditional ? <Link className="font-semibold text-accent underline" to="/">Return to console</Link> : null}
          <button type="button" className="font-semibold text-accent underline" onClick={() => void signOut()}>Sign out</button>
        </div>
    </AuthLayout>
  );
}
