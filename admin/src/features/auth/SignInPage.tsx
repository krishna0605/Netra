import { useState, type FormEvent } from "react";

import { AuthLayout } from "./AuthLayout";
import { Button, Input } from "../../components/ui/primitives";
import { useAuth } from "./AuthContext";

export function SignInPage() {
  const { signIn, error, busy, clearError } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const canSubmit = email.trim().length > 3 && password.length > 0 && !busy;

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!canSubmit) return;
    void signIn(email, password);
  }

  return (
    <AuthLayout title="Sign in" subtitle="Authorized personnel only. All access is recorded.">
      <form onSubmit={onSubmit} noValidate className="flex flex-col gap-4">
        <div>
          <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="email">
            Official email
          </label>
          <Input
            id="email"
            type="email"
            value={email}
            onChange={(event) => {
              setEmail(event.target.value);
              if (error) clearError();
            }}
            placeholder="name@gcc.gov.in"
            autoComplete="username"
            autoFocus
            className="font-mono"
          />
        </div>

        <div>
          <label className="mb-1.5 block text-[13px] text-sand-muted/80" htmlFor="password">
            Password
          </label>
          <Input
            id="password"
            type="password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              if (error) clearError();
            }}
            autoComplete="current-password"
          />
        </div>

        {error ? (
          <p
            role="alert"
            className="rounded-control border border-state-crit/50 bg-state-crit/10 px-3.5 py-2.5 text-[13px] text-state-crit"
          >
            {error}
          </p>
        ) : null}

        <Button type="submit" variant="primary" disabled={!canSubmit} className="mt-1 w-full">
          {busy ? "Checking…" : "Continue"}
        </Button>
      </form>
    </AuthLayout>
  );
}
