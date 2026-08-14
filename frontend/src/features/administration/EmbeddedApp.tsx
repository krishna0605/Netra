import { useCallback, useMemo, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";

import { AppShell } from "./components/AppShell";
import { ErrorBoundary } from "./components/states";
import { AuthContext, IDLE_TIMEOUT_MS, IDLE_WARN_MS, STEP_UP_WINDOW_MS, type AdminProfile, type AuthValue } from "./features/auth/AuthContext";
import { DirectoryProvider } from "./data/store";
import { SessionExpiryDialog } from "./features/auth/SessionExpiryDialog";
import { useIdleTimer } from "./lib/useIdleTimer";
import { supabase } from "./lib/supabase";
import { ActivityPage } from "./pages/ActivityPage";
import { AuditPage } from "./pages/AuditPage";
import { CapabilitiesPage } from "./pages/CapabilitiesPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OrganizationPage } from "./pages/OrganizationPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RolesPage } from "./pages/RolesPage";
import { SessionsPage } from "./pages/SessionsPage";
import { UserDetailPage } from "./pages/UserDetailPage";
import { UsersPage } from "./pages/UsersPage";
import "./index.css";

type Props = {
  profile: AdminProfile;
  onExit: () => void;
  onSignOut: () => Promise<void>;
};

export default function EmbeddedAdministration({ profile, onExit, onSignOut }: Props) {
  const [verifiedAt, setVerifiedAt] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const stepUp = useCallback(async (code: string) => {
    const { data: factors, error: listError } = await supabase.auth.mfa.listFactors();
    const factor = factors?.totp?.find((item) => item.status === "verified") ?? factors?.totp?.[0];
    if (listError || !factor) return "No authenticator is enrolled on this account.";
    const { error: verifyError } = await supabase.auth.mfa.challengeAndVerify({ factorId: factor.id, code: code.trim() });
    if (verifyError) return "That code was not accepted. Codes expire after 30 seconds.";
    setVerifiedAt(new Date().toISOString());
    return "";
  }, []);

  const value = useMemo<AuthValue>(() => ({
    stage: "active",
    profile,
    verifiedAt,
    error,
    busy,
    signIn: async () => undefined,
    verifyCode: async () => undefined,
    stepUp,
    chooseAdministration: () => undefined,
    returnToChooser: onExit,
    signOut: async () => {
      setBusy(true);
      try { await onSignOut(); } finally { setBusy(false); }
    },
    clearError: () => setError(""),
    isStepUpFresh: (maxAgeMs = STEP_UP_WINDOW_MS) => Boolean(verifiedAt && Date.now() - Date.parse(verifiedAt) < maxAgeMs),
  }), [busy, error, onExit, onSignOut, profile, stepUp, verifiedAt]);

  const idle = useIdleTimer({ timeoutMs: IDLE_TIMEOUT_MS, warnMs: IDLE_WARN_MS, onExpire: onExit });
  return (
    <ErrorBoundary>
      <AuthContext.Provider value={value}>
        <DirectoryProvider>
          <AppShell idleWarning={idle.warning} secondsLeft={idle.msRemaining / 1000}>
            <Routes>
              <Route index element={<OverviewPage />} />
              <Route path="users" element={<UsersPage />} />
              <Route path="users/:userId" element={<UserDetailPage />} />
              <Route path="roles" element={<RolesPage />} />
              <Route path="activity" element={<ActivityPage />} />
              <Route path="sessions" element={<SessionsPage />} />
              <Route path="organization" element={<OrganizationPage />} />
              <Route path="capabilities" element={<CapabilitiesPage />} />
              <Route path="audit" element={<AuditPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </AppShell>
        </DirectoryProvider>
        <SessionExpiryDialog open={idle.warning} msRemaining={idle.msRemaining} onStay={idle.reset} onEnd={onExit} />
        <Toaster position="bottom-right" />
      </AuthContext.Provider>
    </ErrorBoundary>
  );
}
