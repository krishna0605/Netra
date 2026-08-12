import { Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";

import { AppShell } from "./components/AppShell";
import { AuthProvider } from "./features/auth/AuthProvider";
import { ChooserPage } from "./features/auth/ChooserPage";
import { DirectoryProvider } from "./data/store";
import { IDLE_TIMEOUT_MS, IDLE_WARN_MS, useAuth } from "./features/auth/AuthContext";
import { NotPermittedPage } from "./features/auth/NotPermittedPage";
import { SessionExpiryDialog } from "./features/auth/SessionExpiryDialog";
import { SignInPage } from "./features/auth/SignInPage";
import { VerifyPage } from "./features/auth/VerifyPage";
import { WorkspaceRouter } from "./features/auth/WorkspaceRouter";
import { useIdleTimer } from "./lib/useIdleTimer";

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

/** The nine administrative screens, reachable only once a session is active. */
function Workspace() {
  const { returnToChooser } = useAuth();

  const { warning, msRemaining, reset } = useIdleTimer({
    timeoutMs: IDLE_TIMEOUT_MS,
    warnMs: IDLE_WARN_MS,
    onExpire: returnToChooser,
  });

  return (
    <WorkspaceRouter>
      <DirectoryProvider>
        <AppShell>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/users/:userId" element={<UserDetailPage />} />
            <Route path="/roles" element={<RolesPage />} />
            <Route path="/activity" element={<ActivityPage />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/organization" element={<OrganizationPage />} />
            <Route path="/capabilities" element={<CapabilitiesPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </AppShell>
      </DirectoryProvider>

      <SessionExpiryDialog open={warning} msRemaining={msRemaining} onStay={reset} onEnd={returnToChooser} />
    </WorkspaceRouter>
  );
}

/**
 * Which screen renders is decided by the session's stage, not by a URL. That
 * is what makes the workspace unreachable by navigation — there is no path to
 * type, so the guard cannot be walked around.
 */
function Gate() {
  const { stage } = useAuth();

  switch (stage) {
    case "resolving":
      return <div className="app-theme min-h-screen" aria-busy="true" />;
    case "anonymous":
      return <SignInPage />;
    case "challenge":
      return <VerifyPage />;
    case "not_permitted":
      return <NotPermittedPage />;
    case "choosing":
      return <ChooserPage />;
    case "active":
      return <Workspace />;
  }
}

export function App() {
  return (
    <AuthProvider>
      <Gate />
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: "#242424",
            border: "1px solid rgba(233, 224, 209, 0.2)",
            color: "#e9e0d1",
            borderRadius: "6px",
            fontFamily: '"Geist", ui-sans-serif, system-ui, sans-serif',
          },
        }}
      />
    </AuthProvider>
  );
}
