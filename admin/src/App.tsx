import { Route, BrowserRouter as Router, Routes } from "react-router-dom";
import { Toaster } from "sonner";

import { AppShell } from "./components/AppShell";
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

export function App() {
  return (
    <Router>
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
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: "#242424",
            border: "1px solid rgba(233, 224, 209, 0.27)",
            color: "#e9e0d1",
            borderRadius: "2px",
            fontFamily: '"Geist", ui-sans-serif, system-ui, sans-serif',
          },
        }}
      />
    </Router>
  );
}
