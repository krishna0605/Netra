import { Activity, AlertTriangle, Database, FileSearch, FileText, Languages, type LucideIcon, Menu, PanelLeftClose, PanelLeftOpen, Search, Settings as SettingsIcon, Upload } from "lucide-react";
import { Alert, Button, Input, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Sheet, SheetContent, SheetTitle, TooltipProvider } from "../../components/ui/primitives";
import { appViewRoute } from "./ConsoleCore";
import { AuthProvider } from "../auth/AuthProvider";
import { caseWorkspaceRoute } from "./ConsoleCore";
import { cn } from "../../lib/utils";
import { useCapabilities } from "../../lib/useCapabilities";
import { Link, MemoryRouter as Router, Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { MetadataRow } from "./reports/ReportPages";
import { MfaPage } from "../auth/MfaPage";
import { motion, MotionConfig } from "framer-motion";
import { NetraProvider } from "./ConsoleProvider";
import { PageFrame } from "./reports/ReportPages";
import { PublicHomePage } from "../../public/PublicSite";
import { RouteErrorBoundary } from "../../components/RouteErrorBoundary";
import { SUPABASE_AUTH_ENABLED } from "../../lib/supabase";
import { toast, Toaster } from "sonner";
import { type DeploymentModuleKey } from "./ConsoleCore";
import { lazy, Suspense, type FormEvent, type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { type Language } from "../../lib/types";
import { useAuth } from "../auth/AuthContext";
import { useNetra } from "./ConsoleCore";
import { VIEW_REFS } from "./ConsoleCore";
import { getLastConsoleWorkspace, rememberConsoleWorkspace, switchConsoleWorkspace } from "../../lib/consoleContext";

const UploadPage = lazy(() => import("./evidence/EvidencePages").then((module) => ({ default: module.UploadPage })));
const TrafficPages = {
  Dashboard: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.DashboardPage }))),
  Packets: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.PacketExplorerPage }))),
  Protocols: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.ProtocolDecoderPage }))),
  Payloads: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.PayloadInspectionPage }))),
  Sessions: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.SessionsPage }))),
  Detection: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.ThreatDetectionPage }))),
  Anomaly: lazy(() => import("./analysis/TrafficPages").then((module) => ({ default: module.AiAnomalyPage }))),
};
const SuspiciousActivityPage = lazy(() => import("./analysis/FindingPages").then((module) => ({ default: module.SuspiciousActivityPage })));
const TrafficEvidencePage = lazy(() => import("./analysis/FindingPages").then((module) => ({ default: module.TrafficEvidencePage })));
const EvidenceReportPage = lazy(() => import("./reports/EvidenceReportPages").then((module) => ({ default: module.EvidenceReportPage })));
const ReportPage = lazy(() => import("./reports/ReportPages").then((module) => ({ default: module.ReportPage })));
const CasesPage = lazy(() => import("./cases/CasePages").then((module) => ({ default: module.CasesPage })));
const CaseDetailPage = lazy(() => import("./cases/CasePages").then((module) => ({ default: module.CaseDetailPage })));
const IntegrationsPage = lazy(() => import("./integrations/IntegrationPages").then((module) => ({ default: module.IntegrationsPage })));
const CompliancePage = lazy(() => import("./integrations/IntegrationPages").then((module) => ({ default: module.CompliancePage })));
const GraphPage = lazy(() => import("./integrations/IntegrationPages").then((module) => ({ default: module.GraphPage })));
const ExportCenterPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.ExportCenterPage })));
const SettingsPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SettingsPage })));
const LabToolsPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.LabToolsPage })));
const SensorsPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SensorsPage })));
const SchedulesPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SchedulesPage })));
const RetentionPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.RetentionPage })));
const SystemPage = lazy(() => import("./operations/OperationsPages").then((module) => ({ default: module.SystemPage })));
const AdministrationWorkspace = lazy(() => import("../administration/EmbeddedApp"));

export function App() {
  return (
    <AuthProvider>
      <MotionConfig reducedMotion="user">
        <TooltipProvider>
          <NetraProvider>
            <div className="app-theme">
              <Router initialEntries={["/"]}>
            <Toaster position="top-right" />
            <Suspense fallback={<RouteLoadingScreen />}>
            <Routes>
              <Route path="/" element={<RootEntry />} />
              <Route path="/app/*" element={<RequireAuth><AppShell /></RequireAuth>} />
              <Route path="/administration/*" element={<RequireAuth><AdministrationEntry /></RequireAuth>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
            </Suspense>
              </Router>
            </div>
          </NetraProvider>
        </TooltipProvider>
      </MotionConfig>
    </AuthProvider>
  );
}

function AdministrationEntry() {
  const navigate = useNavigate();
  const { state, signOut } = useAuth();
  if (!("profile" in state) || !("session" in state) || !state.profile.workspaces?.administration?.available) {
    return <Navigate to="/" replace />;
  }
  return (
    <AdministrationWorkspace
      profile={{
        userId: state.session.user.id,
        email: state.session.user.email ?? "",
        displayName: state.profile.user,
        role: state.profile.role,
        organizationName: state.profile.organization.name,
        isOwner: false,
        isAdministrative: true,
      }}
      onExit={() => navigate("/", { replace: true })}
      onSignOut={signOut}
    />
  );
}

function LeaveForLogin({ path }: { path: string }) {
  useEffect(() => {
    window.location.replace(path);
  }, [path]);
  return <RouteLoadingScreen />;
}

function RootEntry() {
  const { state } = useAuth();

  if (state.status === "initializing" || state.status === "resolving_profile") return <RouteLoadingScreen />;
  if (state.status === "signed_out" || state.status === "profile_denied") {
    return <PublicHomePage languageControl={<LanguageControl />} />;
  }
  if (state.status === "recovery") return <LeaveForLogin path="/login/recovery?required=1" />;
  if (state.status === "mfa_enrollment_required" || state.status === "mfa_challenge_required") {
    return <LeaveForLogin path="/login/mfa" />;
  }
  if (!("session" in state) || !("profile" in state)) return <RouteLoadingScreen />;
  return <WorkspaceEntry state={state} />;
}

function WorkspaceEntry({ state }: { state: Extract<ReturnType<typeof useAuth>["state"], { session: unknown; profile: unknown }> }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const restored = useRef(false);

  const administration = state.profile.workspaces?.administration?.available === true;
  const open = useCallback(async (workspace: "investigation" | "administration") => {
    setBusy(true);
    setError("");
    try {
      await switchConsoleWorkspace(state.session.access_token, workspace);
      rememberConsoleWorkspace(workspace);
      navigate(workspace === "administration" ? "/administration" : appViewRoute("upload"), { replace: true });
    } catch {
      setError("Netra could not open that workspace. Your access may have changed; sign in again.");
    } finally {
      setBusy(false);
    }
  }, [navigate, state.session.access_token]);

  useEffect(() => {
    if (restored.current) return;
    restored.current = true;
    const previous = getLastConsoleWorkspace();
    if (!administration || previous === "investigation" || previous === "administration") {
      const target = previous === "administration" && administration ? "administration" : "investigation";
      void open(target);
    }
  }, [administration, open]);

  if (!administration) {
    return (
      <main className="auth-shell flex min-h-screen items-center justify-center px-4" id="main-content">
        <section className="auth-panel w-full max-w-md border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm">
          <p className="text-sm text-muted">Your Investigation workspace is ready.</p>
          {error ? <Alert>{error}</Alert> : null}
          <Button className="mt-4 w-full" disabled>{busy ? "Opening…" : "Opening Investigation…"}</Button>
        </section>
      </main>
    );
  }
  return (
    <main className="auth-shell flex min-h-screen items-center justify-center px-4" id="main-content">
      <section className="auth-panel w-full max-w-3xl border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm">
        <p className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-accent">NETRA / Verified access</p>
        <h1 className="mt-5 text-4xl font-normal text-strong">Choose a workspace.</h1>
        <p className="mt-2 text-sm text-muted">Your available workspaces are resolved by the server from current permissions.</p>
        {error ? <Alert>{error}</Alert> : null}
        <div className="mt-6 grid gap-4 sm:grid-cols-2">
          <Button className="h-auto min-h-28 justify-start p-5 text-left" disabled={busy} onClick={() => void open("investigation")}>Investigation<br /><span className="text-xs font-normal">Cases, evidence, analysis and reports</span></Button>
          <Button className="h-auto min-h-28 justify-start p-5 text-left" disabled={busy} onClick={() => void open("administration")}>Administration<br /><span className="text-xs font-normal">Users, roles, sessions and audit history</span></Button>
        </div>
      </section>
    </main>
  );
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { state } = useAuth();

  if (state.status === "initializing" || state.status === "resolving_profile") {
    return (
      <main className="auth-shell flex min-h-screen items-center justify-center px-4">
        <section className="auth-panel w-full max-w-md border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm">
          <p className="text-sm font-semibold text-accent">Netra Secure Access</p>
          <h1 className="mt-2 text-2xl font-bold text-strong">Checking authentication</h1>
          <p className="mt-2 text-sm leading-6 text-muted">Verifying your identity and assigned Netra access before opening the investigation console.</p>
        </section>
      </main>
    );
  }

  if (state.status === "signed_out" || state.status === "profile_denied") {
    return <LeaveForLogin path="/login" />;
  }
  if (state.status === "mfa_enrollment_required" || state.status === "mfa_challenge_required") {
    return <LeaveForLogin path="/login/mfa" />;
  }
  if (state.status === "recovery") return <LeaveForLogin path="/login/recovery?required=1" />;

  return <>{children}</>;
}

function RouteLoadingScreen() {
  return (
    <main className="auth-shell flex min-h-screen items-center justify-center px-4" id="main-content" aria-busy="true">
      <section className="auth-panel w-full max-w-md border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm" role="status">
        <p className="text-sm font-semibold text-accent">Netra Secure Console</p>
        <h1 className="mt-2 text-2xl font-bold text-strong">Opening workspace</h1>
        <p className="mt-2 text-sm leading-6 text-muted">Loading the selected investigation view.</p>
      </section>
    </main>
  );
}

function RouteLoadingPanel() {
  return (
    <main id="main-content" className="surface rounded-[1.5rem] p-6" aria-busy="true" role="status">
      <h1 className="text-2xl font-normal text-strong">Opening workspace</h1>
      <p className="mt-2 text-sm text-muted">Loading the selected investigation view.</p>
    </main>
  );
}

export function LoginPage() {
  const { available } = useCapabilities();
  const navigate = useNavigate();
  const location = useLocation();
  const { state, session, signIn: authenticateSession, signOut: endSession } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const from = typeof location.state === "object" && location.state && "from" in location.state ? String(location.state.from) : appViewRoute("upload");
  const checkingSession = state.status === "initializing" || state.status === "resolving_profile";
  const hasSession = Boolean(session);

  async function signIn(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    setLoading(true);
    const result = await authenticateSession(email, password);
    setLoading(false);
    if (!result.ok) {
      toast.error(result.message ?? "Invalid login credentials.");
      return;
    }
    toast.success("Secure session verified");
    navigate(from, { replace: true });
  }

  async function signOut() {
    await endSession();
    toast.success("Signed out");
  }

  return (
    <main className="auth-shell flex min-h-screen items-center justify-center px-4">
      <section className="auth-panel w-full max-w-md border border-[var(--border)] bg-[var(--panel)] p-6 shadow-sm">
        <div className="mb-6">
          <Link to="/" className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-accent">NETRA / Secure access</Link>
          <h1 className="mt-6 text-4xl font-normal text-strong">Enter the investigation console.</h1>
          <p className="mt-2 text-sm text-muted">Authorized officers only. Accounts and roles are provisioned by a Netra administrator.</p>
        </div>
        {!SUPABASE_AUTH_ENABLED && <Alert>Set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY, then rebuild the frontend.</Alert>}
        {checkingSession && <Alert>Checking authentication for this browser session.</Alert>}
        {hasSession && (
          <div className="mt-4 grid gap-3">
            <Alert>You are already signed in on this browser. Continue to the investigation console or sign out to use another officer account.</Alert>
            <Button type="button" onClick={() => navigate(from, { replace: true })}>Continue to investigation console</Button>
            <Button type="button" variant="secondary" onClick={signOut}>Sign out</Button>
          </div>
        )}
        {!hasSession && <form className="mt-4 grid gap-3" onSubmit={signIn}>
          <label className="grid gap-1 text-sm font-semibold text-strong">
            Email
            <Input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="officer@example.com" type="email" autoComplete="email" />
          </label>
          <label className="grid gap-1 text-sm font-semibold text-strong">
            Password
            <Input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" autoComplete="current-password" />
          </label>
          <Button type="submit" disabled={loading || !email || !password}>
            {loading ? "Signing in..." : "Sign in"}
          </Button>
          {available("password_recovery") ? <Link className="text-sm font-semibold text-accent underline" to="/auth/forgot-password">Forgot password?</Link> : null}
        </form>}
      </section>
    </main>
  );
}

export function LanguageControl() {
  const { language, setLanguage } = useNetra();
  return (
    <Select value={language} onValueChange={(value) => setLanguage(value as Language)}>
      <SelectTrigger aria-label="Language" className="min-w-28">
        <Languages className="size-4" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="English">English</SelectItem>
        <SelectItem value="Hindi">Hindi</SelectItem>
        <SelectItem value="Gujarati">Gujarati</SelectItem>
      </SelectContent>
    </Select>
  );
}

export function ModuleRoute({ module, children }: { module: DeploymentModuleKey; children: ReactNode }) {
  const { deploymentAccess } = useNetra();
  const access = deploymentAccess.modules[module];
  if (!deploymentAccess.verified) {
    return <Navigate to={appViewRoute("upload")} replace />;
  }
  if (!access.visible) return <Navigate to={appViewRoute("upload")} replace />;
  if (!access.enabled) {
    return (
      <PageFrame title="Not configured" description={access.reason}>
        <Alert>{module === "lab" ? "Use normal evidence upload for this deployment. Native capture must run through an enrolled external sensor and replay requires an isolated lab environment." : "This operation is intentionally unavailable in the active deployment profile. No action was simulated or queued."}</Alert>
        <div className="surface rounded-[1.5rem] p-5">
          <MetadataRow label="Deployment profile" value={deploymentAccess.profile} />
          <MetadataRow label="Module" value={module} />
          <MetadataRow label="Status" value="Disabled" />
        </div>
      </PageFrame>
    );
  }
  return <>{children}</>;
}

export function OpaqueViewRoute() {
  const { viewRef = "" } = useParams();
  if (viewRef === VIEW_REFS.upload) return <UploadPage />;
  if (viewRef === VIEW_REFS.overview) return <TrafficPages.Dashboard />;
  if (viewRef === VIEW_REFS.activity) return <SuspiciousActivityPage />;
  if (viewRef === VIEW_REFS.evidence) return <TrafficEvidencePage />;
  if (viewRef === VIEW_REFS.reports) return <EvidenceReportPage />;
  if (viewRef === VIEW_REFS.packets) return <TrafficPages.Packets />;
  if (viewRef === VIEW_REFS.sessions) return <TrafficPages.Sessions />;
  if (viewRef === VIEW_REFS.decoder) return <TrafficPages.Protocols />;
  if (viewRef === VIEW_REFS.payloads) return <TrafficPages.Payloads />;
  if (viewRef === VIEW_REFS.detection) return <TrafficPages.Detection />;
  if (viewRef === VIEW_REFS.aiAnomaly) return <TrafficPages.Anomaly />;
  if (viewRef === VIEW_REFS.graph) return <GraphPage />;
  if (viewRef === VIEW_REFS.cases) return <CasesPage />;
  if (viewRef === VIEW_REFS.exports) return <ExportCenterPage />;
  if (viewRef === VIEW_REFS.lab) return <ModuleRoute module="lab"><LabToolsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.compliance) return <CompliancePage />;
  if (viewRef === VIEW_REFS.settings) return <ModuleRoute module="system"><SettingsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.technicalStatus) return <ModuleRoute module="system"><SystemPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.sensors) return <ModuleRoute module="sensors"><SensorsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.schedules) return <ModuleRoute module="schedules"><SchedulesPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.integrations) return <ModuleRoute module="integrations"><IntegrationsPage /></ModuleRoute>;
  if (viewRef === VIEW_REFS.retention) return <ModuleRoute module="retention"><RetentionPage /></ModuleRoute>;
  return <Navigate to={appViewRoute("upload")} replace />;
}

export function LegacyCaseRedirect() {
  const { caseId = "" } = useParams();
  const { caseRecords } = useNetra();
  const record = caseRecords.find((item) => item.id === caseId);
  if (record?.routeRef) return <Navigate to={caseWorkspaceRoute(record.routeRef)} replace />;
  return <PageFrame title="Opening case" description="Resolving the secure case workspace."><div className="surface rounded-[1.5rem] p-6 text-sm text-muted">Checking case access…</div></PageFrame>;
}

export function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const location = useLocation();
  return (
    <div className="min-h-screen bg-[var(--charcoal-deep)]">
      <div className="flex">
        <motion.aside
          animate={{ width: sidebarCollapsed ? 80 : 288 }}
          className="no-print fixed inset-y-0 left-0 hidden border-r border-[var(--border)] bg-[var(--bg)] p-4 lg:flex lg:flex-col"
        >
          <SidebarContent collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((value) => !value)} />
        </motion.aside>
        <div className={cn("min-w-0 flex-1 transition-[padding] duration-300", sidebarCollapsed ? "lg:pl-20" : "lg:pl-72")}>
          <TopBar />
          <div className="app-main-canvas p-4 sm:p-6">
            <RouteErrorBoundary resetKey={location.pathname}>
            <Suspense fallback={<RouteLoadingPanel />}>
            <Routes>
              <Route index element={<Navigate to={appViewRoute("upload")} replace />} />
              <Route path="v/:viewRef" element={<OpaqueViewRoute />} />
              <Route path="w/:routeRef" element={<CaseDetailPage />} />
              <Route path="d/:routeRef" element={<ReportPage />} />
              <Route path="cases/:caseId" element={<LegacyCaseRedirect />} />
              <Route path="reports/:caseId" element={<Navigate to={appViewRoute("reports")} replace />} />
              <Route path="upload" element={<Navigate to={appViewRoute("upload")} replace />} />
              <Route path="overview" element={<Navigate to={appViewRoute("overview")} replace />} />
              <Route path="dashboard" element={<Navigate to={appViewRoute("overview")} replace />} />
              <Route path="activity" element={<Navigate to={appViewRoute("activity")} replace />} />
              <Route path="evidence" element={<Navigate to={appViewRoute("evidence")} replace />} />
              <Route path="report" element={<Navigate to={appViewRoute("reports")} replace />} />
              <Route path="reports" element={<Navigate to={appViewRoute("reports")} replace />} />
              <Route path="packets" element={<Navigate to={appViewRoute("packets")} replace />} />
              <Route path="sessions" element={<Navigate to={appViewRoute("sessions")} replace />} />
              <Route path="decoder" element={<Navigate to={appViewRoute("decoder")} replace />} />
              <Route path="payloads" element={<Navigate to={appViewRoute("payloads")} replace />} />
              <Route path="detection" element={<Navigate to={appViewRoute("detection")} replace />} />
              <Route path="ai-anomaly" element={<Navigate to={appViewRoute("aiAnomaly")} replace />} />
              <Route path="graph" element={<Navigate to={appViewRoute("graph")} replace />} />
              <Route path="cases" element={<Navigate to={appViewRoute("cases")} replace />} />
              <Route path="exports" element={<Navigate to={appViewRoute("exports")} replace />} />
              <Route path="lab" element={<Navigate to={appViewRoute("lab")} replace />} />
              <Route path="compliance" element={<Navigate to={appViewRoute("compliance")} replace />} />
              <Route path="settings" element={<Navigate to={appViewRoute("settings")} replace />} />
              <Route path="settings/technical-status" element={<Navigate to={appViewRoute("technicalStatus")} replace />} />
              <Route path="settings/security" element={<MfaPage allowAdditional />} />
              <Route path="settings/sensors" element={<Navigate to={appViewRoute("sensors")} replace />} />
              <Route path="settings/schedules" element={<Navigate to={appViewRoute("schedules")} replace />} />
              <Route path="settings/integrations" element={<Navigate to={appViewRoute("integrations")} replace />} />
              <Route path="settings/retention" element={<Navigate to={appViewRoute("retention")} replace />} />
              <Route path="system" element={<Navigate to={appViewRoute("technicalStatus")} replace />} />
              <Route path="sensors" element={<Navigate to={appViewRoute("sensors")} replace />} />
              <Route path="schedules" element={<Navigate to={appViewRoute("schedules")} replace />} />
              <Route path="integrations" element={<Navigate to={appViewRoute("integrations")} replace />} />
              <Route path="retention" element={<Navigate to={appViewRoute("retention")} replace />} />
            </Routes>
            </Suspense>
            </RouteErrorBoundary>
          </div>
        </div>
      </div>
    </div>
  );
}

export function SidebarContent({ collapsed = false, onToggle }: { collapsed?: boolean; onToggle?: () => void }) {
  const { t, deploymentAccess } = useNetra();
  const navItem = (icon: LucideIcon, label: string, href: string): [LucideIcon, string, string] => [icon, label, href];
  const navGroups: { label: string; items: [LucideIcon, string, string][] }[] = [
    {
      label: t("mainWorkflow"),
      items: [
        navItem(Upload, "Start Investigation", appViewRoute("upload")),
        navItem(FileSearch, t("cases"), appViewRoute("cases")),
        navItem(FileText, t("evidenceReport"), appViewRoute("reports")),
        navItem(AlertTriangle, t("suspiciousActivity"), appViewRoute("activity")),
        navItem(Database, t("trafficEvidence"), appViewRoute("evidence")),
      ],
    },
    ...(deploymentAccess.modules.lab.visible ? [{
      label: "Lab Tools",
      items: [navItem(Activity, "Capture and Replay", appViewRoute("lab"))],
    }] : []),
    ...(deploymentAccess.modules.system.visible ? [{
      label: "Settings",
      items: [navItem(SettingsIcon, "Settings", appViewRoute("settings"))],
    }] : []),
  ];
  return (
    <>
      <div className={cn("mb-8 flex items-center", collapsed ? "flex-col gap-3" : "justify-between gap-2")}>
        <Link className={cn("flex min-w-0 items-center gap-3", collapsed && "justify-center")} to="/">
          <span className="flex size-10 shrink-0 items-center justify-center">
            <img className="size-full object-contain" src="/brand/netra-logo-mark.svg" alt="" aria-hidden="true" />
          </span>
          {!collapsed && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div className="font-bold text-strong">Netra</div>
              <div className="text-xs text-muted">{t("sidebarSubtitle")}</div>
            </motion.div>
          )}
        </Link>
        {onToggle && (
          <Button variant="ghost" size="icon" onClick={onToggle} aria-label={t("collapseSidebar")}>
            {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
          </Button>
        )}
      </div>
      <nav className="flex flex-col gap-4 overflow-y-auto pr-1">
        {navGroups.map((group) => (
          <div key={group.label} className="grid gap-1">
            {!collapsed && <div className="px-3 pb-1 text-[0.68rem] font-bold uppercase tracking-[0.16em] text-muted">{group.label}</div>}
            {group.items.map(([Icon, label, href]) => (
              <NavLink
                key={href}
                to={href}
                className={({ isActive }) =>
                  cn(
                    "group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-semibold text-muted transition hover:bg-[var(--surface-muted)] hover:text-strong",
                    collapsed && "justify-center px-0",
                    isActive && "bg-[var(--surface-muted)] text-strong",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <span className={cn("absolute left-0 h-6 w-0.5 rounded-full bg-[var(--accent)] opacity-0 transition", isActive && "opacity-100")} />
                    <Icon className="size-4 shrink-0" />
                    {!collapsed && <span>{label}</span>}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
    </>
  );
}

export function TopBar() {
  const { t, activeCaseId, caseRecords } = useNetra();
  const navigate = useNavigate();
  const activeCase = caseRecords.find((record) => record.id === activeCaseId);
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <header className="technical-topbar no-print sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-3 backdrop-blur-xl sm:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileOpen(true)} aria-label={t("openNavigation")}>
            <Menu className="size-5" />
          </Button>
          <SheetContent aria-describedby={undefined} className="left-0 right-auto w-72 border-l-0 border-r bg-[var(--bg)]">
            <SheetTitle className="sr-only">Mobile navigation</SheetTitle>
            <SidebarContent />
          </SheetContent>
        </Sheet>
        <div className="hidden min-w-72 items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--surface-muted)] px-4 py-2 text-sm text-muted md:flex">
          <Search className="size-4" />
          {t("searchPlaceholder")}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <LanguageControl />
        <Button onClick={() => navigate(appViewRoute("reports"))} disabled={!activeCase?.reportEligible} title={activeCase?.reportBlockedReason ?? "Select a completed case first."}>{t("generateReport")}</Button>
      </div>
    </header>
  );
}

export default App;
